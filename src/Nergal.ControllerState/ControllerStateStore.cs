using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Data.Sqlite;
using Nergal.Core.Controller;
using Nergal.Core.Identity;
using Nergal.Linux;

namespace Nergal.ControllerState;

/// <summary>Mode-checked SQLite WAL store for registered hosts, policy revisions, and append-only audit logs.</summary>
[SupportedOSPlatform("linux")]
public sealed class ControllerStateStore
{
    private const int ApplicationId = 0x4e524743; // 'NRGC'
    private const int SchemaVersion = 1;
    private const string DatabaseFileName = "controller.db";

    private readonly ControllerStateOptions _options;
    private readonly string _databasePath;
    private readonly TimeProvider _timeProvider;

    private ControllerStateStore(ControllerStateOptions options, string databasePath, TimeProvider timeProvider)
    {
        _options = options;
        _databasePath = databasePath;
        _timeProvider = timeProvider;
    }

    /// <summary>Creates a fresh SQLite WAL controller database in an existing owner-only <c>0700</c> directory.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="PlatformNotSupportedException">Host is not Linux.</exception>
    /// <exception cref="ControllerStateException">Database already exists, path protection fails, or initialization fails.</exception>
    public static ControllerStateStore Initialize(ControllerStateOptions options, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("Controller persistence requires Linux file protection.");
        }

        var databasePath = ValidatePaths(options.Directory, databaseRequired: false);
        foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" })
        {
            if (LinuxFileSystem.Read(databasePath + suffix) is not null || File.Exists(databasePath + suffix))
            {
                throw new ControllerStateException("controller.exists");
            }
        }

        try
        {
            using (var file = new FileStream(databasePath, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            }))
            {
                file.Flush(flushToDisk: true);
            }

            using var connection = new SqliteConnection(ConnectionString(databasePath));
            connection.Open();
            ExecuteNonQuery(connection, null, """
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=FULL;
                PRAGMA foreign_keys=ON;
                PRAGMA application_id=0x4e524743;
                PRAGMA user_version=1;
                """);

            using (var tx = connection.BeginTransaction())
            {
                ExecuteNonQuery(connection, tx, SchemaSql);
                tx.Commit();
            }

            ExecuteNonQuery(connection, null, "PRAGMA wal_checkpoint(TRUNCATE);");
            connection.Close();
        }
        catch (ControllerStateException)
        {
            throw;
        }
        catch (Exception ex) when (ex is SqliteException or IOException or UnauthorizedAccessException)
        {
            throw new ControllerStateException("controller.initializeFailed", ex);
        }

        return Open(options, timeProvider);
    }

    /// <summary>Opens and validates an existing protected controller database without repairing missing integrity guarantees.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="PlatformNotSupportedException">Host is not Linux.</exception>
    /// <exception cref="ControllerStateException">Directory/file mode fails, database is missing, or schema/triggers are invalid.</exception>
    public static ControllerStateStore Open(ControllerStateOptions options, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("Controller persistence requires Linux file protection.");
        }

        var databasePath = ValidatePaths(options.Directory, databaseRequired: true);
        var store = new ControllerStateStore(options, databasePath, timeProvider ?? TimeProvider.System);
        store.Read((conn, tx) => ValidateSchemaAndIntegrity(conn, tx));
        return store;
    }

    /// <summary>Registers a managed host endpoint and appends an audit record in a single transaction.</summary>
    /// <exception cref="ArgumentNullException">Required argument is null.</exception>
    /// <exception cref="ArgumentException">Actor identity or role is invalid.</exception>
    /// <exception cref="ControllerStateException">Host identity/name already exists or database integrity fails.</exception>
    public void RegisterHost(ManagedHostRecord host, string actorId, string actorRole)
    {
        ArgumentNullException.ThrowIfNull(host);
        ValidateActor(actorId, actorRole);
        if (actorRole != NergalRoles.Administrator)
        {
            throw new ControllerStateException("rbac.denied");
        }

        Write((conn, tx) =>
        {
            var exists = ScalarLong(conn, tx,
                "SELECT count(*) FROM hosts WHERE id = $id OR name = $name",
                ("$id", host.Id.ToString("D")), ("$name", host.Name));
            if (exists != 0)
            {
                throw new ControllerStateException("host.duplicate");
            }

            ExecuteNonQuery(conn, tx, """
                INSERT INTO hosts (id, name, transport_kind, endpoint, expected_uid, socket_gid, pinned_thumbprint, last_known_revision, created_at_utc)
                VALUES ($id, $name, $kind, $endpoint, $uid, $gid, $pin, $rev, $created)
                """,
                ("$id", host.Id.ToString("D")),
                ("$name", host.Name),
                ("$kind", host.TransportKind == AgentTransportKind.Unix ? "unix" : "tls"),
                ("$endpoint", host.Endpoint),
                ("$uid", host.ExpectedServerUserId.HasValue ? (long)host.ExpectedServerUserId.Value : DBNull.Value),
                ("$gid", host.SocketGroupId.HasValue ? (long)host.SocketGroupId.Value : DBNull.Value),
                ("$pin", (object?)host.PinnedServerThumbprint ?? DBNull.Value),
                ("$rev", host.LastKnownRevision.ToString(CultureInfo.InvariantCulture)),
                ("$created", host.CreatedAtUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture)));

            InsertAudit(conn, tx, _timeProvider.GetUtcNow(), actorId, actorRole, "host.register", host.Name, host.LastKnownRevision == 0 ? null : host.LastKnownRevision, "succeeded", null);
        });
    }

    /// <summary>Updates the last observed/confirmed revision for an existing registered host.</summary>
    public void UpdateHostLastRevision(Guid hostId, ulong revision)
    {
        if (hostId == Guid.Empty)
        {
            throw new ArgumentException("Host identity cannot be empty.", nameof(hostId));
        }

        Write((conn, tx) =>
        {
            var updated = ExecuteNonQuery(conn, tx,
                "UPDATE hosts SET last_known_revision = $rev WHERE id = $id",
                ("$rev", revision.ToString(CultureInfo.InvariantCulture)),
                ("$id", hostId.ToString("D")));
            if (updated != 1)
            {
                throw new ControllerStateException("host.notFound");
            }
        });
    }

    /// <summary>Removes a registered host and appends an audit record atomically.</summary>
    public bool DeleteHost(Guid hostId, string actorId, string actorRole)
    {
        if (hostId == Guid.Empty)
        {
            throw new ArgumentException("Host identity cannot be empty.", nameof(hostId));
        }

        ValidateActor(actorId, actorRole);
        if (actorRole != NergalRoles.Administrator)
        {
            throw new ControllerStateException("rbac.denied");
        }

        return Write((conn, tx) =>
        {
            using var select = conn.CreateCommand();
            select.Transaction = tx;
            select.CommandText = "SELECT name FROM hosts WHERE id = $id";
            select.Parameters.AddWithValue("$id", hostId.ToString("D"));
            var name = select.ExecuteScalar() as string;
            if (name is null)
            {
                return false;
            }

            _ = ExecuteNonQuery(conn, tx, "DELETE FROM hosts WHERE id = $id", ("$id", hostId.ToString("D")));
            InsertAudit(conn, tx, _timeProvider.GetUtcNow(), actorId, actorRole, "host.delete", name, null, "succeeded", null);
            return true;
        });
    }

    /// <summary>Returns all registered managed hosts ordered by name.</summary>
    public IReadOnlyList<ManagedHostRecord> ListHosts()
    {
        return Read((conn, tx) =>
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "SELECT id, name, transport_kind, endpoint, expected_uid, socket_gid, pinned_thumbprint, last_known_revision, created_at_utc FROM hosts ORDER BY name";
            using var reader = cmd.ExecuteReader();
            var list = new List<ManagedHostRecord>();
            while (reader.Read())
            {
                list.Add(ReadHost(reader));
            }

            return list;
        });
    }

    /// <summary>Retrieves a single registered host by identifier, or null when absent.</summary>
    public ManagedHostRecord? GetHost(Guid hostId)
    {
        if (hostId == Guid.Empty)
        {
            throw new ArgumentException("Host identity cannot be empty.", nameof(hostId));
        }

        return Read((conn, tx) =>
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "SELECT id, name, transport_kind, endpoint, expected_uid, socket_gid, pinned_thumbprint, last_known_revision, created_at_utc FROM hosts WHERE id = $id";
            cmd.Parameters.AddWithValue("$id", hostId.ToString("D"));
            using var reader = cmd.ExecuteReader();
            return reader.Read() ? ReadHost(reader) : null;
        });
    }

    /// <summary>Persists a new monotonic policy bundle revision and records its creation in the append-only audit log.</summary>
    public PolicyRevisionRecord SavePolicyRevision(
        string policyJson,
        string candidateDigest,
        string actorId,
        string actorRole,
        string? summary = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyJson);
        var normalizedDigest = ManagedHostRecord.NormalizeSha256(candidateDigest);
        ValidateActor(actorId, actorRole);
        if (actorRole != NergalRoles.Administrator)
        {
            throw new ControllerStateException("rbac.denied");
        }

        if (summary is not null && (summary.Length > 256 || summary.Any(char.IsControl)))
        {
            throw new ArgumentException("Policy revision summary must be at most 256 non-control characters.", nameof(summary));
        }

        return Write((conn, tx) =>
        {
            var maxRaw = ScalarString(conn, tx, "SELECT COALESCE(MAX(revision), 0) FROM policy_revisions");
            var nextRev = ulong.Parse(maxRaw, CultureInfo.InvariantCulture) + 1;
            var now = _timeProvider.GetUtcNow().ToUniversalTime();

            ExecuteNonQuery(conn, tx, """
                INSERT INTO policy_revisions (revision, policy_json, candidate_digest, created_by_actor, created_at_utc, summary)
                VALUES ($rev, $json, $digest, $actor, $created, $summary)
                """,
                ("$rev", checked((long)nextRev)),
                ("$json", policyJson),
                ("$digest", normalizedDigest),
                ("$actor", actorId),
                ("$created", now.UtcDateTime.ToString("O", CultureInfo.InvariantCulture)),
                ("$summary", (object?)summary ?? DBNull.Value));

            InsertAudit(conn, tx, now, actorId, actorRole, "policy.save", "bundle", nextRev, "succeeded", null);
            return new PolicyRevisionRecord(nextRev, policyJson, normalizedDigest, actorId, now, summary);
        });
    }

    /// <summary>Returns persisted policy revisions ordered newest-first up to <paramref name="limit"/>.</summary>
    public IReadOnlyList<PolicyRevisionRecord> ListPolicyRevisions(int limit = 100)
    {
        if (limit is < 1 or > 1000)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }

        return Read((conn, tx) =>
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "SELECT revision, policy_json, candidate_digest, created_by_actor, created_at_utc, summary FROM policy_revisions ORDER BY revision DESC LIMIT $limit";
            cmd.Parameters.AddWithValue("$limit", limit);
            using var reader = cmd.ExecuteReader();
            var list = new List<PolicyRevisionRecord>();
            while (reader.Read())
            {
                list.Add(ReadPolicyRevision(reader));
            }

            return list;
        });
    }

    /// <summary>Retrieves a stored policy revision snapshot, or null when missing.</summary>
    public PolicyRevisionRecord? GetPolicyRevision(ulong revision)
    {
        if (revision == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(revision));
        }

        return Read((conn, tx) =>
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "SELECT revision, policy_json, candidate_digest, created_by_actor, created_at_utc, summary FROM policy_revisions WHERE revision = $rev";
            cmd.Parameters.AddWithValue("$rev", checked((long)revision));
            using var reader = cmd.ExecuteReader();
            return reader.Read() ? ReadPolicyRevision(reader) : null;
        });
    }

    /// <summary>Appends an immutable audit entry with explicit actor attribution and outcome.</summary>
    public ControllerAuditEntry AppendAudit(
        string actorId,
        string actorRole,
        string action,
        string target,
        ulong? revision,
        string outcome,
        string? detailCode = null)
    {
        ValidateActor(actorId, actorRole);
        ValidateBoundedToken(action, 128, nameof(action));
        ValidateBoundedToken(target, 256, nameof(target));
        ValidateBoundedToken(outcome, 64, nameof(outcome));
        if (detailCode is not null)
        {
            ValidateBoundedToken(detailCode, 64, nameof(detailCode));
        }

        return Write((conn, tx) =>
            InsertAudit(conn, tx, _timeProvider.GetUtcNow(), actorId, actorRole, action, target, revision, outcome, detailCode));
    }

    /// <summary>Reads append-only audit entries ordered most-recent first up to <paramref name="limit"/>.</summary>
    public IReadOnlyList<ControllerAuditEntry> ListAuditEntries(int limit = 200)
    {
        if (limit is < 1 or > 1000)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }

        return Read((conn, tx) =>
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                SELECT sequence, timestamp_utc, actor_id, actor_role, action, target, revision, outcome, detail_code
                FROM audit_log
                ORDER BY sequence DESC
                LIMIT $limit
                """;
            cmd.Parameters.AddWithValue("$limit", limit);
            using var reader = cmd.ExecuteReader();
            var entries = new List<ControllerAuditEntry>();
            while (reader.Read())
            {
                var rev = reader.IsDBNull(6)
                    ? (ulong?)null
                    : ulong.Parse(reader.GetString(6), CultureInfo.InvariantCulture);
                entries.Add(new ControllerAuditEntry(
                    reader.GetInt64(0),
                    DateTimeOffset.Parse(reader.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                    reader.GetString(2),
                    reader.GetString(3),
                    reader.GetString(4),
                    reader.GetString(5),
                    rev,
                    reader.GetString(7),
                    reader.IsDBNull(8) ? null : reader.GetString(8)));
            }

            return entries;
        });
    }

    /// <summary>Reads the persisted system settings snapshot, returning <see cref="SystemSettingsSnapshot.Default"/> when not yet configured.</summary>
    public SystemSettingsSnapshot ReadSystemSettings()
    {
        return Read((conn, tx) =>
        {
            var tableExists = ScalarLong(conn, tx,
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'system_settings'");
            if (tableExists == 0)
            {
                return SystemSettingsSnapshot.Default;
            }

            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "SELECT settings_json FROM system_settings WHERE singleton = 1";
            var value = cmd.ExecuteScalar();
            if (value is null) { return SystemSettingsSnapshot.Default; }
            if (value is not string raw || string.IsNullOrWhiteSpace(raw)) { throw new ControllerStateException("settings.corrupt"); }

            try { return SystemSettingsCodec.Deserialize(raw); }
            catch (System.Text.Json.JsonException) { throw new ControllerStateException("settings.corrupt"); }
        });
    }

    /// <summary>Validates and persists system settings and appends an immutable <c>settings.update</c> audit record.</summary>
    /// <exception cref="ArgumentNullException">Required argument is null.</exception>
    /// <exception cref="ArgumentException">Actor identity or role is invalid.</exception>
    /// <exception cref="ControllerStateException">Actor is not an administrator or settings fail validation.</exception>
    public void SaveSystemSettings(SystemSettingsSnapshot settings, string actorId, string actorRole)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ValidateActor(actorId, actorRole);
        if (actorRole != NergalRoles.Administrator)
        {
            throw new ControllerStateException("rbac.denied");
        }

        var errors = SystemSettingsCodec.Validate(settings);
        if (errors.Count > 0)
        {
            throw new ControllerStateException("settings.invalid");
        }

        var json = SystemSettingsCodec.Serialize(settings);
        Write((conn, tx) =>
        {
            ExecuteNonQuery(conn, tx, """
                CREATE TABLE IF NOT EXISTS system_settings (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    settings_json TEXT NOT NULL,
                    updated_by_actor TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                ) STRICT;
                """);

            var nowUtc = _timeProvider.GetUtcNow();
            ExecuteNonQuery(conn, tx, """
                INSERT INTO system_settings (singleton, settings_json, updated_by_actor, updated_at_utc)
                VALUES (1, $json, $actor, $updated)
                ON CONFLICT(singleton) DO UPDATE SET
                    settings_json = excluded.settings_json,
                    updated_by_actor = excluded.updated_by_actor,
                    updated_at_utc = excluded.updated_at_utc
                """,
                ("$json", json),
                ("$actor", actorId),
                ("$updated", nowUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture)));

            InsertAudit(conn, tx, nowUtc, actorId, actorRole, "settings.update", "system", null, "succeeded", null);
        });
    }

    private ControllerAuditEntry InsertAudit(
        SqliteConnection conn,
        SqliteTransaction tx,
        DateTimeOffset nowUtc,
        string actorId,
        string actorRole,
        string action,
        string target,
        ulong? revision,
        string outcome,
        string? detailCode)
    {
        var utc = nowUtc.ToUniversalTime();
        var stamp = utc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
        ExecuteNonQuery(conn, tx, """
            INSERT INTO audit_log (timestamp_utc, actor_id, actor_role, action, target, revision, outcome, detail_code)
            VALUES ($ts, $actor, $role, $action, $target, $rev, $outcome, $detail)
            """,
            ("$ts", stamp),
            ("$actor", actorId),
            ("$role", actorRole),
            ("$action", action),
            ("$target", target),
            ("$rev", revision.HasValue ? revision.Value.ToString(CultureInfo.InvariantCulture) : DBNull.Value),
            ("$outcome", outcome),
            ("$detail", (object?)detailCode ?? DBNull.Value));

        var sequence = ScalarLong(conn, tx, "SELECT last_insert_rowid()");
        return new ControllerAuditEntry(sequence, utc, actorId, actorRole, action, target, revision, outcome, detailCode);
    }

    private static ManagedHostRecord ReadHost(SqliteDataReader reader)
    {
        var kind = reader.GetString(2) switch
        {
            "unix" => AgentTransportKind.Unix,
            "tls" => AgentTransportKind.Tls,
            _ => throw new ControllerStateException("controller.corrupt"),
        };

        uint? uid = reader.IsDBNull(4) ? null : checked((uint)reader.GetInt64(4));
        uint? gid = reader.IsDBNull(5) ? null : checked((uint)reader.GetInt64(5));
        string? pin = reader.IsDBNull(6) ? null : reader.GetString(6);
        var rev = ulong.Parse(reader.GetString(7), CultureInfo.InvariantCulture);
        var created = DateTimeOffset.Parse(reader.GetString(8), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

        return new ManagedHostRecord(
            Guid.ParseExact(reader.GetString(0), "D"),
            reader.GetString(1),
            kind,
            reader.GetString(3),
            uid,
            gid,
            pin,
            rev,
            created);
    }

    private static PolicyRevisionRecord ReadPolicyRevision(SqliteDataReader reader) =>
        new(
            checked((ulong)reader.GetInt64(0)),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetString(3),
            DateTimeOffset.Parse(reader.GetString(4), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
            reader.IsDBNull(5) ? null : reader.GetString(5));

    private T Read<T>(Func<SqliteConnection, SqliteTransaction, T> body)
    {
        _ = ValidatePaths(_options.Directory, databaseRequired: true);
        try
        {
            using var conn = new SqliteConnection(ConnectionString(_databasePath));
            conn.Open();
            ConfigureConnection(conn);
            using var tx = conn.BeginTransaction();
            ValidateSchemaAndIntegrity(conn, tx);
            return body(conn, tx);
        }
        catch (ControllerStateException)
        {
            throw;
        }
        catch (Exception ex) when (ex is SqliteException or FormatException or ArgumentException or OverflowException or InvalidCastException)
        {
            throw new ControllerStateException("controller.databaseError", ex);
        }
    }

    private void Write(Action<SqliteConnection, SqliteTransaction> body) =>
        Write((conn, tx) => { body(conn, tx); return true; });

    private T Write<T>(Func<SqliteConnection, SqliteTransaction, T> body)
    {
        _ = ValidatePaths(_options.Directory, databaseRequired: true);
        try
        {
            using var conn = new SqliteConnection(ConnectionString(_databasePath));
            conn.Open();
            ConfigureConnection(conn);
            using var tx = conn.BeginTransaction(deferred: false);
            ValidateSchemaAndIntegrity(conn, tx);
            var result = body(conn, tx);
            tx.Commit();
            return result;
        }
        catch (ControllerStateException)
        {
            throw;
        }
        catch (Exception ex) when (ex is SqliteException or FormatException or ArgumentException or OverflowException or InvalidCastException)
        {
            throw new ControllerStateException("controller.databaseError", ex);
        }
    }

    private static string ValidatePaths(string directory, bool databaseRequired)
    {
        try
        {
            for (DirectoryInfo? part = new(directory); part is not null; part = part.Parent)
            {
                if (part.LinkTarget is not null)
                {
                    throw new ControllerStateException("path.symlink");
                }
            }

            var owner = LinuxProcessIdentity.EffectiveUserId;
            var dirMeta = LinuxFileSystem.Read(directory) ?? throw new ControllerStateException("path.missing");
            if (dirMeta.Type != LinuxNodeType.Directory ||
                dirMeta.OwnerUserId != owner ||
                dirMeta.Permissions != (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute))
            {
                throw new ControllerStateException("path.permissions");
            }

            var databasePath = Path.Combine(directory, DatabaseFileName);
            foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" })
            {
                var filePath = databasePath + suffix;
                var fileMeta = LinuxFileSystem.Read(filePath);
                if (fileMeta is null)
                {
                    if (suffix.Length == 0 && databaseRequired)
                    {
                        throw new ControllerStateException("controller.missing");
                    }

                    continue;
                }

                if (fileMeta.Value.Type != LinuxNodeType.RegularFile ||
                    fileMeta.Value.OwnerUserId != owner ||
                    fileMeta.Value.LinkCount != 1 ||
                    (fileMeta.Value.Permissions & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute |
                        UnixFileMode.SetUser | UnixFileMode.SetGroup | UnixFileMode.StickyBit)) != 0)
                {
                    throw new ControllerStateException("path.permissions");
                }
            }

            return databasePath;
        }
        catch (LinuxMetadataException ex)
        {
            throw new ControllerStateException("path.metadataUnavailable", ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new ControllerStateException("path.permissions", ex);
        }
    }

    private static string ConnectionString(string databasePath) =>
        new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
            DefaultTimeout = 5,
        }.ToString();

    private static void ConfigureConnection(SqliteConnection conn)
    {
        ExecuteNonQuery(conn, null, "PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
        if (!string.Equals(ScalarString(conn, null, "PRAGMA journal_mode"), "wal", StringComparison.OrdinalIgnoreCase))
        {
            throw new ControllerStateException("controller.durability");
        }
    }

    private static bool ValidateSchemaAndIntegrity(SqliteConnection conn, SqliteTransaction tx)
    {
        if (ScalarLong(conn, tx, "PRAGMA application_id") != ApplicationId ||
            ScalarLong(conn, tx, "PRAGMA user_version") != SchemaVersion ||
            !string.Equals(ScalarString(conn, tx, "PRAGMA quick_check"), "ok", StringComparison.Ordinal))
        {
            throw new ControllerStateException("controller.corrupt");
        }

        var triggerCount = ScalarLong(conn, tx,
            "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND tbl_name='audit_log' AND name IN ('audit_no_update','audit_no_delete')");
        if (triggerCount != 2)
        {
            throw new ControllerStateException("controller.corrupt");
        }

        return true;
    }

    private static void ValidateActor(string actorId, string actorRole)
    {
        if (!ControllerActorIdentity.IsValid(actorId))
        {
            throw new ArgumentException("Actor identifier must be canonical 'local:<uuid>' or 'oidc:<issuer>:<subject>'.", nameof(actorId));
        }

        if (!NergalRoles.IsDefined(actorRole))
        {
            throw new ArgumentException("Actor role must be an explicit controller role.", nameof(actorRole));
        }
    }

    private static void ValidateBoundedToken(string value, int maxLen, string paramName)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maxLen || value.Any(char.IsControl))
        {
            throw new ArgumentException($"Value must be 1..{maxLen} non-control characters.", paramName);
        }
    }

    private static int ExecuteNonQuery(SqliteConnection conn, SqliteTransaction? tx, string sql, params (string Name, object Value)[] parameters)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        foreach (var (name, value) in parameters)
        {
            cmd.Parameters.AddWithValue(name, value);
        }

        return cmd.ExecuteNonQuery();
    }

    private static long ScalarLong(SqliteConnection conn, SqliteTransaction? tx, string sql, params (string Name, object Value)[] parameters)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        foreach (var (name, value) in parameters)
        {
            cmd.Parameters.AddWithValue(name, value);
        }

        return Convert.ToInt64(cmd.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private static string ScalarString(SqliteConnection conn, SqliteTransaction? tx, string sql, params (string Name, object Value)[] parameters)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        foreach (var (name, value) in parameters)
        {
            cmd.Parameters.AddWithValue(name, value);
        }

        return Convert.ToString(cmd.ExecuteScalar(), CultureInfo.InvariantCulture) ?? "";
    }

    private const string SchemaSql = """
        CREATE TABLE hosts (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            transport_kind TEXT NOT NULL CHECK(transport_kind IN ('unix', 'tls')),
            endpoint TEXT NOT NULL,
            expected_uid INTEGER,
            socket_gid INTEGER,
            pinned_thumbprint TEXT,
            last_known_revision TEXT NOT NULL,
            created_at_utc TEXT NOT NULL
        ) STRICT;

        CREATE TABLE policy_revisions (
            revision INTEGER PRIMARY KEY CHECK(revision >= 1),
            policy_json TEXT NOT NULL,
            candidate_digest TEXT NOT NULL,
            created_by_actor TEXT NOT NULL,
            created_at_utc TEXT NOT NULL,
            summary TEXT
        ) STRICT;

        CREATE TABLE audit_log (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            revision TEXT,
            outcome TEXT NOT NULL,
            detail_code TEXT
        ) STRICT;

        CREATE TABLE IF NOT EXISTS system_settings (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            settings_json TEXT NOT NULL,
            updated_by_actor TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL
        ) STRICT;

        CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit log is append-only');
        END;

        CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit log is append-only');
        END;
        """;
}
