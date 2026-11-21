using System.Globalization;
using System.Text;
using Microsoft.Data.Sqlite;
using Nergal.Core.Deployment;

namespace Nergal.LocalState;

/// <summary>Private Linux SQLite journal for one explicitly enrolled resource; performs no firewall operations.</summary>
/// <remarks>Requires a trusted service-owned local parent directory. Same-account/root attackers and hostile path replacement are outside this prototype boundary.</remarks>
public sealed partial class ApplyJournal
{
    private readonly string directory;
    private readonly IJournalClock clock;
    private const int ArtifactLimit = 1024 * 1024;
    private const int SchemaVersion = 2;

    private ApplyJournal(string directory, IJournalClock clock)
    {
        this.directory = directory;
        this.clock = clock;
    }

    /// <summary>Initializes a new journal in an existing 0700 directory using an explicit trusted bootstrap assertion.</summary>
    /// <remarks>Never adopts kernel state. Existing or incomplete databases are not overwritten.</remarks>
    /// <exception cref="JournalException">Path protection, artifact identity or database initialization fails.</exception>
    public static ApplyJournal Initialize(string directory, ResourceOwnership ownership, string confirmedArtifact, IJournalClock? clock = null)
        => InitializeCore(directory, ownership, confirmedArtifact, clock, false);

    /// <summary>Creates a fresh protected enrollment intent with legacy operations disabled even if exclusive kernel creation is interrupted.</summary>
    public static ApplyJournal InitializeResourceIntent(string directory, ResourceOwnership ownership, string confirmedArtifact, IJournalClock? clock = null)
        => InitializeCore(directory, ownership, confirmedArtifact, clock, true);

    private static ApplyJournal InitializeCore(string directory, ResourceOwnership ownership, string confirmedArtifact, IJournalClock? clock, bool enrollmentOnly)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("The local journal requires Linux.");
        }

        ArgumentNullException.ThrowIfNull(ownership);
        CheckArtifact(confirmedArtifact);
        var database = PrivateJournalPath.Validate(directory, false);
        if (new[] { database, database + "-journal", database + "-wal", database + "-shm" }.Any(File.Exists))
        {
            throw new JournalException("journal.exists");
        }

        using (var file = new FileStream(database, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            UnixCreateMode = PrivateJournalPath.FileMode,
        }))
        {
            file.Flush(true);
        }

        var journal = new ApplyJournal(directory, clock ?? new LinuxBootClock());
        using var connection = journal.Connect(false);
        using var transaction = connection.BeginTransaction(deferred: false);
        var now = journal.Now();
        Execute(connection, transaction, Schema);
        if (enrollmentOnly)
        {
            Execute(connection, transaction, """
                CREATE TRIGGER enrollment_no_legacy_start BEFORE INSERT ON operations
                BEGIN SELECT RAISE(ABORT,'local enrollment requires receipt-aware apply'); END;
                """);
        }
        Execute(connection, transaction,
            "INSERT INTO enrollment(singleton,agent,owner,revision,artifact,digest,boot,active) VALUES(1,$agent,$owner,$revision,$artifact,$digest,$boot,NULL)",
            ("$agent", ownership.AgentId.ToString("D")), ("$owner", ownership.OwnerId.ToString("D")),
            ("$revision", Revision(ownership.Revision)), ("$artifact", confirmedArtifact),
            ("$digest", CandidateDigest.FromText(confirmedArtifact).Value), ("$boot", now.BootId.ToString("D")));
        transaction.Commit();
        return journal;
    }

    /// <summary>Opens existing state without creating, repairing or resetting it.</summary>
    /// <exception cref="JournalException">The path, database, schema or enrollment is invalid.</exception>
    public static ApplyJournal Open(string directory, IJournalClock? clock = null)
    {
        var journal = new ApplyJournal(directory, clock ?? new LinuxBootClock());
        _ = journal.ReadEnrollment();
        return journal;
    }

    /// <summary>Reads verified last-confirmed ownership and artifact, not a live-kernel ownership proof.</summary>
    public JournalEnrollment ReadEnrollment()
    {
        return Inspect((connection, transaction) => Enrollment(connection, transaction).Value);
    }

    /// <summary>Reads a retained operation and replays its recorded phase changes through the Core model.</summary>
    public JournalEntry Read(Guid operationId)
    {
        return Inspect((connection, transaction) => Load(connection, transaction, operationId));
    }

    /// <summary>Reads the active operation, including recovery-blocked state, or null when no operation is active.</summary>
    public JournalEntry? ReadActive()
    {
        return Inspect((connection, transaction) =>
        {
            var active = Enrollment(connection, transaction).Active;
            return active is null ? null : Load(connection, transaction, active.Value);
        });
    }

    /// <summary>Atomically reserves an unused operation ID after checking enrolled ownership, revision and exact rollback bytes.</summary>
    /// <exception cref="JournalException">State is busy, stale, reused, corrupt, from another boot or content differs.</exception>
    public JournalEntry Start(ApplyPlan plan, string candidate, string rollback)
    {
        ArgumentNullException.ThrowIfNull(plan);
        CheckArtifact(candidate);
        CheckArtifact(rollback);
        if (CandidateDigest.FromText(candidate) != plan.Candidate || CandidateDigest.FromText(rollback) != plan.Rollback)
        {
            throw new JournalException("artifact.mismatch");
        }

        return Write((connection, transaction) =>
        {
            var enrollment = Enrollment(connection, transaction);
            var now = Now();
            if (now.BootId != enrollment.Boot)
            {
                throw new JournalException("clock.bootChanged");
            }

            if (enrollment.Active is not null)
            {
                throw new JournalException("resource.busy");
            }

            if (enrollment.Value.Ownership != plan.Ownership)
            {
                throw new JournalException("ownership.stale");
            }

            if (enrollment.Value.Artifact != rollback)
            {
                throw new JournalException("rollback.mismatch");
            }

            if (LoadReceipt(connection, transaction, enrollment.Value, enrollment.Boot, enrollment.ResourceBound) is not null)
            {
                throw new JournalException("resource.boundApplyUnavailable");
            }

            if (Scalar(connection, transaction, "SELECT count(*) FROM operations WHERE id=$id", ("$id", Id(plan.OperationId))) is long count && count != 0)
            {
                throw new JournalException("operation.reused");
            }

            Execute(connection, transaction,
                "INSERT INTO operations VALUES($id,$agent,$owner,$revision,$candidate,$rollback,$candidateHash,$rollbackHash,$timeout,$boot,$started,0)",
                ("$id", Id(plan.OperationId)), ("$agent", Id(plan.Ownership.AgentId)), ("$owner", Id(plan.Ownership.OwnerId)),
                ("$revision", Revision(plan.Ownership.Revision)), ("$candidate", candidate), ("$rollback", rollback),
                ("$candidateHash", plan.Candidate.Value), ("$rollbackHash", plan.Rollback.Value),
                ("$timeout", plan.ConfirmationTimeout.Ticks), ("$boot", Id(now.BootId)), ("$started", now.SinceBoot.Ticks));
            Execute(connection, transaction, "UPDATE enrollment SET active=$id WHERE singleton=1", ("$id", Id(plan.OperationId)));
            return new JournalEntry(ApplySession.Prepare(plan), candidate, rollback, now);
        });
    }

    /// <summary>Serializes acknowledgment with deadline evaluation using time sampled after acquiring the write lock.</summary>
    /// <remarks>Confirmation and its enrolled revision commit together. RecoveryRequired blocks subsequent operations.</remarks>
    public JournalUpdate Advance(Guid operationId, ApplyEvent kind, ApplyPlan evidence, Guid watchdogId)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        return Write((connection, transaction) =>
        {
            var entry = Load(connection, transaction, operationId);
            if (entry.Session.IsTerminal)
            {
                return new JournalUpdate(entry, false, "phase.terminal");
            }

            var enrollment = Enrollment(connection, transaction);
            if (enrollment.Active != operationId || enrollment.Value.Ownership != entry.Session.Plan.Ownership || enrollment.Value.Artifact != entry.Rollback)
            {
                throw new JournalException("journal.corrupt");
            }

            var now = Now();
            var elapsed = now.SinceBoot - entry.Started.SinceBoot;
            string? clockError = now.BootId != entry.Started.BootId || now.BootId != enrollment.Boot ? "clock.bootChanged" :
                elapsed < entry.Session.Elapsed ? "clock.regressed" : null;
            var result = clockError is null
                ? entry.Session.Advance(kind, evidence, watchdogId, elapsed)
                : entry.Session.Advance(ApplyEvent.Interrupted, entry.Session.Plan, entry.Session.WatchdogId, entry.Session.Elapsed);
            var next = new JournalEntry(result.Session, entry.Candidate, entry.Rollback, entry.Started);
            if (next.Session.Phase != entry.Session.Phase)
            {
                Append(connection, transaction, entry, next.Session, clockError is null ? kind : ApplyEvent.Interrupted,
                    clockError is null ? watchdogId : entry.Session.WatchdogId, result.ErrorCode);
            }
            return new JournalUpdate(next, clockError is null && result.Accepted, clockError ?? result.ErrorCode);
        });
    }

    private static void Append(SqliteConnection connection, SqliteTransaction transaction, JournalEntry prior,
        ApplySession next, ApplyEvent kind, Guid watchdogId, string? error)
    {
        var operation = Id(next.Plan.OperationId);
        Execute(connection, transaction,
            "INSERT INTO events SELECT $id,coalesce(max(sequence),0)+1,$kind,$elapsed,$watchdog,$error,$phase FROM events WHERE operation=$id",
            ("$id", operation), ("$kind", (int)kind), ("$elapsed", next.Elapsed.Ticks),
            ("$watchdog", Id(watchdogId)), ("$error", error), ("$phase", (int)next.Phase));
        Execute(connection, transaction, "UPDATE operations SET phase=$phase WHERE id=$id", ("$phase", (int)next.Phase), ("$id", operation));
        if (next.Phase == ApplyPhase.Confirmed)
        {
            Execute(connection, transaction, "UPDATE enrollment SET revision=$revision,artifact=$artifact,digest=$digest,active=NULL WHERE singleton=1",
                ("$revision", Revision(next.Plan.ConfirmedRevision)), ("$artifact", prior.Candidate), ("$digest", next.Plan.Candidate.Value));
        }
        else if (next.Phase == ApplyPhase.RolledBack)
        {
            Execute(connection, transaction, "UPDATE enrollment SET active=NULL WHERE singleton=1");
        }
    }

    private static JournalEntry Load(SqliteConnection connection, SqliteTransaction transaction, Guid operationId)
    {
        using var command = Command(connection, transaction, "SELECT * FROM operations WHERE id=$id", ("$id", Id(operationId)));
        using var row = command.ExecuteReader();
        if (!row.Read())
        {
            throw new JournalException("operation.missing");
        }

        try
        {
            var candidate = row.GetString(4);
            var rollback = row.GetString(5);
            CheckStoredArtifact(candidate);
            CheckStoredArtifact(rollback);
            var plan = new ApplyPlan(ParseId(row.GetString(0)), new(ParseId(row.GetString(1)), ParseId(row.GetString(2)), ParseRevision(row.GetString(3))),
                new(row.GetString(6)), new(row.GetString(7)), TimeSpan.FromTicks(row.GetInt64(8)));
            if (CandidateDigest.FromText(candidate) != plan.Candidate || CandidateDigest.FromText(rollback) != plan.Rollback)
            {
                throw new JournalException("journal.corrupt");
            }

            var start = new JournalTime(ParseId(row.GetString(9)), TimeSpan.FromTicks(row.GetInt64(10)));
            if (start.SinceBoot < TimeSpan.Zero)
            {
                throw new JournalException("journal.corrupt");
            }

            var phase = row.GetInt32(11);
            row.Close();
            var session = ApplySession.Prepare(plan);
            using var events = Command(connection, transaction, "SELECT sequence,kind,elapsed,watchdog,error,phase FROM events WHERE operation=$id ORDER BY sequence", ("$id", Id(operationId)));
            using var history = events.ExecuteReader();
            var sequence = 0;
            while (history.Read())
            {
                if (++sequence > 16 || history.GetInt32(0) != sequence)
                {
                    throw new JournalException("journal.corrupt");
                }

                var result = session.Advance((ApplyEvent)history.GetInt32(1), plan, ParseId(history.GetString(3), true), TimeSpan.FromTicks(history.GetInt64(2)));
                var error = history.IsDBNull(4) ? null : history.GetString(4);
                if (result.ErrorCode != error || (int)result.Session.Phase != history.GetInt32(5) || result.Session.Phase == session.Phase)
                {
                    throw new JournalException("journal.corrupt");
                }

                session = result.Session;
            }
            if ((int)session.Phase != phase)
            {
                throw new JournalException("journal.corrupt");
            }

            return new(session, candidate, rollback, start);
        }
        catch (Exception error) when (error is ArgumentException or FormatException or OverflowException or InvalidCastException)
        {
            throw new JournalException("journal.corrupt");
        }
    }

    private static (JournalEnrollment Value, Guid Boot, Guid? Active, bool ResourceBound) Enrollment(SqliteConnection connection, SqliteTransaction? transaction, bool legacy = false)
    {
        using var command = Command(connection, transaction, "SELECT agent,owner,revision,artifact,digest,boot,active," + (legacy ? "0" : "resource_bound") + " FROM enrollment WHERE singleton=1");
        using var row = command.ExecuteReader();
        if (!row.Read())
        {
            throw new JournalException("journal.corrupt");
        }

        try
        {
            var ownership = new ResourceOwnership(ParseId(row.GetString(0)), ParseId(row.GetString(1)), ParseRevision(row.GetString(2)));
            var artifact = row.GetString(3);
            CheckStoredArtifact(artifact);
            if (CandidateDigest.FromText(artifact) != new CandidateDigest(row.GetString(4)))
            {
                throw new JournalException("journal.corrupt");
            }

            var bound = row.GetInt64(7);
            if (bound is not (0 or 1))
            {
                throw new JournalException("journal.corrupt");
            }

            return (new(ownership, artifact), ParseId(row.GetString(5)), row.IsDBNull(6) ? null : ParseId(row.GetString(6)), bound == 1);
        }
        catch (Exception error) when (error is ArgumentException or FormatException or OverflowException or InvalidCastException)
        {
            throw new JournalException("journal.corrupt");
        }
    }

    private T Inspect<T>(Func<SqliteConnection, SqliteTransaction, T> action)
    {
        try
        {
            using var connection = Connect();
            using var transaction = connection.BeginTransaction(deferred: true);
            if (!Equals(Scalar(connection, transaction, "PRAGMA user_version"), (long)SchemaVersion))
            {
                throw new JournalException("journal.schemaOrIntegrity");
            }

            return action(connection, transaction);
        }
        catch (SqliteException) { throw new JournalException("database.error"); }
    }

    private T Write<T>(Func<SqliteConnection, SqliteTransaction, T> action)
    {
        try
        {
            using var connection = Connect();
            using var transaction = connection.BeginTransaction(deferred: false);
            if (!Equals(Scalar(connection, transaction, "PRAGMA user_version"), (long)SchemaVersion))
            {
                throw new JournalException("journal.schemaOrIntegrity");
            }

            var result = action(connection, transaction);
            transaction.Commit();
            return result;
        }
        catch (SqliteException) { throw new JournalException("database.error"); }
    }

    private SqliteConnection Connect(bool validate = true, int expectedVersion = SchemaVersion)
    {
        var database = PrivateJournalPath.Validate(directory, true);
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = database,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
            DefaultTimeout = 5,
        }.ToString());
        try
        {
            connection.Open();
            Execute(connection, null, "PRAGMA trusted_schema=OFF");
            if (validate && (!Equals(Scalar(connection, null, "PRAGMA application_id"), 0x4e52474cL) ||
                !Equals(Scalar(connection, null, "PRAGMA user_version"), (long)expectedVersion) ||
                !Equals(Scalar(connection, null, "PRAGMA quick_check"), "ok") ||
                Scalar(connection, null, "PRAGMA foreign_key_check") is not null))
            {
                throw new JournalException("journal.schemaOrIntegrity");
            }

            Execute(connection, null, "PRAGMA foreign_keys=ON; PRAGMA synchronous=EXTRA");
            if (!Equals(Scalar(connection, null, "PRAGMA journal_mode=DELETE"), "delete") ||
                !Equals(Scalar(connection, null, "PRAGMA synchronous"), 3L))
            {
                throw new JournalException("database.durability");
            }

            return connection;
        }
        catch (SqliteException) { connection.Dispose(); throw new JournalException("database.error"); }
        catch { connection.Dispose(); throw; }
    }

    private JournalTime Now()
    {
        var now = clock.Read();
        if (now.BootId == Guid.Empty || now.SinceBoot < TimeSpan.Zero)
        {
            throw new JournalException("clock.invalid");
        }

        return now;
    }

    private static void CheckArtifact(string artifact)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        if (new UTF8Encoding(false, true).GetByteCount(artifact) > ArtifactLimit)
        {
            throw new JournalException("artifact.tooLarge");
        }
    }
    private static void CheckStoredArtifact(string artifact)
    {
        try { CheckArtifact(artifact); }
        catch (Exception error) when (error is ArgumentException or JournalException) { throw new JournalException("journal.corrupt"); }
    }
    private static string Id(Guid value) => value.ToString("D");
    private static Guid ParseId(string value, bool allowEmpty = false)
    {
        if (!Guid.TryParseExact(value, "D", out var id) || (!allowEmpty && id == Guid.Empty))
        {
            throw new JournalException("journal.corrupt");
        }

        return id;
    }
    private static string Revision(ulong revision) => revision.ToString(CultureInfo.InvariantCulture);
    private static ulong ParseRevision(string value) => ulong.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture);
    private static SqliteCommand Command(SqliteConnection connection, SqliteTransaction? transaction, string sql, params (string Name, object? Value)[] parameters)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }

        return command;
    }
    private static void Execute(SqliteConnection connection, SqliteTransaction? transaction, string sql, params (string Name, object? Value)[] parameters)
    {
        using var command = Command(connection, transaction, sql, parameters);
        command.ExecuteNonQuery();
    }
    private static object? Scalar(SqliteConnection connection, SqliteTransaction? transaction, string sql, params (string Name, object? Value)[] parameters)
    {
        using var command = Command(connection, transaction, sql, parameters);
        return command.ExecuteScalar();
    }

    private const string Schema = """
        PRAGMA application_id=0x4e52474c;
        PRAGMA user_version=2;
        CREATE TABLE operations(id TEXT PRIMARY KEY,agent TEXT NOT NULL,owner TEXT NOT NULL,revision TEXT NOT NULL,
          candidate TEXT NOT NULL,rollback TEXT NOT NULL,candidate_hash TEXT NOT NULL,rollback_hash TEXT NOT NULL,
          timeout INTEGER NOT NULL,boot TEXT NOT NULL,started INTEGER NOT NULL,phase INTEGER NOT NULL) STRICT;
        CREATE TABLE enrollment(singleton INTEGER PRIMARY KEY CHECK(singleton=1),agent TEXT NOT NULL,owner TEXT NOT NULL,
          revision TEXT NOT NULL,artifact TEXT NOT NULL,digest TEXT NOT NULL,boot TEXT NOT NULL,active TEXT REFERENCES operations(id),
          resource_bound INTEGER NOT NULL DEFAULT 0 CHECK(resource_bound IN(0,1))) STRICT;
        CREATE TABLE events(operation TEXT NOT NULL REFERENCES operations(id),sequence INTEGER NOT NULL,
          kind INTEGER NOT NULL,elapsed INTEGER NOT NULL,watchdog TEXT NOT NULL,error TEXT,phase INTEGER NOT NULL,
          PRIMARY KEY(operation,sequence)) STRICT;
        """ + ReceiptSchema;
}

/// <summary>Verified enrolled state; does not establish that the kernel currently matches this artifact.</summary>
/// <param name="Ownership">Last-confirmed enrolled ownership and revision.</param>
/// <param name="Artifact">Exact last-confirmed artifact text.</param>
public sealed record JournalEnrollment(ResourceOwnership Ownership, string Artifact);

/// <summary>Durable transition result; expired or interrupted operations can change phase while denying an acknowledgment.</summary>
/// <param name="Entry">Resulting verified operation snapshot.</param>
/// <param name="Accepted">Whether the requested acknowledgment was accepted.</param>
/// <param name="ErrorCode">Stable denial code or null.</param>
public sealed record JournalUpdate(JournalEntry Entry, bool Accepted, string? ErrorCode);
