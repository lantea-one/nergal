using System.Globalization;
using Microsoft.Data.Sqlite;
using Nergal.Core.Controller;
using Nergal.Core.Identity;

namespace Nergal.ControllerState;

public sealed partial class ControllerStateStore
{
    /// <summary>Explicitly upgrades a protected schema-1 controller database while preserving existing state and audit history.</summary>
    /// <remarks>Stop controller writers first and retain a verified backup. The web host never calls this operation.</remarks>
    /// <exception cref="ControllerStateException">Schema, protection, durability or migration validation fails.</exception>
    public static ControllerStateStore Upgrade(ControllerStateOptions options, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!OperatingSystem.IsLinux()) { throw new PlatformNotSupportedException("Controller persistence requires Linux file protection."); }
        var path = ValidatePaths(options.Directory, true);
        try
        {
            using var conn = new SqliteConnection(ConnectionString(path)); conn.Open(); ConfigureConnection(conn);
            using var tx = conn.BeginTransaction(deferred: false);
            var version = ScalarLong(conn, tx, "PRAGMA user_version");
            if (version == SchemaVersion) { ValidateSchemaAndIntegrity(conn, tx); }
            else if (version == 1 && ScalarLong(conn, tx, "PRAGMA application_id") == ApplicationId &&
                ScalarString(conn, tx, "PRAGMA quick_check") == "ok" &&
                ScalarLong(conn, tx, "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND tbl_name='audit_log' AND name IN ('audit_no_update','audit_no_delete')") == 2 &&
                ScalarLong(conn, tx, "SELECT count(*) FROM sqlite_master WHERE name LIKE 'native_source%'") == 0)
            {
                ValidateAuditDefinitions(conn, tx);
                // Exercise required legacy columns before creating anything. Failures roll the transaction back.
                ExecuteNonQuery(conn, tx, "SELECT id,name FROM hosts LIMIT 0; SELECT revision,policy_json FROM policy_revisions LIMIT 0; SELECT sequence,actor_id FROM audit_log LIMIT 0;");
                ExecuteNonQuery(conn, tx, NativeSourcesSchemaSql);
                ExecuteNonQuery(conn, tx, "PRAGMA user_version=2;");
                ValidateSchemaAndIntegrity(conn, tx);
            }
            else { throw new ControllerStateException("controller.upgradeUnsupported"); }
            tx.Commit();
        }
        catch (SqliteException ex) { throw new ControllerStateException("controller.upgradeFailed", ex); }
        return Open(options, timeProvider);
    }

    /// <summary>Imports an immutable source and its audit entry atomically; it does not parse or execute nft syntax.</summary>
    /// <exception cref="ControllerStateException">Role is denied, capacity is exhausted or protected database integrity fails.</exception>
    public NativeSourceSummary ImportNativeSource(NativeSourceContent content, string actorId, string actorRole)
    {
        ArgumentNullException.ThrowIfNull(content); ValidateActor(actorId, actorRole);
        if (actorRole != NergalRoles.Administrator) { throw new ControllerStateException("rbac.denied"); }
        return Write((conn, tx) =>
        {
            if (ScalarLong(conn, tx, "SELECT count(*) FROM native_sources") >= 128 ||
                ScalarLong(conn, tx, "SELECT coalesce(sum(byte_length),0) FROM native_sources") + content.ByteLength > 33_554_432)
            { throw new ControllerStateException("source.capacityExceeded"); }
            var id = Guid.NewGuid(); var now = _timeProvider.GetUtcNow().ToUniversalTime();
            ExecuteNonQuery(conn, tx, """
                INSERT INTO native_sources(id,name,source_text,source_sha256,byte_length,imported_by_actor,imported_at_utc)
                VALUES($id,$name,$text,$sha,$size,$actor,$time)
                """, ("$id", id.ToString("D")), ("$name", content.Name), ("$text", content.Text),
                ("$sha", content.Digest), ("$size", content.ByteLength), ("$actor", actorId), ("$time", now.ToString("O", CultureInfo.InvariantCulture)));
            InsertAudit(conn, tx, now, actorId, actorRole, "source.import", id.ToString("D"), null, "succeeded", null);
            return new NativeSourceSummary(id, content.Name, content.Digest, content.ByteLength, actorId, now);
        });
    }

    /// <summary>Lists bounded persisted metadata without source text, newest first.</summary>
    public IReadOnlyList<NativeSourceSummary> ListNativeSources() => Read((conn, tx) =>
    {
        using var cmd = conn.CreateCommand(); cmd.Transaction = tx;
        cmd.CommandText = "SELECT id,name,source_sha256,byte_length,imported_by_actor,imported_at_utc FROM native_sources ORDER BY rowid DESC LIMIT 129";
        using var reader = cmd.ExecuteReader(); var result = new List<NativeSourceSummary>();
        while (reader.Read()) { result.Add(ReadNativeSummary(reader)); }
        if (result.Count > 128) { throw new ControllerStateException("source.corrupt"); }
        return result.AsReadOnly();
    });

    /// <summary>Reads an exact source by canonical identity and verifies its persisted byte length and digest.</summary>
    /// <exception cref="ControllerStateException">Persisted source is corrupt or database protection fails.</exception>
    public NativeSourceSnapshot? ReadNativeSource(Guid id) => Read((conn, tx) =>
    {
        using var cmd = conn.CreateCommand(); cmd.Transaction = tx;
        cmd.CommandText = "SELECT id,name,source_sha256,byte_length,imported_by_actor,imported_at_utc,source_text,length(CAST(source_text AS BLOB)) FROM native_sources WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", id.ToString("D")); using var reader = cmd.ExecuteReader();
        if (!reader.Read()) { return null; }
        var summary = ReadNativeSummary(reader);
        if (reader.GetInt64(7) != summary.ByteLength) { throw new ControllerStateException("source.corrupt"); }
        NativeSourceContent content;
        try { content = new(summary.Name, reader.GetString(6)); }
        catch (ArgumentException) { throw new ControllerStateException("source.corrupt"); }
        if (content.Digest != summary.Digest || content.ByteLength != summary.ByteLength) { throw new ControllerStateException("source.corrupt"); }
        return new NativeSourceSnapshot(summary, content);
    });

    private static NativeSourceSummary ReadNativeSummary(SqliteDataReader reader)
    {
        var id = Guid.ParseExact(reader.GetString(0), "D"); var name = reader.GetString(1); var digest = reader.GetString(2);
        var size = reader.GetInt32(3); var actor = reader.GetString(4);
        if (id == Guid.Empty || string.IsNullOrWhiteSpace(name) || name.Length > 120 || name != name.Trim() || name.Any(c => char.IsControl(c) || c is '/' or '\\') || digest.Length != 64 || digest.Any(c => !char.IsAsciiHexDigitLower(c)) ||
            size is < 1 or > NativeSourceContent.MaximumBytes || !ControllerActorIdentity.IsValid(actor))
        { throw new ControllerStateException("source.corrupt"); }
        return new(id, name, digest, size, actor, DateTimeOffset.ParseExact(reader.GetString(5), "O", CultureInfo.InvariantCulture));
    }

    private static void ValidateNativeSourceSchema(SqliteConnection conn, SqliteTransaction tx)
    {
        RequireDefinition(conn, tx, "native_sources", NativeSourcesTableSql);
        RequireDefinition(conn, tx, "native_sources_no_update", NativeSourcesUpdateTriggerSql);
        RequireDefinition(conn, tx, "native_sources_no_delete", NativeSourcesDeleteTriggerSql);
    }

    private static void RequireDefinition(SqliteConnection conn, SqliteTransaction tx, string name, string expected, string errorCode = "source.schemaInvalid")
    {
        static string Normalize(string sql) => new(sql.Trim().TrimEnd(';').Where(c => !char.IsWhiteSpace(c)).Select(char.ToUpperInvariant).ToArray());
        var actual = ScalarString(conn, tx, "SELECT sql FROM sqlite_master WHERE name=$name", ("$name", name));
        if (Normalize(actual) != Normalize(expected)) { throw new ControllerStateException(errorCode); }
    }

    private static void ValidateAuditDefinitions(SqliteConnection conn, SqliteTransaction tx)
    {
        RequireDefinition(conn, tx, "audit_no_update", "CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;", "controller.corrupt");
        RequireDefinition(conn, tx, "audit_no_delete", "CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;", "controller.corrupt");
    }

    private const string NativeSourcesTableSql = """
        CREATE TABLE native_sources (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            source_text TEXT NOT NULL,
            source_sha256 TEXT NOT NULL,
            byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 1 AND 524288),
            imported_by_actor TEXT NOT NULL,
            imported_at_utc TEXT NOT NULL
        ) STRICT;
        """;
    private const string NativeSourcesUpdateTriggerSql = """
        CREATE TRIGGER native_sources_no_update BEFORE UPDATE ON native_sources
        BEGIN SELECT RAISE(ABORT, 'native sources are immutable'); END;
        """;
    private const string NativeSourcesDeleteTriggerSql = """
        CREATE TRIGGER native_sources_no_delete BEFORE DELETE ON native_sources
        BEGIN SELECT RAISE(ABORT, 'native sources are immutable'); END;
        """;
    private const string NativeSourcesSchemaSql = NativeSourcesTableSql + NativeSourcesUpdateTriggerSql + NativeSourcesDeleteTriggerSql;
}
