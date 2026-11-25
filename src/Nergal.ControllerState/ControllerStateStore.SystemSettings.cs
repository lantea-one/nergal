using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Nergal.Core.Controller;
using Nergal.Core.Identity;

namespace Nergal.ControllerState;

public sealed partial class ControllerStateStore
{
    /// <summary>Reads the current contents for views that do not edit settings.</summary>
    public SystemSettingsSnapshot ReadSystemSettings() => ReadSystemSettingsVersion().Settings;

    /// <summary>Reads settings and their edit token from a single committed version.</summary>
    public SystemSettingsVersion ReadSystemSettingsVersion() => Read(ReadCurrentSettings);

    /// <summary>Appends a settings version and its audit event after checking the caller's edit token.</summary>
    /// <remarks>The comparison occurs under the SQLite writer reservation. A divergent restore may reuse a version number.</remarks>
    /// <exception cref="ControllerStateException">The caller is denied, the settings are invalid, the edit is stale, or the transaction fails.</exception>
    public SystemSettingsVersion SaveSystemSettings(SystemSettingsSnapshot settings, string expectedToken, string actorId, string actorRole)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ValidateActor(actorId, actorRole);
        if (actorRole != NergalRoles.Administrator) { throw new ControllerStateException("rbac.denied"); }
        if (!SystemSettingsVersion.IsValidFormToken(expectedToken)) { throw new ControllerStateException("settings.invalidVersion"); }
        if (SystemSettingsCodec.Validate(settings).Count != 0) { throw new ControllerStateException("settings.invalid"); }

        var json = SystemSettingsCodec.Serialize(settings);
        if (json.Length > SystemSettingsCodec.MaximumJsonLength) { throw new ControllerStateException("settings.bounds"); }
        return Write((conn, tx) =>
        {
            var current = ReadCurrentSettings(conn, tx);
            if (current.FormToken != expectedToken) { throw new ControllerStateException("settings.stale"); }
            if (current.Version == long.MaxValue) { throw new ControllerStateException("settings.versionExhausted"); }

            var version = current.Version + 1;
            var formToken = Guid.NewGuid().ToString("N");
            var audit = InsertAudit(conn, tx, _timeProvider.GetUtcNow(), actorId, actorRole, "settings.update", "system",
                null, "succeeded", SettingsAuditDetail(version, formToken, json));
            ExecuteNonQuery(conn, tx, """
                INSERT INTO system_settings (version, form_token, settings_json, audit_sequence)
                VALUES ($version, $token, $json, $audit)
                """, ("$version", version), ("$token", formToken), ("$json", json), ("$audit", audit.Sequence));
            return new SystemSettingsVersion(version, formToken, settings, audit.TimestampUtc, actorId);
        });
    }

    private static SystemSettingsVersion ReadCurrentSettings(SqliteConnection conn, SqliteTransaction tx)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            SELECT s.version, s.form_token, s.settings_json, a.sequence, a.timestamp_utc, a.actor_id,
                   a.actor_role, a.action, a.target, a.revision, a.outcome, a.detail_code,
                   (SELECT max(sequence) FROM audit_log WHERE action = 'settings.update')
            FROM system_settings AS s LEFT JOIN audit_log AS a ON a.sequence = s.audit_sequence
            ORDER BY s.version DESC LIMIT 1
            """;
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) { throw new ControllerStateException("settings.corrupt"); }
        var version = reader.GetInt64(0);
        var token = reader.GetString(1);
        var json = reader.GetString(2);
        if (version < 0 || !SystemSettingsVersion.IsValidFormToken(token) || string.IsNullOrWhiteSpace(json))
        { throw new ControllerStateException("settings.corrupt"); }

        SystemSettingsSnapshot settings;
        try { settings = SystemSettingsCodec.Deserialize(json); }
        catch (JsonException) { throw new ControllerStateException("settings.corrupt"); }
        if (version == 0)
        {
            if (!reader.IsDBNull(3) || !reader.IsDBNull(12))
            { throw new ControllerStateException("settings.corrupt"); }
            return new(0, token, settings, null, null);
        }

        if (reader.IsDBNull(3) || reader.IsDBNull(12) || reader.GetInt64(3) != reader.GetInt64(12) ||
            !DateTimeOffset.TryParseExact(reader.GetString(4), "O", CultureInfo.InvariantCulture, DateTimeStyles.None, out var updated) ||
            updated.Offset != TimeSpan.Zero || !ControllerActorIdentity.IsValid(reader.GetString(5)) ||
            reader.GetString(6) != NergalRoles.Administrator || reader.GetString(7) != "settings.update" ||
            reader.GetString(8) != "system" || !reader.IsDBNull(9) || reader.GetString(10) != "succeeded" ||
            reader.IsDBNull(11) || reader.GetString(11) != SettingsAuditDetail(version, token, json))
        { throw new ControllerStateException("settings.corrupt"); }
        return new(version, token, settings, updated, reader.GetString(5));
    }

    private static string SettingsAuditDetail(long version, string formToken, string json)
    {
        // The token has a fixed width. Binding both fields detects mismatched rows even when version and audit sequence agree.
        var digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(formToken + json)));
        return "settings.version:" + version.ToString(CultureInfo.InvariantCulture) + ":" + digest;
    }

    private static void InitializeSystemSettings(SqliteConnection connection, SqliteTransaction transaction)
    {
        ExecuteNonQuery(connection, transaction, SystemSettingsTableSql);
        ExecuteNonQuery(connection, transaction, SettingsAuditIndexSql);
        ExecuteNonQuery(connection, transaction, SettingsAppendTriggerSql);
        ExecuteNonQuery(connection, transaction, SettingsUpdateTriggerSql);
        ExecuteNonQuery(connection, transaction, SettingsDeleteTriggerSql);
        ExecuteNonQuery(connection, transaction, """
            INSERT INTO system_settings (version, form_token, settings_json)
            VALUES (0, $token, $json)
            """, ("$token", Guid.NewGuid().ToString("N")), ("$json", SystemSettingsCodec.Serialize(SystemSettingsSnapshot.Default)));
    }

    private static void ValidateSystemSettingsSchema(SqliteConnection connection, SqliteTransaction transaction)
    {
        RequireDefinition(connection, transaction, "system_settings", SystemSettingsTableSql, "controller.corrupt");
        RequireDefinition(connection, transaction, "settings_audit_sequence", SettingsAuditIndexSql, "controller.corrupt");
        RequireDefinition(connection, transaction, "system_settings_append", SettingsAppendTriggerSql, "controller.corrupt");
        RequireDefinition(connection, transaction, "system_settings_no_update", SettingsUpdateTriggerSql, "controller.corrupt");
        RequireDefinition(connection, transaction, "system_settings_no_delete", SettingsDeleteTriggerSql, "controller.corrupt");
    }

    private const string SystemSettingsTableSql = """
        CREATE TABLE system_settings (
            version INTEGER PRIMARY KEY CHECK(version >= 0),
            form_token TEXT NOT NULL UNIQUE CHECK(length(form_token) = 32 AND form_token NOT GLOB '*[^0-9a-f]*'),
            settings_json TEXT NOT NULL CHECK(length(trim(settings_json)) > 0),
            audit_sequence INTEGER UNIQUE REFERENCES audit_log(sequence) ON DELETE RESTRICT,
            CHECK((version = 0 AND audit_sequence IS NULL) OR (version > 0 AND audit_sequence IS NOT NULL))
        ) STRICT;
        """;

    private const string SettingsAuditIndexSql = """
        CREATE INDEX settings_audit_sequence ON audit_log(sequence) WHERE action = 'settings.update';
        """;

    private const string SettingsAppendTriggerSql = """
        CREATE TRIGGER system_settings_append BEFORE INSERT ON system_settings
        WHEN NEW.version <> (SELECT coalesce(max(version) + 1, 0) FROM system_settings)
          OR EXISTS (SELECT 1 FROM system_settings
                     WHERE form_token = NEW.form_token OR audit_sequence = NEW.audit_sequence)
        BEGIN SELECT RAISE(ABORT, 'settings versions must be consecutive and unique'); END;
        """;

    private const string SettingsUpdateTriggerSql = """
        CREATE TRIGGER system_settings_no_update BEFORE UPDATE ON system_settings
        BEGIN SELECT RAISE(ABORT, 'settings versions are immutable'); END;
        """;

    private const string SettingsDeleteTriggerSql = """
        CREATE TRIGGER system_settings_no_delete BEFORE DELETE ON system_settings
        BEGIN SELECT RAISE(ABORT, 'settings versions are immutable'); END;
        """;
}
