using Microsoft.Data.Sqlite;

namespace Nergal.ControllerState;

public sealed partial class ControllerStateStore
{
    /// <summary>Explicitly upgrades a protected schema-1/2 controller database while preserving existing state and audit history.</summary>
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
            else if (version is 1 or 2 && ScalarLong(conn, tx, "PRAGMA application_id") == ApplicationId &&
                ScalarString(conn, tx, "PRAGMA quick_check") == "ok" &&
                ScalarLong(conn, tx, "SELECT count(*) FROM sqlite_master WHERE name LIKE 'reusable_object%'") == 0)
            {
                ValidateAuditDefinitions(conn, tx);
                ExecuteNonQuery(conn, tx, "SELECT id,name FROM hosts LIMIT 0; SELECT revision,policy_json FROM policy_revisions LIMIT 0; SELECT sequence,actor_id FROM audit_log LIMIT 0;");
                if (version == 1)
                {
                    if (ScalarLong(conn, tx, "SELECT count(*) FROM sqlite_master WHERE name LIKE 'native_source%'") != 0) { throw new ControllerStateException("controller.upgradeUnsupported"); }
                    ExecuteNonQuery(conn, tx, NativeSourcesSchemaSql);
                }
                else { ValidateNativeSourceSchema(conn, tx); }
                ExecuteNonQuery(conn, tx, ObjectsSchemaSql);
                ExecuteNonQuery(conn, tx, "PRAGMA user_version=3;");
                ValidateSchemaAndIntegrity(conn, tx);
            }
            else { throw new ControllerStateException("controller.upgradeUnsupported"); }
            tx.Commit();
        }
        catch (SqliteException ex) { throw new ControllerStateException("controller.upgradeFailed", ex); }
        return Open(options, timeProvider);
    }

}
