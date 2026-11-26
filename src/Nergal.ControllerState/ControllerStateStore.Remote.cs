using System.Buffers.Binary;
using System.Data;
using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using MySqlConnector;
using Npgsql;

namespace Nergal.ControllerState;

public sealed partial class ControllerStateStore
{
    private const string RemoteMetadata = "controller_metadata";
    private const string StatementSeparator = "-- nergal:statement";

    private static ControllerStateStore InitializeRemote(ControllerStateOptions options, TimeProvider? timeProvider)
    {
        var store = new ControllerStateStore(options, null, timeProvider ?? TimeProvider.System);
        try
        {
            using var connection = store.OpenConnection(initializing: true);
            store.AcquireInitializationLock(connection);
            if (ScalarLong(connection, null, EmptyNamespaceQuery(options.Provider)) != 0)
            {
                throw new ControllerStateException("controller.exists");
            }

            // MySQL and MariaDB commit DDL implicitly. Publish the metadata and initial settings only
            // once all definitions exist, so a partial bootstrap cannot be opened as a controller.
            if (options.Provider is ControllerDatabaseProvider.MariaDb or ControllerDatabaseProvider.MySql)
            {
                store.CreateRemoteSchema(connection, null);
                using var transaction = connection.BeginTransaction();
                store.SeedRemoteSchema(connection, transaction);
                transaction.Commit();
            }
            else
            {
                using var transaction = connection.BeginTransaction();
                store.CreateRemoteSchema(connection, transaction);
                store.SeedRemoteSchema(connection, transaction);
                transaction.Commit();
            }

            // Bootstrap connections are unpooled. Disposal releases the session initialization lock.
        }
        catch (DbException ex)
        {
            throw new ControllerStateException("controller.initializeFailed", ex);
        }

        return Open(options, timeProvider);
    }

    private DbConnection OpenConnection(bool initializing = false)
    {
        DbConnection connection = _options.Provider switch
        {
            ControllerDatabaseProvider.PostgreSql => new NpgsqlConnection(new NpgsqlConnectionStringBuilder(_options.ConnectionString)
            {
                Pooling = !initializing,
                SearchPath = "public,pg_temp",
                IncludeErrorDetail = false,
            }.ConnectionString),
            ControllerDatabaseProvider.MariaDb or ControllerDatabaseProvider.MySql =>
                new MySqlConnection(new MySqlConnectionStringBuilder(_options.ConnectionString!)
                {
                    Pooling = !initializing,
                    ConnectionReset = true,
                    AllowUserVariables = false,
                }.ConnectionString),
            ControllerDatabaseProvider.SqlServer => new SqlConnection(new SqlConnectionStringBuilder(_options.ConnectionString)
            {
                Pooling = !initializing,
                MultipleActiveResultSets = false,
            }.ConnectionString),
            _ => new SqliteConnection(ConnectionString(_databasePath!)),
        };

        try
        {
            connection.Open();
            switch (connection)
            {
                case SqliteConnection sqlite:
                    ConfigureConnection(sqlite);
                    break;
                case MySqlConnection mysql:
                    var isMariaDb = mysql.ServerVersion.Contains("MariaDB", StringComparison.OrdinalIgnoreCase);
                    if (isMariaDb != (_options.Provider == ControllerDatabaseProvider.MariaDb))
                    {
                        throw new ControllerStateException("controller.wrongProvider");
                    }

                    ExecuteNonQuery(mysql, null, "SET SESSION foreign_key_checks = 1, unique_checks = 1, sql_mode = 'STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION'");
                    if (isMariaDb) { ExecuteNonQuery(mysql, null, "SET SESSION check_constraint_checks = 1"); }
                    break;
                case SqlConnection sqlServer:
                    if (ScalarString(sqlServer, null, "SELECT SCHEMA_NAME()") != "dbo")
                    {
                        throw new ControllerStateException("controller.invalidDatabaseSchema");
                    }
                    ExecuteNonQuery(sqlServer, null, """
                        SET ANSI_NULLS ON; SET ANSI_PADDING ON; SET ANSI_WARNINGS ON; SET ARITHABORT ON;
                        SET CONCAT_NULL_YIELDS_NULL ON; SET QUOTED_IDENTIFIER ON; SET NUMERIC_ROUNDABORT OFF;
                        """);
                    break;
            }

            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private void AcquireInitializationLock(DbConnection connection)
    {
        switch (_options.Provider)
        {
            case ControllerDatabaseProvider.PostgreSql:
                ExecuteNonQuery(connection, null, "SELECT pg_catalog.pg_advisory_lock(1314015043)");
                break;
            case ControllerDatabaseProvider.MariaDb:
            case ControllerDatabaseProvider.MySql:
                if (ScalarLong(connection, null, "SELECT GET_LOCK(SHA2(CONCAT('nergal.controller:', DATABASE()), 256), 10)") != 1)
                {
                    throw new ControllerStateException("controller.busy");
                }
                break;
            case ControllerDatabaseProvider.SqlServer:
                if (ScalarLong(connection, null, """
                    DECLARE @result int;
                    EXEC @result = sys.sp_getapplock @Resource=N'nergal.controller.init', @LockMode=N'Exclusive',
                        @LockOwner=N'Session', @LockTimeout=10000;
                    SELECT @result;
                    """) < 0)
                {
                    throw new ControllerStateException("controller.busy");
                }
                break;
        }
    }

    private static string EmptyNamespaceQuery(ControllerDatabaseProvider provider) => provider switch
    {
        ControllerDatabaseProvider.PostgreSql => """
            SELECT CASE WHEN EXISTS (
                SELECT 1 FROM pg_catalog.pg_namespace AS ns
                WHERE ns.nspname = 'public' AND NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_depend AS dep
                    WHERE dep.refclassid = 'pg_catalog.pg_namespace'::pg_catalog.regclass AND dep.refobjid = ns.oid
                )
            ) THEN 0 ELSE 1 END
            """,
        ControllerDatabaseProvider.SqlServer => """
            SELECT CASE WHEN DB_ID() <= 4
                OR EXISTS (SELECT 1 FROM sys.objects WHERE is_ms_shipped = 0)
                OR EXISTS (SELECT 1 FROM sys.triggers WHERE parent_class = 0 AND is_ms_shipped = 0)
                THEN 1 ELSE 0 END
            """,
        _ => """
            SELECT (SELECT count(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE())
                 + (SELECT count(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = DATABASE())
                 + (SELECT count(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA = DATABASE())
            """,
    };

    private void CreateRemoteSchema(DbConnection connection, DbTransaction? transaction)
    {
        var schema = _options.Provider switch
        {
            ControllerDatabaseProvider.MariaDb => ReadSqlResource("MySqlFamily", "schema")
                .Replace("__NERGAL_BINARY_COLLATION__", "utf8mb4_nopad_bin", StringComparison.Ordinal),
            ControllerDatabaseProvider.MySql => ReadSqlResource("MySqlFamily", "schema")
                .Replace("__NERGAL_BINARY_COLLATION__", "utf8mb4_0900_bin", StringComparison.Ordinal),
            _ => ReadSqlResource(_options.Provider.ToString(), "schema"),
        };
        foreach (var sql in schema.Split(StatementSeparator, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            ExecuteNonQuery(connection, transaction, sql);
        }
    }

    private void SeedRemoteSchema(DbConnection connection, DbTransaction transaction)
    {
        var fingerprint = ReadRemoteSchemaFingerprint(connection, transaction);
        ExecuteNonQuery(connection, transaction,
            $"INSERT INTO {RemoteMetadata} (id, schema_version, schema_fingerprint) VALUES (1, @version, @hash)",
            ("@version", SchemaVersion), ("@hash", fingerprint));
        SeedSystemSettings(connection, transaction);
    }

    private void ValidateRemoteSchema(DbConnection connection, DbTransaction transaction)
    {
        var expected = ScalarString(connection, transaction,
            $"SELECT schema_fingerprint FROM {RemoteMetadata} WHERE id=1 AND schema_version=@version", ("@version", SchemaVersion));
        if (expected.Length != 64 || expected != ReadRemoteSchemaFingerprint(connection, transaction))
        {
            throw new ControllerStateException("controller.corrupt");
        }
    }

    private string ReadRemoteSchemaFingerprint(DbConnection connection, DbTransaction transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = ReadSqlResource(_options.Provider.ToString(), "catalog");
        using var reader = command.ExecuteReader();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[sizeof(int)];
        while (reader.Read())
        {
            var definition = Encoding.UTF8.GetBytes(reader.GetString(0));
            BinaryPrimitives.WriteInt32BigEndian(length, definition.Length);
            hash.AppendData(length);
            hash.AppendData(definition);
        }

        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static string ReadSqlResource(string directory, string name)
    {
        var assembly = typeof(ControllerStateStore).Assembly;
        using var stream = assembly.GetManifestResourceStream($"Nergal.ControllerState.Sql.{directory}.{name}.sql")
            ?? throw new InvalidOperationException("Missing controller database SQL resource.");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private DbTransaction BeginControllerTransaction(DbConnection connection, bool writing)
    {
        if (connection is SqliteConnection sqlite)
        {
            return sqlite.BeginTransaction(deferred: !writing);
        }

        var transaction = connection.BeginTransaction(writing ? IsolationLevel.ReadCommitted : IsolationLevel.RepeatableRead);
        try
        {
            var lockSql = _options.Provider switch
            {
                ControllerDatabaseProvider.SqlServer when writing => $"SELECT id FROM {RemoteMetadata} WITH (XLOCK,HOLDLOCK) WHERE id=1",
                ControllerDatabaseProvider.SqlServer => $"SELECT id FROM {RemoteMetadata} WITH (HOLDLOCK) WHERE id=1",
                _ when writing => $"SELECT id FROM {RemoteMetadata} WHERE id=1 FOR UPDATE",
                _ => null,
            };
            if (lockSql is not null && ScalarLong(connection, transaction, lockSql) != 1)
            {
                throw new ControllerStateException("controller.corrupt");
            }

            return transaction;
        }
        catch
        {
            transaction.Dispose();
            throw;
        }
    }
}
