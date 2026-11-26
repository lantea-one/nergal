using Microsoft.Data.SqlClient;
using MySqlConnector;
using Npgsql;

namespace Nergal.ControllerState;

/// <summary>Database engine for the controller store.</summary>
public enum ControllerDatabaseProvider
{
    /// <summary>Protected local SQLite database.</summary>
    Sqlite,
    /// <summary>PostgreSQL server.</summary>
    PostgreSql,
    /// <summary>MariaDB server.</summary>
    MariaDb,
    /// <summary>MySQL server.</summary>
    MySql,
    /// <summary>Microsoft SQL Server.</summary>
    SqlServer,
}

/// <summary>Explicit controller storage configuration.</summary>
public sealed class ControllerStateOptions
{
    /// <summary>Validates an absolute NUL-free directory path for controller state persistence.</summary>
    /// <exception cref="ArgumentException">Directory is empty, relative, or contains a NUL character.</exception>
    public ControllerStateOptions(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        if (!Path.IsPathFullyQualified(directory) || directory.Contains('\0'))
        {
            throw new ArgumentException("An absolute NUL-free controller state directory is required.", nameof(directory));
        }

        Directory = Path.GetFullPath(directory);
    }

    /// <summary>Selects an existing dedicated server database using driver-level credentials and transport settings.</summary>
    /// <exception cref="ArgumentException">The provider or connection string is invalid.</exception>
    public ControllerStateOptions(ControllerDatabaseProvider provider, string connectionString)
    {
        if (provider is ControllerDatabaseProvider.Sqlite || !Enum.IsDefined(provider))
        {
            throw new ArgumentException("A server database provider is required.", nameof(provider));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        var database = provider switch
        {
            ControllerDatabaseProvider.PostgreSql => new NpgsqlConnectionStringBuilder(connectionString).Database,
            ControllerDatabaseProvider.MariaDb or ControllerDatabaseProvider.MySql => new MySqlConnectionStringBuilder(connectionString).Database,
            ControllerDatabaseProvider.SqlServer => new SqlConnectionStringBuilder(connectionString).InitialCatalog,
            _ => null,
        };
        if (string.IsNullOrWhiteSpace(database))
        {
            throw new ArgumentException("An explicit controller database is required.", nameof(connectionString));
        }

        Provider = provider;
        ConnectionString = connectionString;
    }

    /// <summary>Gets the configured database provider.</summary>
    public ControllerDatabaseProvider Provider { get; }

    /// <summary>Gets the canonical absolute SQLite state directory path, when configured.</summary>
    public string? Directory { get; }

    internal string? ConnectionString { get; }

    /// <summary>Resolves a configuration provider name, defaulting to SQLite when omitted.</summary>
    /// <exception cref="ArgumentException">The provider name is unknown.</exception>
    public static ControllerDatabaseProvider ParseProvider(string? provider) => provider switch
    {
        null or "" or "sqlite" => ControllerDatabaseProvider.Sqlite,
        "postgresql" => ControllerDatabaseProvider.PostgreSql,
        "mariadb" => ControllerDatabaseProvider.MariaDb,
        "mysql" => ControllerDatabaseProvider.MySql,
        "sqlserver" => ControllerDatabaseProvider.SqlServer,
        _ => throw new ArgumentException("Unknown controller database provider.", nameof(provider)),
    };
}

/// <summary>Stable diagnostic failure thrown when controller persistence validation or integrity fails.</summary>
public sealed class ControllerStateException : Exception
{
    internal ControllerStateException(string code) : base(code) => Code = code;

    internal ControllerStateException(string code, Exception innerException) : base(code, innerException) => Code = code;

    /// <summary>Gets the stable error identifier.</summary>
    public string Code { get; }
}
