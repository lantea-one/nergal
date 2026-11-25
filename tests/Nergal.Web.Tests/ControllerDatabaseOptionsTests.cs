using Nergal.ControllerState;

namespace Nergal.Web.Tests;

/// <summary>Verifies explicit controller database selection.</summary>
public sealed class ControllerDatabaseOptionsTests
{
    /// <summary>Each server provider requires an explicitly selected database.</summary>
    [Theory]
    [InlineData("postgresql", ControllerDatabaseProvider.PostgreSql, "Host=127.0.0.1")]
    [InlineData("mariadb", ControllerDatabaseProvider.MariaDb, "Server=127.0.0.1")]
    [InlineData("mysql", ControllerDatabaseProvider.MySql, "Server=127.0.0.1")]
    [InlineData("sqlserver", ControllerDatabaseProvider.SqlServer, "Server=127.0.0.1")]
    public void ServerOptionsRequireAnExplicitDatabase(string name, ControllerDatabaseProvider provider, string address)
    {
        Assert.Equal(provider, ControllerStateOptions.ParseProvider(name));
        Assert.Throws<ArgumentException>(() => new ControllerStateOptions(provider, address));
        var options = new ControllerStateOptions(provider, address + ";Database=synthetic_controller");
        Assert.Equal(provider, options.Provider);
        Assert.Null(options.Directory);
    }

    /// <summary>A mistyped provider cannot select SQLite or a different server engine.</summary>
    [Fact]
    public void InvalidProviderFailsClosed()
    {
        Assert.Equal(ControllerDatabaseProvider.Sqlite, ControllerStateOptions.ParseProvider(null));
        Assert.Throws<ArgumentException>(() => ControllerStateOptions.ParseProvider("sql"));
    }
}
