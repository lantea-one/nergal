using System.Runtime.Versioning;
using Microsoft.Extensions.Configuration;

namespace Nergal.Web.Tests;

/// <summary>Operator bootstrap trust is immutable within its process generation, even when configuration sources reload.</summary>
[SupportedOSPlatform("linux")]
public sealed class OidcBootstrapTests
{
    /// <summary>Deferred reads use the startup copy; reloaded issuer/client/secret inputs cannot silently reuse generation zero.</summary>
    [Fact]
    public void ReloadedConfiguration_CannotChangeBootstrapTrust()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Oidc:Enabled"] = "true",
            ["Oidc:Issuer"] = "https://identity.example.test",
            ["Oidc:ClientId"] = "client",
            ["Oidc:ClientSecret"] = "synthetic-secret",
            ["Oidc:CallbackUri"] = "https://firewall.example.test/signin-oidc",
            ["Oidc:GroupClaim"] = "groups",
            ["Oidc:AdministratorGroups:0"] = "admins",
        }).Build();
        var bootstrap = new Nergal.Web.OidcBootstrapConnection(config.GetSection("Oidc"));
        config["Oidc:Issuer"] = "https://other.example.test";
        config["Oidc:ClientId"] = "other-client";
        config["Oidc:ClientSecret"] = "replacement-secret";
        var runtime = bootstrap.Runtime!;
        Assert.Equal(0, runtime.Snapshot.Version);
        Assert.Equal("https://identity.example.test", runtime.Snapshot.Settings.Issuer);
        Assert.Equal("client", runtime.Snapshot.Settings.ClientId);
        Assert.Equal("synthetic-secret", runtime.ClientSecret);
        Assert.Same(runtime, bootstrap.Runtime);
    }
}
