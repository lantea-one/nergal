using System.Runtime.Versioning;
using Microsoft.Extensions.Configuration;
using Nergal.Core.Identity;

namespace Nergal.Web.Tests;

/// <summary>Operator bootstrap trust is immutable within its process generation, even when configuration sources reload.</summary>
[SupportedOSPlatform("linux")]
public sealed class OidcBootstrapTests
{
    /// <summary>Deferred reads use the startup copy; reloaded issuer/client/secret inputs cannot silently reuse generation zero.</summary>
    [Fact]
    public void ReloadedConfiguration_CannotChangeBootstrapTrust()
    {
        var config = Configuration();
        var bootstrap = new Nergal.Web.OidcBootstrapConnection(config.GetSection("Oidc"));
        config["Oidc:Issuer"] = "https://other.example.test";
        config["Oidc:ClientId"] = "other-client";
        config["Oidc:ClientSecret"] = "replacement-secret";
        config["Oidc:MfaAssuranceMode"] = "ProviderBypass";
        var runtime = bootstrap.Runtime!;
        Assert.Equal(0, runtime.Snapshot.Version);
        Assert.Equal("https://identity.example.test", runtime.Snapshot.Settings.Issuer);
        Assert.Equal("client", runtime.Snapshot.Settings.ClientId);
        Assert.Equal("synthetic-secret", runtime.ClientSecret);
        Assert.Equal(OidcMfaAssuranceMode.Deny, runtime.Snapshot.Settings.MfaAssuranceMode);
        Assert.Same(runtime, bootstrap.Runtime);
    }

    /// <summary>Protected startup settings accept an explicit signed assurance policy.</summary>
    [Fact]
    public void BootstrapCanRequireAnExactSignedClaim()
    {
        var config = Configuration();
        config["Oidc:MfaAssuranceMode"] = "SignedClaim";
        config["Oidc:MfaAssuranceClaim"] = "acr";
        config["Oidc:MfaAssuranceValue"] = "urn:example:mfa";
        var assurance = new Nergal.Web.OidcBootstrapConnection(config.GetSection("Oidc")).Runtime!.Snapshot.Settings;
        Assert.Equal(OidcMfaAssuranceMode.SignedClaim, assurance.MfaAssuranceMode);
        Assert.Equal("acr", assurance.MfaAssuranceClaim);
        Assert.Equal("urn:example:mfa", assurance.MfaAssuranceValue);
    }

    /// <summary>Invalid or incomplete startup modes cannot become an implicit bypass.</summary>
    [Theory]
    [InlineData("1", "", "")]
    [InlineData("SignedClaim", "amr", "")]
    [InlineData("ProviderBypass", "", "mfa")]
    [InlineData(null, "amr", "mfa")]
    public void InvalidBootstrapAssuranceIsRejected(string? mode, string claim, string value)
    {
        var config = Configuration();
        config["Oidc:MfaAssuranceMode"] = mode;
        config["Oidc:MfaAssuranceClaim"] = claim;
        config["Oidc:MfaAssuranceValue"] = value;
        var bootstrap = new Nergal.Web.OidcBootstrapConnection(config.GetSection("Oidc"));
        Assert.Throws<InvalidOperationException>(() => bootstrap.Runtime);
    }

    private static IConfigurationRoot Configuration() => new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["Oidc:Enabled"] = "true",
        ["Oidc:Issuer"] = "https://identity.example.test",
        ["Oidc:ClientId"] = "client",
        ["Oidc:ClientSecret"] = "synthetic-secret",
        ["Oidc:CallbackUri"] = "https://firewall.example.test/signin-oidc",
        ["Oidc:GroupClaim"] = "groups",
        ["Oidc:AdministratorGroups:0"] = "admins",
    }).Build();
}
