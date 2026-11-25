using Nergal.Core.Identity;

namespace Nergal.Core.Tests;

/// <summary>Trust configuration accepts exact bounded values without granting identities or normalizing ambiguous input.</summary>
public sealed class OidcConnectionSettingsTests
{
    private static OidcConnectionSettings Settings(string issuer = "https://identity.example.test", string callback = "https://firewall.example.test/signin-oidc",
        string claim = "groups", string[]? admins = null, string[]? auditors = null) => new(true, issuer, "client", callback, claim, admins ?? ["admins"], auditors ?? ["auditors"]);

    /// <summary>Untrusted callback, issuer and expression forms never become active trust.</summary>
    [Theory]
    [InlineData("http://identity.example.test", "https://firewall.example.test/signin-oidc", "groups")]
    [InlineData("https://identity.example.test?tenant=x", "https://firewall.example.test/signin-oidc", "groups")]
    [InlineData("https://identity.example.test", "https://firewall.example.test/signin-oidc?next=x", "groups")]
    [InlineData("https://identity.example.test", "https://user:pass@firewall.example.test/signin-oidc", "groups")]
    [InlineData("https://identity.example.test", "https://firewall.example.test/other", "groups")]
    [InlineData("https://identity.example.test", "https://firewall.example.test/signin-oidc", "$.groups")]
    [InlineData("https://identity.example.test", "https://firewall.example.test/signin-oidc", "sub")]
    public void AmbiguousTrust_IsDenied(string issuer, string callback, string claim) => Assert.False(Settings(issuer, callback, claim).IsValid);

    /// <summary>Input mutation, duplicate groups and overlapping roles cannot change the immutable contract.</summary>
    [Fact]
    public void GroupSnapshots_AreDefensiveExactAndDisjoint()
    {
        var admins = new[] { "admins" };
        var settings = Settings(admins: admins);
        admins[0] = "auditors";
        Assert.True(settings.IsValid); Assert.Equal("admins", Assert.Single(settings.AdministratorGroups));
        Assert.True(Settings(admins: ["Admins"], auditors: ["admins"]).IsValid);
        Assert.False(Settings(admins: ["same"], auditors: ["same"]).IsValid);
        Assert.False(Settings(admins: ["same", "same"]).IsValid);
        Assert.False(Settings(admins: [], auditors: []).IsValid);
        Assert.False(Settings(admins: Enumerable.Range(0, 33).Select(i => i.ToString()).ToArray()).IsValid);
    }
}
