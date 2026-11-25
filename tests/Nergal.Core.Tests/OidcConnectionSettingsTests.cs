using System.Text.Json;
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

    /// <summary>Only an explicit provider decision or an exact signed claim can satisfy MFA.</summary>
    [Theory]
    [InlineData("{}", false)]
    [InlineData("{\"amr\":\"mfa\"}", true)]
    [InlineData("{\"amr\":[\"pwd\",\"mfa\"]}", true)]
    [InlineData("{\"acr\":\"mfa\"}", false)]
    [InlineData("{\"AMR\":\"mfa\"}", false)]
    [InlineData("{\"amr\":\"MFA\"}", false)]
    [InlineData("{\"amr\":\"mfa otp\"}", false)]
    [InlineData("{\"amr\":[]}", false)]
    [InlineData("{\"amr\":{\"value\":\"mfa\"}}", false)]
    [InlineData("{\"nested\":{\"amr\":\"mfa\"}}", false)]
    [InlineData("{\"amr\":[\"mfa\",true]}", false)]
    [InlineData("{\"amr\":[\"mfa\",\"\"]}", false)]
    [InlineData("{\"amr\":[\"mfa\",\"mfa\"]}", false)]
    [InlineData("{\"amr\":[\"mfa\",\"pwd\",\"pwd\"]}", false)]
    [InlineData("{\"amr\":[\"mfa\",\"\\ud800\"]}", false)]
    [InlineData("{\"amr\":null,\"am\\u0072\":\"mfa\"}", false)]
    public void AssuranceRequiresExactUnambiguousEvidence(string json, bool expected)
    {
        using var document = JsonDocument.Parse(json);
        Assert.False(Settings().AssuresVerifiedMfa(document.RootElement));
        Assert.True(Assurance(OidcMfaAssuranceMode.ProviderBypass).AssuresVerifiedMfa(document.RootElement));
        Assert.Equal(expected, Assurance(OidcMfaAssuranceMode.SignedClaim, "amr", "mfa").AssuresVerifiedMfa(document.RootElement));
    }

    /// <summary>Unknown modes, ambiguous selectors, and settings inconsistent with the selected mode are denied.</summary>
    [Theory]
    [InlineData((OidcMfaAssuranceMode)99, "", "")]
    [InlineData(OidcMfaAssuranceMode.Deny, "amr", "")]
    [InlineData(OidcMfaAssuranceMode.ProviderBypass, "", "mfa")]
    [InlineData(OidcMfaAssuranceMode.SignedClaim, "amr", "")]
    [InlineData(OidcMfaAssuranceMode.SignedClaim, "", "mfa")]
    [InlineData(OidcMfaAssuranceMode.SignedClaim, "$.amr", "mfa")]
    [InlineData(OidcMfaAssuranceMode.SignedClaim, "groups", "admins")]
    [InlineData(OidcMfaAssuranceMode.SignedClaim, "aud", "client")]
    [InlineData(OidcMfaAssuranceMode.SignedClaim, "email", "mfa@example.test")]
    public void InvalidAssuranceSettingsAreDenied(OidcMfaAssuranceMode mode, string claim, string value) =>
        Assert.False(Assurance(mode, claim, value).IsValid);

    /// <summary>Array and value limits still apply when the first element matches.</summary>
    [Fact]
    public void AssuranceChecksTheEntireBoundedArray()
    {
        var settings = Assurance(OidcMfaAssuranceMode.SignedClaim, "amr", "mfa");
        Assert.True(settings.IsValid);
        using var oversizedArray = JsonDocument.Parse(JsonSerializer.Serialize(new { amr = Enumerable.Range(0, 32).Select(i => $"method{i}").Prepend("mfa") }));
        using var oversizedValue = JsonDocument.Parse(JsonSerializer.Serialize(new { amr = new[] { "mfa", new string('x', 257) } }));
        Assert.False(settings.AssuresVerifiedMfa(oversizedArray.RootElement));
        Assert.False(settings.AssuresVerifiedMfa(oversizedValue.RootElement));
    }

    private static OidcConnectionSettings Assurance(OidcMfaAssuranceMode mode, string claim = "", string value = "") =>
        new(true, "https://identity.example.test", "client", "https://firewall.example.test/signin-oidc",
            "groups", ["admins"], ["auditors"], mode, claim, value);
}
