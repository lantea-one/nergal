using System.Text.Json;
using Nergal.Core.Identity;

namespace Nergal.Core.Tests;

/// <summary>Optional signed metadata must remain bounded descriptive data, never an identity or authority overlay.</summary>
public sealed class OidcProfileMapperTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 2, 9, 0, 0, TimeSpan.Zero);
    private static readonly OidcProfileMapping Mapping = new("https://identity.example.test", 1, true, "name", "given_name", "family_name", "email", null);

    /// <summary>Invalid authority-like selectors and expressions cannot become profile mappings.</summary>
    [Theory]
    [InlineData("sub")]
    [InlineData("roles")]
    [InlineData("groups")]
    [InlineData("amr")]
    [InlineData("email_verified")]
    [InlineData("$.profile.name")]
    [InlineData("name[0]")]
    [InlineData("bad\nname")]
    public void Mapping_DeniesReservedClaimsAndExpressions(string claim) => Assert.False(OidcProfileMapper.IsValid(Mapping with { DisplayNameClaim = claim }));

    /// <summary>Exact HTTPS issuers and literal custom names are retained; no issuer normalization joins identities.</summary>
    [Fact]
    public void Mapping_ValidatesIssuerBoundsAndLiteralNames()
    {
        Assert.True(OidcProfileMapper.IsValid(Mapping with { DisplayNameClaim = "https://claims.example.test/display-name", EmailClaim = "" }));
        foreach (var issuer in new[] { "http://identity.example.test", "https://user@identity.example.test", "https://identity.example.test?x=1", "https://identity.example.test/#fragment" })
        { Assert.False(OidcProfileMapper.IsValid(Mapping with { Issuer = issuer })); }
        Assert.False(OidcProfileMapper.IsValid(Mapping with { GivenNameClaim = new string('x', 129) }));
    }

    /// <summary>Claim shape failures become explicit value-free diagnostics and do not infer or concatenate values.</summary>
    [Fact]
    public void Projection_ReportsOptionalMissingAndInvalidValues()
    {
        using var json = JsonDocument.Parse("""{"name":["Administrator"],"given_name":null,"family_name":"valid family","email":"not a mailbox"}""");
        var result = OidcProfileMapper.Project(Mapping, json.RootElement, DateTimeOffset.Parse("2026-01-02T12:00:00+03:00"));
        Assert.Equal(new ProfileMetadata(FamilyName: "valid family"), result.Metadata);
        Assert.Equal(["displayName.invalid", "givenName.missing", "email.invalid"], result.Diagnostics);
        Assert.Equal(TimeSpan.Zero, result.ObservedUtc.Offset);
        Assert.Equal(Mapping.Issuer, result.Issuer);
        using var ambiguous = JsonDocument.Parse("""{"name":"first","name":"second"}""");
        Assert.Throws<ArgumentException>(() => OidcProfileMapper.Project(Mapping, ambiguous.RootElement, Now));
    }

    /// <summary>Invalid Unicode in optional metadata is unavailable rather than a string-decoding exception.</summary>
    [Fact]
    public void Projection_RejectsMalformedUnicodeWithoutExposingValues()
    {
        using var json = JsonDocument.Parse("""{"name":"\uD800"}""");
        var result = OidcProfileMapper.Project(Mapping with { GivenNameClaim = "", FamilyNameClaim = "", EmailClaim = "" }, json.RootElement, Now);
        Assert.Empty(result.Metadata.DisplayName);
        Assert.Equal(["displayName.invalid"], result.Diagnostics);
    }

    /// <summary>Only selected exact top-level strings supply defaults; unknown or nested fields and verification claims grant nothing.</summary>
    [Fact]
    public void Projection_UsesSelectedFieldsAndDefensiveDiagnostics()
    {
        using var json = JsonDocument.Parse("""{"custom_name":"Provider <script>name</script>","given_name":"Given","family_name":"Family","email":"person@example.test","email_verified":true,"nested":{"name":"ignored"}}""");
        var result = OidcProfileMapper.Project(Mapping with { DisplayNameClaim = "custom_name" }, json.RootElement, Now);
        Assert.Equal(new ProfileMetadata("Provider <script>name</script>", "Given", "Family", "person@example.test"), result.Metadata);
        Assert.Empty(result.Diagnostics);
        Assert.Throws<ArgumentException>(() => OidcProfileMapper.Project(Mapping with { Enabled = false }, json.RootElement, Now));
        Assert.Throws<ArgumentException>(() => OidcProfileMapper.Project(Mapping with { Version = 0 }, json.RootElement, Now));
        var diagnostics = new List<string> { "email.missing" };
        var copy = new ProviderProfileSnapshot(Mapping.Issuer, 1, ProfileMetadata.Empty, Now, diagnostics);
        diagnostics.Clear();
        Assert.Equal(["email.missing"], copy.Diagnostics);
        Assert.Throws<NotSupportedException>(() => ((IList<string>)copy.Diagnostics).Clear());
        Assert.Throws<ArgumentException>(() => new ProviderProfileSnapshot(Mapping.Issuer, 1, ProfileMetadata.Empty, Now, ["unknown"]));
        Assert.Throws<ArgumentException>(() => new ProviderProfileSnapshot(Mapping.Issuer, 0, ProfileMetadata.Empty, Now, []));
        Assert.Equal(TimeSpan.Zero, new ProviderProfileSnapshot(Mapping.Issuer, 1, ProfileMetadata.Empty, Now.ToOffset(TimeSpan.FromHours(3)), []).ObservedUtc.Offset);
    }

    /// <summary>Blank overrides follow provider changes independently per field without mutating either input.</summary>
    [Fact]
    public void Metadata_ResolvesPerFieldOverridesWithoutIdentityMeaning()
    {
        var defaults = new ProfileMetadata("Provider", "Provider given", "Provider family", "provider@example.test");
        var local = new ProfileMetadata("Local", FamilyName: "Local family");
        Assert.Equal(new ProfileMetadata("Local", "Provider given", "Local family", "provider@example.test"), local.Over(defaults));
        Assert.Equal("Provider", defaults.DisplayName);
        Assert.Empty(local.Email);
        Assert.Throws<ArgumentNullException>(() => local.Over(null!));
        Assert.Throws<ArgumentException>(() => local.Over(new ProfileMetadata(Email: "not email")));
    }

    /// <summary>Malformed Unicode, hidden controls, oversized names and display-name mailboxes cannot persist as profile metadata.</summary>
    [Fact]
    public void Metadata_RejectsInvalidTextAndMailboxForms()
    {
        Assert.True(new ProfileMetadata(new string('x', 80), Email: "person@example.test").IsValid);
        foreach (var value in new[] { "hidden\ncontrol", "bad\ud800", new string('x', 81) })
        { Assert.False(new ProfileMetadata(value).IsValid); }
        foreach (var email in new[] { "not-email", "name@example.test\n", "Person <person@example.test>", "two@@example.test" })
        { Assert.False(new ProfileMetadata(Email: email).IsValid); }
    }
}
