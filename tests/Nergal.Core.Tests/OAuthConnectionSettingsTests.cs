using System.Text.Json;
using Nergal.Core.Identity;

namespace Nergal.Core.Tests;

/// <summary>Tests the OAuth trust configuration and provider profile projection.</summary>
public sealed class OAuthConnectionSettingsTests
{
    private static readonly OAuthConnectionSettings Connection = new(true,
        "https://auth.example.test/authorize", "https://auth.example.test/token", "https://auth.example.test/me",
        "https://controller.example.test/signin-oauth", "fixture-client", "profile groups", "id", "groups", "admins",
        "auditors", new("name", "given_name", "", "email"));

    /// <summary>Credentials and tokens can travel only to their configured HTTPS origin and descriptive selectors cannot read authority fields.</summary>
    [Fact]
    public void RejectsSplitOriginAmbiguousRolesAndInvalidSelectors()
    {
        Assert.True(Connection.IsValid);
        Assert.All(new[]
        {
            Connection with { TokenEndpoint = "https://other.example.test/token" },
            Connection with { ProfileEndpoint = "https://auth.example.test:8443/me" },
            Connection with { AuthorizationEndpoint = "https://auth.example.test/authorize?scope=all" },
            Connection with { CallbackUri = "https://controller.example.test/signin-oidc" },
            Connection with { SubjectField = "groups" },
            Connection with { Fields = new("id") },
            Connection with { AdministratorGroups = "auditors" },
            Connection with { AuditorGroups = "auditors\nauditors" },
            Connection with { Scope = "profile  groups" },
        }, settings => Assert.False(settings.IsValid));
    }

    /// <summary>Only an unambiguous authoritative provider subject and role can produce an eligible proof.</summary>
    [Theory]
    [InlineData("""{"id":"one","groups":["admins","auditors"]}""")]
    [InlineData("""{"id":"one","groups":["auditors","auditors"]}""")]
    [InlineData("""{"id":"one","groups":"auditors"}""")]
    [InlineData("""{"id":"one","groups":["AUDITORS"]}""")]
    [InlineData("""{"id":"one","id":"two","groups":["auditors"]}""")]
    [InlineData("""{"id":12,"groups":["auditors"]}""")]
    [InlineData("""{"email":"one@example.test","groups":["auditors"]}""")]
    public void DeniesMalformedOrAmbiguousAuthority(string json)
    {
        using var document = JsonDocument.Parse(json);
        Assert.Null(Connection.ReadProfile(document.RootElement, 1, DateTimeOffset.UnixEpoch));
    }

    /// <summary>Metadata can be projected after authority is established and is independent of the immutable subject.</summary>
    [Fact]
    public void ProjectsOptionalMetadataWithoutMakingItAuthoritative()
    {
        using var document = JsonDocument.Parse("""
            {"id":"stable:one","groups":["auditors"],"name":"Fixture User","email":"invalid mailbox"}
            """);
        var proof = Assert.IsType<OAuthProfileProof>(Connection.ReadProfile(document.RootElement, 2, DateTimeOffset.UnixEpoch));
        Assert.Equal("stable:one", proof.Subject);
        Assert.Equal(NergalRoles.Auditor, proof.Role);
        Assert.Equal(new ProfileMetadata("Fixture User"), proof.Profile.Metadata);
        Assert.Equal(["givenName.missing", "email.invalid"], proof.Profile.Diagnostics);
        var actor = ControllerActorIdentity.FromOAuthAccount(Guid.Parse("00000000-0000-0000-0000-000000000001"), proof.Subject);
        Assert.True(ControllerActorIdentity.IsValid(actor));
        Assert.NotEqual(actor, ControllerActorIdentity.FromFederatedAccount(Connection.ProfileEndpoint, proof.Subject));
    }
}
