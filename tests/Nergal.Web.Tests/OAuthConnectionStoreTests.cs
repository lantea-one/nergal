using System.Runtime.Versioning;
using System.Security.Claims;
using System.Text.Json;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Tests;

/// <summary>Tests versioned OAuth trust and profile persistence in the protected store.</summary>
[SupportedOSPlatform("linux")]
public sealed class OAuthConnectionStoreTests
{
    private static readonly DateTimeOffset Deadline = new(2026, 6, 1, 0, 5, 0, TimeSpan.Zero);
    private const string Secret = "synthetic OAuth credential";
    private static readonly OAuthConnectionSettings Settings = new(true,
        "https://provider.example.test/authorize", "https://provider.example.test/token", "https://provider.example.test/me",
        "https://controller.example.test/signin-oauth", "fixture-client", "profile groups", "id", "groups",
        "admins", "auditors", new("name", "", "", "email"));

    /// <summary>Generation retirement preserves independent user overrides until provider identity itself changes.</summary>
    [Fact]
    public async Task ReplacingProfileMappingRetiresTicketsWithoutLinkingAnotherProvider()
    {
        await using var fixture = await RecoveryFixture.Create();
        var admin = await fixture.Admin();
        using var response = JsonDocument.Parse("""{"id":"remote-1","groups":["auditors"],"name":"Fixture Profile","email":"remote@example.test"}""");

        async Task<ClaimsPrincipal> SignIn(long version) => Assert.IsType<ClaimsPrincipal>(
            await fixture.Run(accounts => accounts.CompleteOAuthSignInAsync(version, response.RootElement, Deadline, TestContext.Current.CancellationToken)));
        Task<LocalProvisionResult> Save(long version, OAuthConnectionSettings settings, string secret = "")
            => fixture.Run(accounts => accounts.SaveOAuthConnectionAsync(admin, version, settings, secret, fixture.Keys));

        Assert.True((await Save(0, Settings, Secret)).Succeeded);
        var original = await SignIn(1);
        var profile = await fixture.Run(accounts => accounts.ReadProfileAsync(original));
        Assert.Equal(new ProfileMetadata("Fixture Profile", Email: "remote@example.test"), profile.Effective);
        Assert.True((await fixture.Run(accounts => accounts.SaveProfileAsync(original, 0, new("My override")))).Succeeded);
        var mapped = Settings with { Fields = new(Email: "email") };
        Assert.True((await Save(1, mapped)).Succeeded);
        Assert.False(await fixture.Run(accounts => accounts.ValidateOAuthSessionAsync(original)));
        Assert.Null(await fixture.Run(accounts => accounts.CompleteOAuthSignInAsync(1, response.RootElement, Deadline, TestContext.Current.CancellationToken)));
        var refreshed = await SignIn(2);
        profile = await fixture.Run(accounts => accounts.ReadProfileAsync(refreshed));
        Assert.Equal(new ProfileMetadata("My override", Email: "remote@example.test"), profile.Effective);

        var changed = mapped with { ClientId = "new-client" };
        Assert.Equal(["provider.secretRequired"], (await Save(2, changed)).ErrorCodes);
        Assert.True((await Save(2, changed, Secret)).Succeeded);
        var replacement = await SignIn(3);
        profile = await fixture.Run(accounts => accounts.ReadProfileAsync(replacement));
        Assert.NotEqual(original.FindFirstValue(ControllerActorIdentity.ActorClaimType), profile.ActorId);
        Assert.Equal("", profile.DisplayName);
        Assert.Equal("remote@example.test", profile.Effective.Email);
    }

    /// <summary>A stored rollback denies stale trust while an independent local Administrator remains valid.</summary>
    [Fact]
    public async Task PartialRestoreCannotReactivateOlderTrust()
    {
        await using var fixture = await RecoveryFixture.Create();
        var admin = await fixture.Admin();
        Assert.True((await fixture.Run(accounts => accounts.SaveOAuthConnectionAsync(admin, 0, Settings, Secret, fixture.Keys))).Succeeded);
        using var response = JsonDocument.Parse("""{"id":"remote-1","groups":["admins"]}""");
        var expired = Deadline.AddMinutes(-5);
        Assert.Null(await fixture.Run(accounts => accounts.CompleteOAuthSignInAsync(1, response.RootElement,
            expired, TestContext.Current.CancellationToken)));
        Assert.DoesNotContain(await fixture.Run(accounts => accounts.ReadIdentityAuditAsync(admin)), entry => entry.Action == "oauth.signedIn");
        var retired = Assert.IsType<ClaimsPrincipal>(await fixture.Run(accounts => accounts.CompleteOAuthSignInAsync(1, response.RootElement, Deadline, TestContext.Current.CancellationToken)));
        Assert.True((await fixture.Run(accounts => accounts.SaveOAuthConnectionAsync(admin, 1, Settings with { Enabled = false }, "", fixture.Keys))).Succeeded);
        await fixture.Sql("""UPDATE OAuthConnection SET Version = 1""");
        Assert.False(await fixture.Run(accounts => accounts.ValidateOAuthSessionAsync(retired)));
        Assert.Null(await fixture.Run(accounts => accounts.ReadOAuthSignInGenerationAsync()));
        Assert.True(await fixture.Run(accounts => accounts.ValidateSessionAsync(admin)));
    }
}
