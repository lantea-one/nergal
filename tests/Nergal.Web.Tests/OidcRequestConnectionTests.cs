using System.Runtime.Versioning;
using Microsoft.Extensions.Configuration;
using Nergal.Core.Identity;

namespace Nergal.Web.Tests;

/// <summary>Checks the boundary between restart-scoped bootstrap challenges and database-managed trust.</summary>
[SupportedOSPlatform("linux")]
public sealed class OidcRequestConnectionTests
{
    /// <summary>Restart retires outstanding bootstrap challenges while unchanged managed trust keeps its generation.</summary>
    [Fact]
    public async Task OnlyBootstrapChallengesAreScopedToHostStart()
    {
        await using var fixture = await RecoveryFixture.Create();
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Oidc:Enabled"] = "true",
            ["Oidc:Issuer"] = "https://issuer.example.test",
            ["Oidc:ClientId"] = "fixture",
            ["Oidc:ClientSecret"] = "synthetic-bootstrap",
            ["Oidc:CallbackUri"] = "https://controller.example.test/signin-oidc",
            ["Oidc:GroupClaim"] = "groups",
            ["Oidc:AdministratorGroups:0"] = "administrators",
        }).Build().GetSection("Oidc");
        var first = new OidcBootstrapConnection(config);
        var second = new OidcBootstrapConnection(config);

        async Task<string> Challenge(OidcBootstrapConnection start) => await fixture.Run(async accounts =>
        {
            var request = new OidcRequestConnection(start, accounts, fixture.Keys);
            await request.LoadAsync();
            Assert.True(request.Enabled);
            Assert.True(await request.IsCurrentAsync(request.Generation));
            return request.ChallengeGeneration;
        });

        var original = await Challenge(first);
        Assert.Equal(original, await Challenge(first));
        Assert.NotEqual(original, await Challenge(second));
        var admin = await fixture.Admin();
        var settings = new OidcConnectionSettings(true, "https://managed.example.test", "managed",
            "https://controller.example.test/signin-oidc", "groups", ["administrators"], []);
        Assert.True((await fixture.Run(a => a.SaveOidcConnectionAsync(admin, 0, settings, "synthetic-managed", fixture.Keys))).Succeeded);
        Assert.Equal("1", await Challenge(first));
        Assert.Equal("1", await Challenge(second));

        // Both startup loading and in-flight revalidation must treat an unreadable managed secret as disabled.
        await fixture.Sql("UPDATE OidcConnection SET ProtectedSecret='unreadable'");
        await fixture.Run(async accounts =>
        {
            var request = new OidcRequestConnection(second, accounts, fixture.Keys);
            await request.LoadAsync();
            Assert.False(request.Enabled);
            Assert.False(await request.IsCurrentAsync("1"));
            Assert.False(await request.IsCurrentAsync("0"));
            return true;
        });
    }
}
