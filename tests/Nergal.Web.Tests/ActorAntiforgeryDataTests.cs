using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Nergal.Core.Identity;

namespace Nergal.Web.Tests;

/// <summary>Exercises the real framework antiforgery token binding across provider identities.</summary>
public sealed class ActorAntiforgeryDataTests
{
    /// <summary>Equal upstream subject values cannot share a form token across OIDC or OAuth identity namespaces.</summary>
    [Fact]
    public async Task EqualSubjectsDoNotShareFormIdentity()
    {
        const string subject = "fixture-subject";
        const string issuer = "https://identity.example.test";
        var oidc = ControllerActorIdentity.FromFederatedAccount(issuer, subject);
        var oauth = ControllerActorIdentity.FromOAuthAccount(Guid.Parse("00000000-0000-0000-0000-000000000001"), subject);
        var replacement = ControllerActorIdentity.FromOAuthAccount(Guid.Parse("00000000-0000-0000-0000-000000000002"), subject);

        var collection = new ServiceCollection();
        collection.AddLogging();
        collection.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
        collection.AddSingleton<IAntiforgeryAdditionalDataProvider, ActorAntiforgeryData>();
        collection.AddAntiforgery(options =>
        {
            options.Cookie.Name = "fixture-antiforgery";
            options.HeaderName = "X-Fixture-Antiforgery";
        });
        await using var services = collection.BuildServiceProvider();
        var antiforgery = services.GetRequiredService<IAntiforgery>();

        DefaultHttpContext Context(string actor) => new()
        {
            RequestServices = services,
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new("sub", subject),
                new(ControllerActorIdentity.ActorClaimType, actor),
            ], "synthetic-authentication")),
        };

        async Task AssertBinding(string origin, string other)
        {
            var tokens = antiforgery.GetTokens(Context(origin));
            var request = Context(origin);
            request.Request.Method = HttpMethods.Post;
            request.Request.Headers.Cookie = "fixture-antiforgery=" + tokens.CookieToken;
            request.Request.Headers["X-Fixture-Antiforgery"] = tokens.RequestToken;
            Assert.True(await antiforgery.IsRequestValidAsync(request));

            var displaced = Context(other);
            displaced.Request.Method = HttpMethods.Post;
            displaced.Request.Headers.Cookie = request.Request.Headers.Cookie;
            displaced.Request.Headers["X-Fixture-Antiforgery"] = tokens.RequestToken;
            Assert.False(await antiforgery.IsRequestValidAsync(displaced));
        }

        await AssertBinding(oidc, oauth);
        await AssertBinding(oauth, replacement);
    }
}
