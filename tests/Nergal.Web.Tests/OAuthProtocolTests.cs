using System.Net;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Tests;

/// <summary>Browser correlation and backchannel tests use opaque synthetic values and no external services.</summary>
[SupportedOSPlatform("linux")]
public sealed class OAuthProtocolTests
{
    private static readonly OAuthConnectionSettings Settings = new(true, "https://oauth.example/authorize",
        "https://oauth.example/token", "https://oauth.example/me", "https://controller.example/signin-oauth",
        "test client", "read", "account", "groups", "ops", "readers", new());

    /// <summary>Only the issuing browser and one concurrent callback can consume a challenge and its original verifier.</summary>
    [Fact]
    public async Task ChallengeBindsBrowserStateVerifierAndGeneration()
    {
        var challenges = new OAuthChallenges(TimeProvider.System, new FederatedSessions(TimeProvider.System));
        var first = Assert.IsType<OAuthChallenges.Challenge>(challenges.Begin(7, null));
        var second = Assert.IsType<OAuthChallenges.Challenge>(challenges.Begin(8, null));
        Assert.NotEqual(first.State, first.Browser);
        Assert.NotEqual(first.State, first.Verifier);
        Assert.Equal(WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(first.Verifier))), first.CodeChallenge);
        Assert.Null(challenges.Take(second.Browser, first.State));
        Assert.Null(challenges.Take(first.State, first.State));
        var attempts = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ =>
            Task.Run(() => challenges.Take(first.Browser, first.State))));
        Assert.Equal(7, Assert.Single(attempts.OfType<OAuthChallenges.Challenge>()).Generation);
        Assert.Same(second, challenges.Take(second.Browser, second.State));
    }

    /// <summary>Replacement within a browser and absolute expiry each retire an outstanding challenge.</summary>
    [Fact]
    public void RestartingSignInOrReachingDeadlineRetiresPendingState()
    {
        var clock = new Clock();
        var challenges = new OAuthChallenges(clock, new FederatedSessions(clock));
        var first = Assert.IsType<OAuthChallenges.Challenge>(challenges.Begin(1, null));
        var second = Assert.IsType<OAuthChallenges.Challenge>(challenges.Begin(1, first.Browser));
        Assert.Null(challenges.Take(first.Browser, first.State));
        var displaced = Assert.IsType<OAuthChallenges.Challenge>(challenges.Begin(1, null));
        challenges.Revoke(displaced.Browser);
        Assert.Null(challenges.Take(displaced.Browser, displaced.State));
        clock.Now = second.Expires;
        Assert.Null(challenges.Take(second.Browser, second.State));
    }

    /// <summary>Supersession cancels a taken callback before it can reserve a session.</summary>
    [Fact]
    public void ReplacementCancelsTakenCallbackAndRejectsItsRegistration()
    {
        var clock = new Clock();
        var sessions = new FederatedSessions(clock);
        var challenges = new OAuthChallenges(clock, sessions);
        var older = Assert.IsType<OAuthChallenges.Challenge>(challenges.Begin(1, null));
        Assert.Same(older, challenges.Take(older.Browser, older.State));

        var newer = Assert.IsType<OAuthChallenges.Challenge>(challenges.Begin(2, older.Browser));
        Assert.Equal(older.Browser, newer.Browser);
        Assert.True(older.Cancellation.IsCancellationRequested);
        Assert.Null(challenges.RegisterSession(older, Actor(clock)));
        challenges.Abandon(older);
        Assert.Same(newer, challenges.Take(newer.Browser, newer.State));
    }

    /// <summary>A response already carrying the previous SID cannot authorize after a newer choice revokes it.</summary>
    [Fact]
    public void SupersessionRevokesRegisteredSessionEvenAfterChallengeDeadline()
    {
        var clock = new Clock();
        var sessions = new FederatedSessions(clock);
        var challenges = new OAuthChallenges(clock, sessions);
        var older = Assert.IsType<OAuthChallenges.Challenge>(challenges.Begin(1, null));
        Assert.Same(older, challenges.Take(older.Browser, older.State));
        var actor = Actor(clock);
        var sid = Assert.IsType<string>(challenges.RegisterSession(older, actor));
        Assert.True(challenges.CanIssue(older, older.Expires));
        clock.Now = older.Expires;
        Assert.NotNull(challenges.Begin(1, null)); // Expiry sweep must preserve the SID binding.
        Assert.False(challenges.CanIssue(older, older.Expires));
        Assert.True(sessions.IsCurrent(sid, actor.Issuer, actor.Subject, actor.Role));

        challenges.Revoke(older.Browser);
        Assert.True(older.Cancellation.IsCancellationRequested);
        Assert.False(sessions.IsCurrent(sid, actor.Issuer, actor.Subject, actor.Role));
    }

    /// <summary>Concurrent callback registration and logout leave no usable ticket in either lock order.</summary>
    [Fact]
    public async Task ConcurrentRegistrationAndRevocationLeaveNoActiveTicket()
    {
        var clock = new Clock();
        var sessions = new FederatedSessions(clock);
        var challenges = new OAuthChallenges(clock, sessions);
        var challenge = Assert.IsType<OAuthChallenges.Challenge>(challenges.Begin(1, null));
        Assert.Same(challenge, challenges.Take(challenge.Browser, challenge.State));
        var actor = Actor(clock);
        var registration = Task.Run(() => challenges.RegisterSession(challenge, actor), TestContext.Current.CancellationToken);
        var revocation = Task.Run(() => challenges.Revoke(challenge.Browser), TestContext.Current.CancellationToken);
        await Task.WhenAll(registration, revocation);
        Assert.False(sessions.IsCurrent(await registration, actor.Issuer, actor.Subject, actor.Role));
        Assert.True(challenge.Cancellation.IsCancellationRequested);
    }

    private static FederatedAdministrator Actor(Clock clock) =>
        new(Settings.ProfileEndpoint, "synthetic-subject", clock.Now.AddMinutes(10), NergalRoles.Auditor);

    /// <summary>The callback has one exact target, one code and one state. Browser tokens and error responses cannot complete.</summary>
    [Theory]
    [InlineData("/signin-oauth", "", true)]
    [InlineData("/signin-oauth", "&session_state=ignored", true)]
    [InlineData("/signin-oauth", "&code=another", false)]
    [InlineData("/signin-oauth", "&STATE=another", false)]
    [InlineData("/signin-oauth", "&error=access_denied", false)]
    [InlineData("/signin-oauth", "&access_token=ignored", false)]
    [InlineData("/signin-oauth", "&iss=https://other.example", false)]
    [InlineData("/Signin-oauth", "", false)]
    [InlineData("/signin-%6Fauth", "", false)]
    public void CallbackAcceptsOnlyUnambiguousCodeAtRegisteredPath(string rawPath, string extra, bool accepted)
    {
        var context = new DefaultHttpContext();
        var request = context.Request;
        request.Method = HttpMethods.Get;
        request.Scheme = "https";
        request.Host = new HostString("controller.example");
        request.Path = "/signin-oauth";
        var state = new string('s', 43);
        request.QueryString = new QueryString("?state=" + state + "&code=synthetic-code" + extra);
        context.Features.Get<IHttpRequestFeature>()!.RawTarget = rawPath + request.QueryString;
        Assert.Equal(accepted, OAuthLogin.TryReadCallback(request, out _, out _));
        Assert.True(OAuthLogin.MatchesCallbackOrigin(request, Settings.CallbackUri));
        request.Host = new HostString("another.example");
        Assert.False(OAuthLogin.MatchesCallbackOrigin(request, Settings.CallbackUri));
    }

    /// <summary>Only the token from confidential server redemption reaches the configured authenticated current-user endpoint.</summary>
    [Fact]
    public async Task ExchangeUsesFixedTargetsAndReturnsOnlyProfileAndDeadline()
    {
        var calls = 0;
        using var exchange = new OAuthBackchannel(new HttpClient(new Handler(async request =>
        {
            calls++;
            if (calls == 1)
            {
                Assert.Equal(HttpMethod.Post, request.Method);
                Assert.Equal(Settings.TokenEndpoint, request.RequestUri!.AbsoluteUri);
                Assert.Equal("Basic", request.Headers.Authorization!.Scheme);
                Assert.Equal("test+client:s%3Ae", Encoding.ASCII.GetString(Convert.FromBase64String(request.Headers.Authorization.Parameter!)),
                    ignoreCase: true);
                var form = QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync());
                Assert.Equal(4, form.Count);
                Assert.Equal("authorization_code", form["grant_type"].ToString());
                Assert.Equal("synthetic-code", form["code"].ToString());
                Assert.Equal("synthetic-verifier", form["code_verifier"].ToString());
                Assert.Equal(Settings.CallbackUri, form["redirect_uri"].ToString());
                return Json("""{"token_type":"Bearer","access_token":"fixture","expires_in":60}""");
            }
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal(Settings.ProfileEndpoint, request.RequestUri!.AbsoluteUri);
            Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
            Assert.Equal("fixture", request.Headers.Authorization.Parameter);
            return Json("""{"account":"stable","groups":["readers"]}""");
        })));
        var before = DateTimeOffset.UtcNow;
        var result = await exchange.ReadProfileAsync(Settings, "s:e", "synthetic-code", "synthetic-verifier", TestContext.Current.CancellationToken);
        Assert.NotNull(result);
        Assert.Equal(2, calls);
        Assert.Equal("stable", result.Value.Profile.GetProperty("account").GetString());
        Assert.InRange(result.Value.Expires, before.AddSeconds(60), DateTimeOffset.UtcNow.AddSeconds(60));
    }

    /// <summary>Malformed, duplicated, oversized or redirected upstream input cannot become a profile proof.</summary>
    [Theory]
    [InlineData("duplicate-token")]
    [InlineData("invalid-bearer")]
    [InlineData("expired")]
    [InlineData("redirect-token")]
    [InlineData("redirect-profile")]
    [InlineData("duplicate-profile")]
    [InlineData("oversized")]
    [InlineData("wrong-origin")]
    public async Task BadExchangeYieldsNoProof(string failure)
    {
        var settings = failure == "wrong-origin" ? Settings with { ProfileEndpoint = "https://other.example/me" } : Settings;
        var calls = 0;
        using var exchange = new OAuthBackchannel(new HttpClient(new Handler(request =>
        {
            calls++;
            var tokenEndpoint = request.Method == HttpMethod.Post;
            var response = failure switch
            {
                "duplicate-token" => Json("""{"token_type":"Bearer","access_token":"a","access_token":"b"}"""),
                "invalid-bearer" => Json("""{"token_type":"Bearer","access_token":"a b"}"""),
                "expired" => Json("""{"token_type":"Bearer","access_token":"a","expires_in":0}"""),
                "redirect-token" => new HttpResponseMessage(HttpStatusCode.TemporaryRedirect),
                "redirect-profile" when !tokenEndpoint => new HttpResponseMessage(HttpStatusCode.Found),
                "duplicate-profile" when !tokenEndpoint => Json("""{"account":"one","account":"two"}"""),
                "oversized" when !tokenEndpoint => Json("{\"padding\":\"" + new string('x', 65536) + "\"}"),
                _ => Json("""{"token_type":"Bearer","access_token":"fixture"}"""),
            };
            return Task.FromResult(response);
        })));
        Assert.Null(await exchange.ReadProfileAsync(settings, "synthetic", "code", "verifier", TestContext.Current.CancellationToken));
        Assert.Equal(failure switch
        {
            "wrong-origin" => 0,
            "redirect-profile" or "duplicate-profile" or "oversized" => 2,
            _ => 1,
        }, calls);
    }

    private static HttpResponseMessage Json(string json) => new(HttpStatusCode.OK)
    { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private sealed class Handler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request);
    }

    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now { get; set; } = DateTimeOffset.UnixEpoch;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
