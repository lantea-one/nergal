using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.Versioning;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web;

[SupportedOSPlatform("linux")]
internal sealed class OAuthLogin(LocalAdministratorAccounts accounts, IDataProtectionProvider keys, OAuthChallenges challenges,
    OAuthBackchannel backchannel)
{
    internal const string Session = "nergal.oauth-session";
    internal const string Cookie = "__Host-nergal-oauth";
    private const string CorrelationCookie = "__Host-nergal-oauth-correlation";

    internal static void Configure(AuthenticationBuilder auth, IDataProtectionProvider keys)
    {
        auth.Services.AddScoped<OAuthLogin>();
        var sessions = new FederatedSessions(TimeProvider.System);
        auth.Services.AddKeyedSingleton(Session, sessions);
        auth.Services.AddSingleton(new OAuthChallenges(TimeProvider.System, sessions));
        auth.Services.AddSingleton(_ => new OAuthBackchannel(new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            MaxResponseHeadersLength = 16,
            MaxResponseDrainSize = 0,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        })));
        auth.AddCookie(Session, options =>
        {
            options.DataProtectionProvider = keys;
            options.Cookie.Name = Cookie;
            options.Cookie.Path = "/";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.ExpireTimeSpan = TimeSpan.FromMinutes(15);
            options.SlidingExpiration = false;
            options.Events.OnValidatePrincipal = async context =>
            {
                var principal = context.Principal;
                var registry = context.HttpContext.RequestServices.GetRequiredKeyedService<FederatedSessions>(Session);
                if (principal?.Identity?.AuthenticationType == Session &&
                    NergalRoles.IsDefined(principal.FindFirstValue(ClaimTypes.Role)) &&
                    registry.IsCurrent(principal.FindFirstValue("sid"), principal.FindFirstValue("iss"),
                        principal.FindFirstValue("sub"), principal.FindFirstValue(ClaimTypes.Role)) &&
                    await context.HttpContext.RequestServices.GetRequiredService<LocalAdministratorAccounts>()
                        .ValidateOAuthSessionAsync(principal) &&
                    registry.IsCurrent(principal.FindFirstValue("sid"), principal.FindFirstValue("iss"),
                        principal.FindFirstValue("sub"), principal.FindFirstValue(ClaimTypes.Role))) { return; }
                registry.Revoke(principal?.FindFirstValue("sid"));
                context.RejectPrincipal();
                options.CookieManager.DeleteCookie(context.HttpContext, Cookie, options.Cookie.Build(context.HttpContext));
            };
            options.Events.OnSigningOut = async context =>
            {
                var ticket = await context.HttpContext.AuthenticateAsync(Session);
                context.HttpContext.RequestServices.GetRequiredKeyedService<FederatedSessions>(Session)
                    .Revoke(ticket.Principal?.FindFirstValue("sid"));
            };
            options.Events.OnRedirectToLogin = BrowserResponses.LoginChallenge;
            options.Events.OnRedirectToAccessDenied = context => { context.Response.StatusCode = 403; return Task.CompletedTask; };
        });
    }

    internal async Task<string?> StartAsync(HttpContext context, long generation)
    {
        var runtime = await ReadRuntimeAsync();
        if (runtime?.Snapshot.Settings.Enabled != true || runtime.Snapshot.Version != generation) { return null; }
        var settings = runtime.Snapshot.Settings;
        if (!MatchesCallbackOrigin(context.Request, settings.CallbackUri) || !settings.IsValid ||
            await accounts.ReadOAuthSignInGenerationAsync() != generation) { return null; }

        var challenge = challenges.Begin(generation, context.Request.Cookies[CorrelationCookie]);
        if (challenge is null) { return null; }
        // Strict application cookies may be absent on the cross-site callback. Retire them on this same-site POST.
        try { await RetirePresentedSessionsAsync(context); }
        catch { challenges.Abandon(challenge); throw; }
        if (context.Request.Cookies.ContainsKey("__Host-nergal-mfa"))
        {
            context.Response.Cookies.Delete("__Host-nergal-mfa", new CookieOptions
            { Path = "/", HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict });
        }
        if (challenge.Cancellation.IsCancellationRequested) { return null; }
        var cookie = CorrelationOptions();
        // A concurrent login must still be able to retire a SID after its callback has written a response.
        // Retain the opaque browser handle through the longest possible session.
        cookie.Expires = challenge.Expires.AddMinutes(15);
        context.Response.Cookies.Append(CorrelationCookie, challenge.Browser, cookie);
        var fields = new Dictionary<string, string?>
        {
            ["client_id"] = settings.ClientId,
            ["redirect_uri"] = settings.CallbackUri,
            ["response_type"] = "code",
            ["state"] = challenge.State,
            ["code_challenge_method"] = "S256",
            ["code_challenge"] = challenge.CodeChallenge,
        };
        if (settings.Scope.Length != 0) { fields.Add("scope", settings.Scope); }
        return QueryHelpers.AddQueryString(settings.AuthorizationEndpoint, fields);
    }

    internal async Task<bool> CompleteAsync(HttpContext context)
    {
        var request = context.Request;
        if (!TryReadCallback(request, out var state, out var code)) { return false; }
        var challenge = challenges.Take(request.Cookies[CorrelationCookie], state);
        if (challenge is null) { return false; }
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, challenge.Cancellation);
        var remaining = challenge.Expires - DateTimeOffset.UtcNow;
        lifetime.CancelAfter(remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero);
        var signedIn = false;
        try
        {
            signedIn = await CompleteTakenChallengeAsync(context, challenge, code, lifetime.Token);
            return signedIn;
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { return false; }
        finally { if (!signedIn) { challenges.Abandon(challenge); } }
    }

    private async Task<bool> CompleteTakenChallengeAsync(HttpContext context, OAuthChallenges.Challenge challenge,
        string code, CancellationToken cancellation)
    {
        var runtime = await ReadRuntimeAsync();
        if (runtime?.Snapshot.Settings.Enabled != true || runtime.Snapshot.Version != challenge.Generation ||
            !MatchesCallbackOrigin(context.Request, runtime.Snapshot.Settings.CallbackUri) ||
            !runtime.Snapshot.Settings.IsValid ||
            await accounts.ReadOAuthSignInGenerationAsync() != challenge.Generation ||
            cancellation.IsCancellationRequested || challenge.Expires <= DateTimeOffset.UtcNow) { return false; }

        var settings = runtime.Snapshot.Settings;
        var proof = await backchannel.ReadProfileAsync(settings, runtime.ClientSecret, code, challenge.Verifier, cancellation);
        if (proof is null || await accounts.ReadOAuthSignInGenerationAsync() != challenge.Generation) { return false; }
        var deadline = proof.Value.Expires < challenge.Expires ? proof.Value.Expires : challenge.Expires;
        if (cancellation.IsCancellationRequested || deadline <= DateTimeOffset.UtcNow) { return false; }

        // Reserve the SID under the browser-slot lock before committing the audit. A newer choice can
        // then revoke that SID even if the HTTP response carrying it has not reached the browser.
        var actor = settings.ReadProfile(proof.Value.Profile, challenge.Generation, DateTimeOffset.UtcNow);
        if (actor is null || challenges.RegisterSession(challenge,
            new(settings.ProfileEndpoint, actor.Subject, proof.Value.Expires, actor.Role)) is not { } sid ||
            cancellation.IsCancellationRequested) { return false; }

        var principal = await accounts.CompleteOAuthSignInAsync(challenge.Generation, proof.Value.Profile, deadline, cancellation);
        if (principal?.Identity is not ClaimsIdentity identity || identity.AuthenticationType != Session ||
            principal.FindFirstValue("iss") != settings.ProfileEndpoint || principal.FindFirstValue("sub") != actor.Subject ||
            principal.FindFirstValue(ClaimTypes.Role) != actor.Role ||
            principal.FindFirstValue("nergal.oauth-generation") != challenge.Generation.ToString(CultureInfo.InvariantCulture) ||
            !await accounts.ValidateOAuthSessionAsync(principal) || cancellation.IsCancellationRequested ||
            !challenges.CanIssue(challenge, deadline)) { return false; }

        identity.AddClaim(new("sid", sid));
        await context.SignInAsync(Session, principal, new AuthenticationProperties
        { IsPersistent = false, AllowRefresh = false, ExpiresUtc = proof.Value.Expires });
        return !cancellation.IsCancellationRequested && challenges.CanIssue(challenge, deadline);
    }

    private async Task<OAuthConnectionRuntime?> ReadRuntimeAsync()
    {
        try { return await accounts.ReadOAuthRuntimeAsync(keys); }
        catch (AccountStoreException error) when (error.Code is "account.corrupt" or "provider.secretUnavailable")
        { return null; }
    }

    // A later authentication choice cancels the pending flow even if the browser has no application ticket yet.
    internal static void RetireChallenge(HttpContext context)
    {
        if (context.Request.Cookies[CorrelationCookie] is not { } browser) { return; }
        context.RequestServices.GetRequiredService<OAuthChallenges>().Revoke(browser);
        context.Response.Cookies.Delete(CorrelationCookie, CorrelationOptions());
    }

    private static async Task RetirePresentedSessionsAsync(HttpContext context)
    {
        await FederatedLogin.RetireLocalSessionAsync(context);
        if (context.Request.Cookies.ContainsKey(FederatedLogin.Cookie)) { await context.SignOutAsync(FederatedLogin.Session); }
        if (context.Request.Cookies.ContainsKey(FederatedLogin.LdapCookie)) { await context.SignOutAsync(FederatedLogin.LdapSession); }
        if (context.Request.Cookies.ContainsKey(Cookie)) { await context.SignOutAsync(Session); }
    }

    internal static bool MatchesCallbackOrigin(HttpRequest request, string callback) =>
        request.IsHttps && !request.PathBase.HasValue &&
        string.Equals("https://" + request.Host.ToUriComponent() + "/signin-oauth", callback, StringComparison.Ordinal);

    internal static bool TryReadCallback(HttpRequest request, out string state, out string code)
    {
        state = code = "";
        var rawTarget = request.HttpContext.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (!HttpMethods.IsGet(request.Method) || !request.IsHttps || request.PathBase.HasValue ||
            request.Path.Value != "/signin-oauth" || request.ContentLength > 0 || request.Headers.ContainsKey("Transfer-Encoding") ||
            (rawTarget is { Length: > 0 } && !rawTarget.StartsWith("/signin-oauth?", StringComparison.Ordinal)) ||
            request.QueryString.Value is not { Length: > 0 and <= 8192 } || request.Query.Count > 16) { return false; }

        foreach (var field in request.Query)
        {
            if (field.Value.Count != 1) { return false; }
            switch (field.Key.ToLowerInvariant())
            {
                case "state" when field.Key == "state": state = field.Value.ToString(); break;
                case "code" when field.Key == "code": code = field.Value.ToString(); break;
                // This connection has no registered RFC 9207 issuer. Never guess one from the profile URL.
                case "iss" or "error" or "error_description" or "error_uri" or "access_token" or
                    "refresh_token" or "id_token" or "token_type" or "expires_in" or "response":
                    return false;
            }
        }
        return state.Length == 43 && code.Length is > 0 and <= 4096 && code.All(c => c is >= '!' and <= '~');
    }

    private static CookieOptions CorrelationOptions() => new()
    { Path = "/", Secure = true, HttpOnly = true, SameSite = SameSiteMode.Lax, IsEssential = true };
}

// The browser handle outlives state consumption. A single lock orders supersession against SID registration.
internal sealed class OAuthChallenges(TimeProvider clock, FederatedSessions sessions)
{
    private readonly Dictionary<string, Challenge> slots = new(StringComparer.Ordinal);
    private readonly object gate = new();

    internal sealed class Challenge(long generation, DateTimeOffset expires, string? browser)
    {
        private readonly CancellationTokenSource cancellation = new();
        internal long Generation { get; } = generation;
        internal DateTimeOffset Expires { get; } = expires;
        internal string Browser { get; } = browser ?? RandomValue();
        internal string State { get; } = RandomValue();
        internal string Verifier { get; } = RandomValue();
        internal string CodeChallenge => WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(Verifier)));
        internal CancellationToken Cancellation => cancellation.Token;
        internal bool Taken { get; set; }
        internal string? Sid { get; set; }
        internal DateTimeOffset? SessionExpires { get; set; }

        // Cancellation state changes synchronously. Run token callbacks outside the browser-slot lock.
        internal void Cancel() => _ = cancellation.CancelAsync();
        private static string RandomValue() => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
    }

    internal Challenge? Begin(long generation, string? previousBrowser)
    {
        lock (gate)
        {
            var now = clock.GetUtcNow();
            // Preserve the known handle across successive OAuth choices. Requests already holding
            // that handle must still be able to cancel the replacement.
            var browser = previousBrowser is not null && slots.ContainsKey(previousBrowser) ? previousBrowser : null;
            if (browser is not null) { RevokeSlot(browser); }
            foreach (var item in slots.Where(item => (item.Value.SessionExpires ?? item.Value.Expires) <= now).ToArray())
            { RevokeSlot(item.Key); }
            if (slots.Count >= 1024) { return null; }
            var challenge = new Challenge(generation, now.AddMinutes(5), browser);
            slots.Add(challenge.Browser, challenge);
            return challenge;
        }
    }

    internal void Revoke(string browser)
    {
        lock (gate) { RevokeSlot(browser); }
    }

    internal void Abandon(Challenge challenge)
    {
        lock (gate)
        {
            if (slots.TryGetValue(challenge.Browser, out var current) && current == challenge)
            { RevokeSlot(challenge.Browser); }
        }
    }

    private void RevokeSlot(string browser)
    {
        if (!slots.Remove(browser, out var challenge)) { return; }
        challenge.Cancel();
        sessions.Revoke(challenge.Sid);
    }

    internal Challenge? Take(string? browser, string state)
    {
        lock (gate)
        {
            if (browser?.Length != 43 || !slots.TryGetValue(browser, out var challenge) || challenge.State != state ||
                challenge.Taken || challenge.Expires <= clock.GetUtcNow()) { return null; }
            challenge.Taken = true;
            return challenge;
        }
    }

    internal string? RegisterSession(Challenge challenge, FederatedAdministrator actor)
    {
        lock (gate)
        {
            if (!IsCurrent(challenge) || challenge.Sid is not null || challenge.Expires <= clock.GetUtcNow()) { return null; }
            try { challenge.Sid = sessions.Register(actor); }
            catch (InvalidOperationException) { return null; }
            challenge.SessionExpires = actor.Expires;
            return challenge.Sid;
        }
    }

    internal bool CanIssue(Challenge challenge, DateTimeOffset deadline)
    {
        lock (gate) { return IsCurrent(challenge) && challenge.Sid is not null && deadline > clock.GetUtcNow(); }
    }

    private bool IsCurrent(Challenge challenge) =>
        challenge.Taken && slots.TryGetValue(challenge.Browser, out var current) && current == challenge;
}

internal sealed class OAuthBackchannel(HttpClient client) : IDisposable
{
    private const int MaxBytes = 65536;

    internal async Task<(JsonElement Profile, DateTimeOffset Expires)?> ReadProfileAsync(OAuthConnectionSettings settings,
        string secret, string code, string verifier, CancellationToken cancellation)
    {
        if (!settings.Enabled || !settings.IsValid) { return null; }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            using var redeem = new HttpRequestMessage(HttpMethod.Post, settings.TokenEndpoint);
            redeem.Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = settings.CallbackUri,
                ["code_verifier"] = verifier,
            });
            // OAuth client_secret_basic encodes each UTF-8 form component before joining them.
            var credentials = WebUtility.UrlEncode(settings.ClientId) + ":" + WebUtility.UrlEncode(secret);
            redeem.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials)));
            var issued = DateTimeOffset.UtcNow;
            using var tokens = await ReadObjectAsync(redeem, deadline.Token);
            if (tokens is null || !TryReadToken(tokens.RootElement, out var bearer, out var seconds)) { return null; }
            var expires = issued.AddSeconds(seconds);
            using var profile = new HttpRequestMessage(HttpMethod.Get, settings.ProfileEndpoint);
            profile.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            using var document = await ReadObjectAsync(profile, deadline.Token);
            return document is null ? null : (document.RootElement.Clone(), expires);
        }
        catch (Exception error) when (error is HttpRequestException or IOException or JsonException or
            OperationCanceledException or InvalidOperationException)
        { return null; }
    }

    private async Task<JsonDocument?> ReadObjectAsync(HttpRequestMessage request, CancellationToken cancellation)
    {
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation);
        if (response.StatusCode != HttpStatusCode.OK ||
            !string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase) ||
            response.Content.Headers.ContentLength > MaxBytes) { return null; }
        await response.Content.LoadIntoBufferAsync(MaxBytes, cancellation);
        var document = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(cancellation),
            new JsonDocumentOptions { MaxDepth = 16, AllowDuplicateProperties = false });
        if (document.RootElement.ValueKind == JsonValueKind.Object && !document.RootElement.TryGetProperty("error", out _))
        { return document; }
        document.Dispose();
        return null;
    }

    internal static bool TryReadToken(JsonElement json, out string token, out int seconds)
    {
        token = "";
        seconds = 900;
        if (!json.TryGetProperty("token_type", out var type) || type.ValueKind != JsonValueKind.String ||
            !string.Equals(type.GetString(), "Bearer", StringComparison.OrdinalIgnoreCase) ||
            !json.TryGetProperty("access_token", out var access) || access.ValueKind != JsonValueKind.String ||
            access.GetString() is not { Length: > 0 and <= 8192 } value) { return false; }
        var body = value.AsSpan().TrimEnd('=');
        if (body.IsEmpty || body.IndexOfAnyExcept("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/") >= 0)
        { return false; }
        if (json.TryGetProperty("expires_in", out var expiry))
        {
            if (expiry.ValueKind != JsonValueKind.Number || !expiry.TryGetInt64(out var lifetime) || lifetime <= 0) { return false; }
            seconds = (int)Math.Min(seconds, lifetime);
        }
        token = value;
        return true;
    }

    public void Dispose() => client.Dispose();
}
