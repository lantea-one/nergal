using System.Globalization;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web;

internal static class FederatedLogin
{
    internal const string Protocol = "nergal.oidc";
    internal const string Session = "nergal.federated-session";
    internal const string Browser = "nergal.browser-session";
    private const string ConnectionGenerationClaim = "nergal.oidc-generation";
    private const string PolicyGenerationClaim = "nergal.oidc-mfa-generation";
    private const string MfaAssuredClaim = "nergal.oidc-mfa-assured";
    private static readonly object VerifiedProfilePayload = new();
    internal const string Cookie = "__Host-nergal-federated";
    internal const string LdapSession = "nergal.ldap-session";
    internal const string LdapCookie = "__Host-nergal-ldap";

    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    internal static void Configure(IServiceCollection services, IConfigurationSection config, IDataProtectionProvider keys)
    {
        services.AddSingleton(new OidcBootstrapConnection(config));
        services.AddScoped<OidcRequestConnection>();
        services.AddSingleton<OidcGenerationCache>();
        services.AddScoped<Microsoft.Extensions.Options.IOptionsMonitor<OpenIdConnectOptions>, OidcRequestOptions>();
        services.AddSingleton(new FederatedSessions(TimeProvider.System));
        var auth = services.AddAuthentication(options => options.DefaultScheme = Browser);
        auth.AddPolicyScheme(Browser, null, options => options.ForwardDefaultSelector =
            context => context.Request.Cookies.ContainsKey(Cookie) ? Session :
                context.Request.Cookies.ContainsKey(OAuthLogin.Cookie) ? OAuthLogin.Session :
                context.Request.Cookies.ContainsKey(LdapCookie) ? LdapSession : IdentityConstants.ApplicationScheme);
        OAuthLogin.Configure(auth, keys);
        auth.AddCookie(LdapSession, cookie =>
        {
            cookie.DataProtectionProvider = keys;
            cookie.Cookie.Name = LdapCookie;
            cookie.Cookie.Path = "/";
            cookie.Cookie.HttpOnly = true;
            cookie.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            cookie.Cookie.SameSite = SameSiteMode.Strict;
            cookie.ExpireTimeSpan = TimeSpan.FromMinutes(15);
            cookie.SlidingExpiration = false;
            cookie.Events.OnValidatePrincipal = async context =>
            {
                var accounts = context.HttpContext.RequestServices.GetRequiredService<LocalAdministratorAccounts>();
                if (context.Principal is null || !await accounts.ValidateLdapSessionAsync(context.Principal))
                {
                    context.RejectPrincipal();
                    context.Options.CookieManager.DeleteCookie(context.HttpContext, LdapCookie,
                        context.Options.Cookie.Build(context.HttpContext));
                }
            };
            cookie.Events.OnSigningOut = async context =>
            {
                var ticket = await context.HttpContext.AuthenticateAsync(LdapSession);
                if (ticket.Principal is { } principal)
                { await context.HttpContext.RequestServices.GetRequiredService<LocalAdministratorAccounts>().RevokeLdapSessionAsync(principal); }
            };
            cookie.Events.OnRedirectToLogin = BrowserResponses.LoginChallenge;
            cookie.Events.OnRedirectToAccessDenied = context => { context.Response.StatusCode = 403; return Task.CompletedTask; };
        });
        auth.AddCookie(Session, cookie =>
        {
            cookie.DataProtectionProvider = keys;
            cookie.Cookie.Name = Cookie;
            cookie.Cookie.Path = "/";
            cookie.Cookie.HttpOnly = true;
            cookie.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            cookie.Cookie.SameSite = SameSiteMode.Strict;
            cookie.ExpireTimeSpan = TimeSpan.FromMinutes(15);
            cookie.SlidingExpiration = false;
            cookie.Events.OnValidatePrincipal = async context =>
            {
                var principal = context.Principal;
                var connection = context.HttpContext.RequestServices.GetRequiredService<OidcRequestConnection>();
                if (principal is null || !connection.Enabled || principal.FindFirstValue(ConnectionGenerationClaim) != connection.Generation ||
                    principal.FindFirstValue(MfaAssuredClaim) is not ("true" or "false") ||
                    (await context.HttpContext.RequestServices.GetRequiredService<LocalAdministratorAccounts>()
                        .ReadOidcMfaGenerationAsync(principal.FindFirstValue(ClaimTypes.Role),
                            principal.FindFirstValue(MfaAssuredClaim) == "true")) is not { } policyGeneration ||
                    principal.FindFirstValue(PolicyGenerationClaim) != policyGeneration.ToString(CultureInfo.InvariantCulture) ||
                    !Registry(context.HttpContext).IsCurrent(principal.FindFirstValue("sid"),
                        principal.FindFirstValue("iss"), principal.FindFirstValue("sub"), principal.FindFirstValue(ClaimTypes.Role)))
                {
                    context.RejectPrincipal();
                    context.Options.CookieManager.DeleteCookie(context.HttpContext, Cookie, context.Options.Cookie.Build(context.HttpContext));
                }
            };
            cookie.Events.OnSigningOut = async context =>
            {
                var ticket = await context.HttpContext.AuthenticateAsync(Session);
                Registry(context.HttpContext).Revoke(ticket.Principal?.FindFirstValue("sid"));
            };
            cookie.Events.OnRedirectToLogin = BrowserResponses.LoginChallenge;
            cookie.Events.OnRedirectToAccessDenied = context => { context.Response.StatusCode = 403; return Task.CompletedTask; };
        });
        auth.AddOpenIdConnect(Protocol, _ => { });
        services.AddOptions<OpenIdConnectOptions>(Protocol).Configure<OidcRequestConnection>((options, connection) =>
        {
            var generation = connection.Generation;
            var challengeGeneration = connection.ChallengeGeneration;
            var runtime = connection.Runtime;
            var settings = runtime?.Snapshot.Settings ?? new Nergal.Core.Identity.OidcConnectionSettings(false,
                "https://disabled.invalid", "disabled", "https://disabled.invalid/signin-oidc", "groups", ["disabled"], []);
            var policy = new FederatedAdministratorPolicy(settings.Issuer, settings.ClientId, settings.GroupClaim,
                settings.AdministratorGroups, settings.AuditorGroups);
            var callback = new Uri(settings.CallbackUri);
            var issuer = new Uri(settings.Issuer);
            var secret = runtime?.ClientSecret ?? "disabled";
            options.Authority = policy.Issuer;
            options.ClientId = policy.ClientId;
            options.ClientSecret = secret;
            options.SignInScheme = Session;
            options.CallbackPath = callback.AbsolutePath;
            options.RemoteSignOutPath = PathString.Empty;
            options.SignedOutCallbackPath = PathString.Empty;
            options.ResponseType = OpenIdConnectResponseType.Code;
            options.ResponseMode = OpenIdConnectResponseMode.FormPost;
            options.UsePkce = true;
            options.RequireHttpsMetadata = true;
            options.SaveTokens = false;
            options.GetClaimsFromUserInfoEndpoint = false;
            options.MapInboundClaims = false;
            // We build the complete bounded principal from verified signed data.
            // Framework defaults run later and otherwise delete its issuer claim
            // or overlay unselected profile fields.
            options.ClaimActions.Clear();
            options.Scope.Clear();
            options.Scope.Add("openid");
            options.Scope.Add("profile");
            options.Scope.Add("email");
            options.RemoteAuthenticationTimeout = TimeSpan.FromMinutes(5);
            options.BackchannelTimeout = TimeSpan.FromSeconds(10);
            options.BackchannelHttpHandler = new IssuerBackchannel(issuer);
            options.TokenValidationParameters = new()
            {
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                IssuerValidator = (value, _, _) => value == policy.Issuer ? value : throw new SecurityTokenInvalidIssuerException(),
                ValidAudience = policy.ClientId,
                ValidateAudience = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            };
            options.Events.OnRedirectToIdentityProvider = async context =>
            {
                if (!settings.Enabled) { context.HandleResponse(); context.Response.StatusCode = 404; return; }
                context.Properties.Items[ConnectionGenerationClaim] = challengeGeneration;
                if (context.Request.PathBase.HasValue ||
                    !string.Equals(context.Request.Host.ToUriComponent(), callback.Authority, StringComparison.OrdinalIgnoreCase))
                {
                    context.HandleResponse();
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    return;
                }
                var metadata = await context.Options.ConfigurationManager!.GetConfigurationAsync(context.HttpContext.RequestAborted);
                if (metadata.Issuer != policy.Issuer || !SameOrigin(issuer, new Uri(context.ProtocolMessage.IssuerAddress)))
                { throw new InvalidOperationException("Unexpected OIDC discovery identity."); }
                context.ProtocolMessage.RedirectUri = callback.AbsoluteUri;
            };
            options.Events.OnMessageReceived = async context =>
            {
                var request = context.Request;
                if (!settings.Enabled || request.Method != HttpMethods.Post || request.QueryString.HasValue || !string.Equals(request.ContentType?.Split(';')[0].Trim(), "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(request.Host.ToUriComponent(), callback.Authority, StringComparison.OrdinalIgnoreCase) ||
                    request.PathBase.HasValue || request.Path != callback.AbsolutePath)
                { context.Fail("Invalid callback."); return; }
                var form = await request.ReadFormAsync(context.HttpContext.RequestAborted);
                if (form.Count > 16 || form.Keys.Any(key => key is "error" or "error_description" or "error_uri" or "id_token" or "access_token" or "refresh_token" or "token_type" or "expires_in") ||
                    form.Any(field => field.Value.Count != 1) || string.IsNullOrEmpty(form["code"]) ||
                    string.IsNullOrEmpty(form["state"]) || (form.ContainsKey("iss") && form["iss"] != policy.Issuer))
                { context.Fail("Invalid authorization-code response."); return; }
                // RFC 6749 section 4.1.2 permits extension fields (including
                // form submit controls). Never forward one to a protocol decision.
                foreach (var key in context.ProtocolMessage.Parameters.Keys.Where(key => key is not ("code" or "state" or "iss" or "session_state")).ToArray())
                { context.ProtocolMessage.RemoveParameter(key); }
            };
            options.Events.OnAuthorizationCodeReceived = async context =>
            {
                // Reject retired state before sending its authorization code to
                // any token endpoint selected by a newer connection generation.
                if (context.Properties is null || !context.Properties.Items.TryGetValue(ConnectionGenerationClaim, out var issuedGeneration) ||
                    issuedGeneration != challengeGeneration ||
                    !await context.HttpContext.RequestServices.GetRequiredService<OidcRequestConnection>().IsCurrentAsync(generation))
                { context.Fail("Retired federated connection."); }
            };
            options.Events.OnTokenValidated = context =>
            {
                // At this event the signature has been verified. The handler still
                // completes its protocol/nonce validation before TicketReceived.
                if (context.SecurityToken.RawPayload is not { Length: > 0 and <= 65536 } payload)
                { context.Fail("Federated login denied."); return Task.CompletedTask; }
                using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(payload), new JsonDocumentOptions { MaxDepth = 16 });
                var admin = policy.AuthorizeVerifiedClaims(document.RootElement, context.Options.TimeProvider!.GetUtcNow());
                if (admin is null) { context.Fail("Federated login denied."); return Task.CompletedTask; }
                var id = new ClaimsIdentity(Session);
                id.AddClaim(new("iss", admin.Issuer));
                id.AddClaim(new("sub", admin.Subject));
                id.AddClaim(new(ClaimTypes.NameIdentifier, WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(admin.Issuer)) + "." + WebEncoders.Base64UrlEncode(Encoding.ASCII.GetBytes(admin.Subject))));
                id.AddClaim(new(ClaimTypes.Name, admin.Subject));
                id.AddClaim(new(ClaimTypes.Role, admin.Role));
                id.AddClaim(new(ControllerActorIdentity.ActorClaimType, ControllerActorIdentity.FromFederatedAccount(admin.Issuer, admin.Subject)));
                context.HttpContext.Items[VerifiedProfilePayload] = payload;
                context.Principal = new(id);
                context.Properties!.ExpiresUtc = admin.Expires;
                context.Properties.AllowRefresh = false;
                context.Properties.IsPersistent = false;
                return Task.CompletedTask;
            };
            options.Events.OnTicketReceived = async context =>
            {
                if (!OperatingSystem.IsLinux()) { RejectTicket(context); return; }
                if (context.Properties is null || !context.Properties.Items.TryGetValue(ConnectionGenerationClaim, out var issuedGeneration) || issuedGeneration != challengeGeneration ||
                    !await context.HttpContext.RequestServices.GetRequiredService<OidcRequestConnection>().IsCurrentAsync(generation))
                { RejectTicket(context); return; }
                var principal = context.Principal!;
                var role = principal.FindFirstValue(ClaimTypes.Role);
                var issuer = principal.FindFirstValue("iss");
                var subject = principal.FindFirstValue("sub");
                if (issuer is null || issuer != policy.Issuer || string.IsNullOrWhiteSpace(subject) || !NergalRoles.IsDefined(role) ||
                    principal.FindFirstValue(ControllerActorIdentity.ActorClaimType) != ControllerActorIdentity.FromFederatedAccount(issuer, subject))
                { RejectTicket(context); return; }
                if (!context.HttpContext.Items.Remove(VerifiedProfilePayload, out var raw) || raw is not string payload)
                { RejectTicket(context); return; }

                // The protocol and nonce checks are complete. Evaluate the signed payload and
                // retain only the decision in the application principal.
                using var claims = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(payload), new JsonDocumentOptions { MaxDepth = 16 });
                var assured = settings.AssuresVerifiedMfa(claims.RootElement);
                var accounts = context.HttpContext.RequestServices.GetRequiredService<LocalAdministratorAccounts>();
                var mfaGeneration = await accounts.ReadOidcMfaGenerationAsync(role, assured);
                if (mfaGeneration is null) { RejectTicket(context); return; }
                var identity = (ClaimsIdentity)principal.Identity!;
                identity.AddClaim(new(ConnectionGenerationClaim, generation));
                identity.AddClaim(new(MfaAssuredClaim, assured ? "true" : "false"));
                identity.AddClaim(new(PolicyGenerationClaim, mfaGeneration.Value.ToString(CultureInfo.InvariantCulture)));
                var admin = new FederatedAdministrator(issuer, subject, context.Properties!.ExpiresUtc!.Value, role!);
                var sid = Registry(context.HttpContext).Register(admin);
                try
                {
                    if (!(await accounts.RefreshVerifiedOidcProfileAsync(principal, claims.RootElement)).Succeeded)
                    { Registry(context.HttpContext).Revoke(sid); RejectTicket(context); return; }
                    await context.HttpContext.SignOutAsync(Session);
                    await RetireLocalSessionAsync(context.HttpContext);
                    await context.HttpContext.SignOutAsync(LdapSession);
                    await context.HttpContext.SignOutAsync(OAuthLogin.Session);
                    OAuthLogin.RetireChallenge(context.HttpContext);
                    identity.AddClaim(new("sid", sid));
                }
                catch (AccountStoreException error) when (error.Code == "account.denied")
                { Registry(context.HttpContext).Revoke(sid); RejectTicket(context); return; }
                catch { Registry(context.HttpContext).Revoke(sid); throw; }
                // Reassert a fixed local destination after the full protocol validation;
                // neither caller return URLs nor provider fields choose navigation.
                context.ReturnUri = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>()
                    .GetValue<bool>("ControllerState:Enabled") ? "/manage" : "/session";
            };
            options.Events.OnRemoteFailure = context =>
            {
                context.HandleResponse();
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
        });
    }

    // Authenticate the local cookie explicitly, even when the browser scheme selected a different ticket.
    // The store rechecks its stamp under a write reservation and commits revocation together with its audit.
    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    internal static async Task RetireLocalSessionAsync(HttpContext context)
    {
        if (context.Request.Cookies.Count == 0) { return; }
        var scheme = IdentityConstants.ApplicationScheme;
        var cookie = context.RequestServices.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(scheme).Cookie.Name;
        if (cookie is null || !context.Request.Cookies.ContainsKey(cookie)) { return; }

        var ticket = await context.AuthenticateAsync(scheme);
        if (ticket.Principal is { } principal)
        { await context.RequestServices.GetRequiredService<LocalAdministratorAccounts>().RevokeSessionsAsync(principal); }
        await context.SignOutAsync(scheme);
    }

    private static void RejectTicket(TicketReceivedContext context)
    {
        // End the remote callback here, before the handler can issue an application cookie.
        context.HandleResponse();
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
    }

    internal static bool SameOrigin(Uri expected, Uri target) =>
        target.IsAbsoluteUri && target.Scheme == "https" && target.UserInfo.Length == 0 &&
        expected.IdnHost.Equals(target.IdnHost, StringComparison.OrdinalIgnoreCase) && expected.Port == target.Port;

    private static FederatedSessions Registry(HttpContext context) => context.RequestServices.GetRequiredService<FederatedSessions>();

    private sealed class IssuerBackchannel(Uri issuer) : DelegatingHandler(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            request.RequestUri is { } uri && SameOrigin(issuer, uri)
                ? base.SendAsync(request, cancellationToken)
                : throw new HttpRequestException("OIDC backchannel origin refused.");
    }
}
