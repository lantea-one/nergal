using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
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
    private const string Cookie = "__Host-nergal-federated";

    internal static void Configure(IServiceCollection services, IConfigurationSection config, IDataProtectionProvider keys)
    {
        var adminGroups = config.GetSection("AdministratorGroups").GetChildren().Select(entry => entry.Value ?? "").ToArray();
        if (adminGroups.Length == 0)
        {
            adminGroups = config.GetSection("AllowedGroups").GetChildren().Select(entry => entry.Value ?? "").ToArray();
        }
        var auditorGroups = config.GetSection("AuditorGroups").GetChildren().Select(entry => entry.Value ?? "").ToArray();
        var policy = new FederatedAdministratorPolicy(config["Issuer"] ?? "", config["ClientId"] ?? "", config["GroupClaim"] ?? "",
            adminGroups, auditorGroups);
        if (!Uri.TryCreate(config["CallbackUri"], UriKind.Absolute, out var callback) || callback.Scheme != "https" ||
            callback.UserInfo.Length != 0 || callback.PathAndQuery != "/signin-oidc" || callback.Fragment.Length != 0)
        { throw new InvalidOperationException("A fixed direct HTTPS callback at /signin-oidc is required."); }
        var secret = config["ClientSecret"];
        if (string.IsNullOrWhiteSpace(secret) || secret.Length > 4096) { throw new InvalidOperationException("An OIDC client secret is required."); }
        var issuer = new Uri(policy.Issuer);
        services.AddSingleton(new FederatedSessions(TimeProvider.System));
        var auth = services.AddAuthentication(options => options.DefaultScheme = Browser);
        auth.AddPolicyScheme(Browser, null, options => options.ForwardDefaultSelector =
            context => context.Request.Cookies.ContainsKey(Cookie) ? Session : IdentityConstants.ApplicationScheme);
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
            cookie.Events.OnValidatePrincipal = context =>
            {
                var principal = context.Principal;
                if (!Registry(context.HttpContext).IsCurrent(principal?.FindFirstValue("sid"),
                    principal?.FindFirstValue("iss"), principal?.FindFirstValue("sub"), principal?.FindFirstValue(ClaimTypes.Role)))
                { context.RejectPrincipal(); }
                return Task.CompletedTask;
            };
            cookie.Events.OnSigningOut = async context =>
            {
                var ticket = await context.HttpContext.AuthenticateAsync(Session);
                Registry(context.HttpContext).Revoke(ticket.Principal?.FindFirstValue("sid"));
            };
            cookie.Events.OnRedirectToLogin = context => { context.Response.StatusCode = 401; return Task.CompletedTask; };
            cookie.Events.OnRedirectToAccessDenied = context => { context.Response.StatusCode = 403; return Task.CompletedTask; };
        });
        auth.AddOpenIdConnect(Protocol, options =>
        {
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
            options.MapInboundClaims = false;
            options.Scope.Clear();
            options.Scope.Add("openid");
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
                if (request.Method != HttpMethods.Post || request.QueryString.HasValue || !string.Equals(request.ContentType?.Split(';')[0].Trim(), "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) ||
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
                context.Principal = new(id);
                context.Properties!.ExpiresUtc = admin.Expires;
                context.Properties.AllowRefresh = false;
                context.Properties.IsPersistent = false;
                return Task.CompletedTask;
            };
            options.Events.OnTicketReceived = async context =>
            {
                var principal = context.Principal!;
                var role = principal.FindFirstValue(ClaimTypes.Role) ?? NergalRoles.Administrator;
                var admin = new FederatedAdministrator(principal.FindFirstValue("iss")!, principal.FindFirstValue("sub")!, context.Properties!.ExpiresUtc!.Value, role);
                await context.HttpContext.SignOutAsync(Session);
                await context.HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
                ((ClaimsIdentity)principal.Identity!).AddClaim(new("sid", Registry(context.HttpContext).Register(admin)));
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
