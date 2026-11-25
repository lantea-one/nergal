using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Nergal.Identity;

namespace Nergal.Web;

[SupportedOSPlatform("linux")]
internal static class LocalSessionHost
{
    internal static ProtectedSessionKeyRing Configure(IServiceCollection services, IConfigurationSection config)
    {
        var accounts = new LocalAccountOptions(config["AccountDirectory"] ?? "");
        var keys = new ProtectedSessionKeyOptions(config["KeyDirectory"] ?? "");
        if (Path.TrimEndingDirectorySeparator(accounts.Directory) == Path.TrimEndingDirectorySeparator(keys.Directory))
        { throw new InvalidOperationException("Account and key directories must be distinct."); }
        var retained = config.GetSection("RetainedCertificateFiles").GetChildren().ToArray();
        if (retained.Length > 7) { throw new InvalidOperationException("At most seven retained certificates are supported."); }
        using var current = PrivateWrappingCertificate.Load(config["CertificateFile"] ?? "");
        var history = new List<X509Certificate2>();
        ProtectedSessionKeyRing ring;
        try
        {
            foreach (var entry in retained) { history.Add(PrivateWrappingCertificate.Load(entry.Value ?? "")); }
            ring = ProtectedSessionKeyRing.Open(keys, current, history);
        }
        finally { foreach (var certificate in history) { certificate.Dispose(); } }

        services.Replace(ServiceDescriptor.Singleton<IDataProtectionProvider>(ring));
        services.AddLocalAdministratorAccounts(accounts).AddLocalAdministratorSessions(ring);
        services.Configure<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>(
            Microsoft.AspNetCore.Identity.IdentityConstants.ApplicationScheme,
            options => options.Events.OnRedirectToLogin = BrowserResponses.LoginChallenge);
        services.AddScoped<UserPresentationFilter>();
        services.Configure<Microsoft.AspNetCore.Mvc.MvcOptions>(options => options.Filters.AddService<UserPresentationFilter>());
        services.AddAuthorization(options => options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());
        services.AddAntiforgery(options =>
        {
            options.Cookie.Name = "__Host-nergal-csrf";
            options.Cookie.Path = "/";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Strict;
        });
        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddFixedWindowLimiter("local-login", limiter =>
            {
                limiter.PermitLimit = 10;
                limiter.Window = TimeSpan.FromMinutes(1);
                limiter.QueueLimit = 0;
            });
            options.AddFixedWindowLimiter("local-password", limiter =>
            {
                limiter.PermitLimit = 10;
                limiter.Window = TimeSpan.FromMinutes(1);
                limiter.QueueLimit = 0;
            });
        });
        return ring;
    }

    internal static async Task EnableAsync(WebApplication app)
    {
        using (var scope = app.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<LocalAdministratorAccounts>().RequireProvisionedAsync();
            await scope.ServiceProvider.GetRequiredService<OidcRequestConnection>().LoadAsync();
            // Exercise first-key persistence and historical decryption before listening.
            var protector = scope.ServiceProvider.GetRequiredService<IDataProtectionProvider>().CreateProtector("startup-readiness");
            if (protector.Unprotect(protector.Protect("ready")) != "ready")
            { throw new InvalidOperationException("Session key readiness failed."); }
        }
        app.Use(async (context, next) =>
        {
            if (!context.Request.IsHttps || context.Features.Get<ITlsConnectionFeature>() is null)
            { context.Response.StatusCode = StatusCodes.Status400BadRequest; return; }
            context.Response.Headers.CacheControl = "no-store";
            var maxBytes = HttpMethods.IsPost(context.Request.Method) &&
                           context.Request.Path.Equals("/manage/sources/import", StringComparison.OrdinalIgnoreCase)
                ? 600_000L
                : context.Request.Path.StartsWithSegments("/manage/objects", StringComparison.OrdinalIgnoreCase)
                    ? 24_576L
                : context.Request.Path.StartsWithSegments("/manage/policies", StringComparison.OrdinalIgnoreCase) ||
                           context.Request.Path.StartsWithSegments("/controller/policies", StringComparison.OrdinalIgnoreCase)
                ? 524_288L
                : context.Request.Path.StartsWithSegments("/manage/settings", StringComparison.OrdinalIgnoreCase) ||
                           context.Request.Path.StartsWithSegments("/manage/identity/connection", StringComparison.OrdinalIgnoreCase)
                    ? 32_768L
                    : 8192L;
            if (context.Request.ContentLength > maxBytes) { context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge; return; }
            if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } limit)
            { limit.MaxRequestBodySize = maxBytes; }
            await next();
        });
        app.UseRouting();
        app.Use(async (context, next) =>
        {
            var connection = context.RequestServices.GetRequiredService<OidcRequestConnection>();
            await connection.LoadAsync();
            // Reject disabled challenges before the framework can perform discovery.
            if (!connection.Enabled && context.Request.Path == "/login/oidc")
            { context.Response.StatusCode = 404; return; }
            await next();
        });
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseRateLimiter();
        app.MapControllerRoute("local-login", "login", new { controller = "Session", action = "Login" });
        app.MapControllerRoute("local-authenticate", "login", new { controller = "Session", action = "Authenticate" });
        app.MapControllerRoute("local-session", "session", new { controller = "Session", action = "Index" });
        app.MapControllerRoute("local-logout", "logout", new { controller = "Session", action = "Logout" });
        app.MapControllerRoute("local-users", "manage/users", new { controller = "Users", action = "Index" });
        foreach (var action in new[] { "Create", "Update", "Revoke" })
        { app.MapControllerRoute("local-users-" + action, "manage/users/" + action.ToLowerInvariant(), new { controller = "Users", action }); }
        app.MapControllerRoute("identity-connection", "manage/identity/connection", new { controller = "IdentityConnection", action = "Index" });
        app.MapControllerRoute("identity-connection-save", "manage/identity/connection/save", new { controller = "IdentityConnection", action = "Save" });
        app.MapControllerRoute("profile-mappings", "manage/identity/profiles", new { controller = "IdentityProfiles", action = "Index" });
        app.MapControllerRoute("profile-mappings-save", "manage/identity/profiles/save", new { controller = "IdentityProfiles", action = "Save" });
        app.MapControllerRoute("user-profile", "profile", new { controller = "Profile", action = "Index" });
        foreach (var action in new[] { "Save", "Password" })
        { app.MapControllerRoute("user-profile-" + action, "profile/" + action.ToLowerInvariant(), new { controller = "Profile", action }); }
    }
}
