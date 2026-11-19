using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Nergal.Identity;

/// <summary>Explicit application-only browser authentication for an HTTPS host with protected persistent keys.</summary>
[SupportedOSPlatform("linux")]
public static class LocalSessionServices
{
    /// <summary>Configures a host-only session cookie with absolute expiration and current account validation on every request.</summary>
    public static IServiceCollection AddLocalAdministratorSessions(this IServiceCollection services, ProtectedSessionKeyRing keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        services.AddAuthentication(IdentityConstants.ApplicationScheme).AddCookie(IdentityConstants.ApplicationScheme, cookie =>
        {
            cookie.DataProtectionProvider = keys;
            cookie.Cookie.Name = "__Host-nergal-admin";
            cookie.Cookie.Path = "/";
            cookie.Cookie.HttpOnly = true;
            cookie.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            cookie.Cookie.SameSite = SameSiteMode.Strict;
            cookie.ExpireTimeSpan = TimeSpan.FromMinutes(15);
            cookie.SlidingExpiration = false;
            cookie.Events.OnValidatePrincipal = async context =>
            {
                var accounts = context.HttpContext.RequestServices.GetRequiredService<LocalAdministratorAccounts>();
                if (context.Principal is null || !await accounts.ValidateSessionAsync(context.Principal))
                {
                    context.RejectPrincipal();
                    context.Options.CookieManager.DeleteCookie(context.HttpContext, context.Options.Cookie.Name!,
                        context.Options.Cookie.Build(context.HttpContext));
                }
            };
            cookie.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            cookie.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
        return services;
    }
}
