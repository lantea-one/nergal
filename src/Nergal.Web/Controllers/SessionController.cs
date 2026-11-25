using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Nergal.Identity;

namespace Nergal.Web.Controllers;

/// <summary>Local session endpoints mapped only by the explicitly enabled authentication host.</summary>
[SupportedOSPlatform("linux")]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class SessionController(LocalAdministratorAccounts accounts, IConfiguration configuration) : Controller
{
    private string SignedInDestination => configuration.GetValue<bool>("ControllerState:Enabled") ? "~/manage" : "~/session";

    /// <summary>Shows a blank, antiforgery-protected credential form.</summary>
    [HttpGet, AllowAnonymous]
    public IActionResult Login() => User.Identity?.IsAuthenticated == true ? LocalRedirect(SignedInDestination) : View();

    /// <summary>Verifies bounded form credentials. Every failure uses the same response without reflecting submitted values.</summary>
    [HttpPost, AllowAnonymous, ValidateAntiForgeryToken, EnableRateLimiting("local-login")]
    [RequestSizeLimit(8192)]
    [RequestFormLimits(ValueCountLimit = 3, KeyLengthLimit = 128, ValueLengthLimit = 2048)]
    public async Task<IActionResult> Authenticate()
    {
        if (!string.Equals(Request.ContentType?.Split(';')[0].Trim(), "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        { return BadRequest(); }
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        var names = form["username"];
        var passwords = form["password"];
        if (names.Count != 1 || passwords.Count != 1 || form.Count != 3) { return BadRequest(); }
        if (!await accounts.SignInAsync(names[0]!, passwords[0]!, HttpContext.RequestAborted))
        { Response.StatusCode = StatusCodes.Status401Unauthorized; return View("Login", false); }
        if (HttpContext.RequestServices.GetService<FederatedSessions>() is not null && Request.Cookies.ContainsKey(FederatedLogin.Cookie))
        { await HttpContext.SignOutAsync(FederatedLogin.Session); }
        return LocalRedirect(SignedInDestination);
    }

    /// <summary>Begins a correlated authorization-code exchange for an explicitly configured external issuer.</summary>
    [HttpPost, AllowAnonymous, ValidateAntiForgeryToken, EnableRateLimiting("local-login"), RequestSizeLimit(8192)]
    public IActionResult Federated() => Challenge(new AuthenticationProperties
    { RedirectUri = configuration.GetValue<bool>("ControllerState:Enabled") ? "/manage" : "/session" }, FederatedLogin.Protocol);

    /// <summary>Displays the authenticated session page without accessing agent state.</summary>
    [HttpGet, Authorize]
    public IActionResult Index() => View();

    /// <summary>Revokes the administrator's sessions and removes the browser cookie.</summary>
    [HttpPost, Authorize, ValidateAntiForgeryToken, RequestSizeLimit(8192)]
    public async Task<IActionResult> Logout()
    {
        if (User.Identity?.AuthenticationType == FederatedLogin.Session)
        { await HttpContext.SignOutAsync(FederatedLogin.Session); }
        else
        {
            await accounts.RevokeSessionsAsync(User);
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
        }
        return LocalRedirect("~/login");
    }
}
