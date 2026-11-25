using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Nergal.Web.Controllers;

/// <summary>Browser entry points for the optional, generation-bound OAuth authorization code connection.</summary>
[AllowAnonymous, ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
[SupportedOSPlatform("linux")]
public sealed class OAuthSignInController : Controller
{
    /// <summary>Starts sign-in only for the connection version presented in the protected form.</summary>
    [HttpPost, ValidateAntiForgeryToken, EnableRateLimiting("local-login")]
    [RequestSizeLimit(8192), RequestFormLimits(ValueCountLimit = 2, KeyLengthLimit = 128, ValueLengthLimit = 2048)]
    public async Task<IActionResult> Start()
    {
        Response.Headers["Referrer-Policy"] = "no-referrer";
        if (HttpContext.RequestServices.GetService<OAuthLogin>() is not { } login) { return NotFound(); }
        if (!Request.IsHttps || Request.QueryString.HasValue || !string.Equals(Request.ContentType?.Split(';')[0].Trim(),
            "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) { return BadRequest(); }
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (form.Count != 2 || !form.All(p => p.Value.Count == 1 && p.Key is "version" or "__RequestVerificationToken") ||
            !long.TryParse(form["version"], NumberStyles.None, CultureInfo.InvariantCulture, out var generation) ||
            generation <= 0) { return BadRequest(); }
        var location = await login.StartAsync(HttpContext, generation);
        return location is null ? Unauthorized() : Redirect(location);
    }

    /// <summary>Consumes the correlated browser response once and navigates to a fixed local destination.</summary>
    [HttpGet]
    public async Task<IActionResult> Complete()
    {
        Response.Headers["Referrer-Policy"] = "no-referrer";
        if (HttpContext.RequestServices.GetService<OAuthLogin>() is not { } login) { return NotFound(); }
        if (!await login.CompleteAsync(HttpContext)) { return Unauthorized(); }
        var configuration = HttpContext.RequestServices.GetRequiredService<IConfiguration>();
        return LocalRedirect(configuration.GetValue<bool>("ControllerState:Enabled") ? "~/manage" : "~/session");
    }
}
