using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Nergal.Web.Controllers;

/// <summary>Changes the current browser's allowlisted presentation language.</summary>
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class LanguageController : Controller
{
    /// <summary>Saves a valid language preference and returns to a local page without replaying a form.</summary>
    [AllowAnonymous, HttpPost("/language"), ValidateAntiForgeryToken, RequestSizeLimit(8192)]
    public async Task<IActionResult> Select()
    {
        if (!Request.HasFormContentType) { return BadRequest(); }
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        var language = form["culture"];
        var returnPaths = form["returnPath"];
        if (language.Count != 1 || UiLocalization.FindCulture(language[0]) is not { } culture || returnPaths.Count > 1)
        {
            return BadRequest();
        }

        // Never copy the query or fragment of a page carrying a transient form or authentication state.
        var returnPath = returnPaths.Count == 1 ? returnPaths[0] : null;
        var pathBase = Request.PathBase;
        var destination = returnPath is { Length: <= 2048 } && returnPath.StartsWith('/') &&
            !returnPath.Contains('?') && !returnPath.Contains('#') && Url.IsLocalUrl(returnPath) &&
            (!pathBase.HasValue || new PathString(returnPath).StartsWithSegments(pathBase)) ? returnPath : "~/";

        Response.Cookies.Append(UiLocalization.CookieName, culture.Name, new CookieOptions
        {
            HttpOnly = true,
            Secure = Request.IsHttps,
            SameSite = SameSiteMode.Lax,
            Path = pathBase.HasValue ? pathBase.ToUriComponent() : "/",
            MaxAge = TimeSpan.FromDays(180),
        });
        return LocalRedirect(destination);
    }
}
