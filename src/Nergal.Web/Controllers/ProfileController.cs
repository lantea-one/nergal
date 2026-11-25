using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Controllers;

/// <summary>Current user's metadata and password controls; profile data never grants a role or links identities.</summary>
[SupportedOSPlatform("linux")]
[Authorize(Policy = ControllerAuthorizationPolicies.Reader)]
public sealed class ProfileController(LocalAdministratorAccounts accounts, IConfiguration configuration) : IdentityUiController(accounts, configuration)
{
    /// <summary>Displays the authenticated user's profile and local credential controls when applicable.</summary>
    [HttpGet]
    public async Task<IActionResult> Index() => Request.Query.Count == 0 ? await PageAsync() : BadRequest();

    /// <summary>Saves an expected-version local metadata override for the current identity only.</summary>
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Save()
    {
        var form = await ReadFieldsAsync("version", "displayName", "givenName", "familyName", "email");
        if (form is null || !Version(form["version"], out var version)) { return BadRequest(); }
        var proposed = new ProfileMetadata(form["displayName"].ToString(), form["givenName"].ToString(), form["familyName"].ToString(), form["email"].ToString());
        var result = await Accounts.SaveProfileAsync(User, version, proposed);
        return result.Succeeded ? LocalRedirect("~/profile") : await PageAsync(Explain(result), proposed);
    }

    /// <summary>Changes the current local password after current-password verification, then clears the revoked browser ticket.</summary>
    [HttpPost, ValidateAntiForgeryToken, EnableRateLimiting("local-password")]
    public async Task<IActionResult> Password()
    {
        var form = await ReadFieldsAsync("version", "currentPassword", "newPassword");
        if (form is null || !Version(form["version"], out var version)) { return BadRequest(); }
        var result = await Accounts.ChangeOwnPasswordAsync(User, version, form["currentPassword"].ToString(), form["newPassword"].ToString());
        if (!result.Succeeded) { return await PageAsync(Explain(result)); }
        await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
        return LocalRedirect("~/login");
    }

    private async Task<IActionResult> PageAsync(string? error = null, ProfileMetadata? proposed = null)
    {
        if (error is not null) { Response.StatusCode = 400; }
        return View("Index", new ProfilePageModel(await Accounts.ReadProfileAsync(User), error, proposed));
    }
}
