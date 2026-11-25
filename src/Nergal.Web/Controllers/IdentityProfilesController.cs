using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Controllers;

/// <summary>Administrator-only metadata configuration; no request activates a provider or changes authentication trust.</summary>
[SupportedOSPlatform("linux")]
[Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
public sealed class IdentityProfilesController(LocalAdministratorAccounts accounts, IConfiguration configuration) : IdentityUiController(accounts, configuration)
{
    /// <summary>Shows versioned exact-issuer profile mappings without querying an external provider.</summary>
    [HttpGet]
    public async Task<IActionResult> Index() => Request.Query.Count == 0 ? await PageAsync() : BadRequest();

    /// <summary>Saves a bounded versioned mapping after CSRF and current-authority checks.</summary>
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Save()
    {
        var form = await ReadFieldsWithOptionalSwitchAsync("enabled", "issuer", "version", "displayNameClaim", "givenNameClaim", "familyNameClaim", "emailClaim");
        if (form is null || !Version(form["version"], out var version) ||
            form.ContainsKey("enabled") && form["enabled"] != "true") { return BadRequest(); }
        var mapping = new OidcProfileMapping(form["issuer"].ToString(), version, form["enabled"] == "true",
            form["displayNameClaim"].ToString(), form["givenNameClaim"].ToString(), form["familyNameClaim"].ToString(), form["emailClaim"].ToString(), null);
        var result = await Accounts.SaveOidcProfileMappingAsync(User, mapping);
        return result.Succeeded ? LocalRedirect("~/manage/identity/profiles") : await PageAsync(Explain(result));
    }

    private async Task<IActionResult> PageAsync(string? error = null)
    {
        if (error is not null) { Response.StatusCode = 400; }
        return View("Index", new IdentityProfileMappingsModel(await Accounts.ReadOidcProfileMappingsAsync(User), error));
    }
}
