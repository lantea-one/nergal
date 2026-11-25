using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Controllers;

/// <summary>Local-Administrator OIDC connection configuration. Secrets are accepted once and never reflected.</summary>
[SupportedOSPlatform("linux"), Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
[RequestSizeLimit(32768), RequestFormLimits(ValueCountLimit = 12, ValueLengthLimit = 16384, KeyLengthLimit = 128)]
public sealed class IdentityConnectionController(LocalAdministratorAccounts accounts, IConfiguration configuration,
    IDataProtectionProvider keys) : IdentityUiController(accounts, configuration)
{
    /// <summary>Shows saved credential-free connection status. No provider network request is made.</summary>
    [HttpGet]
    public async Task<IActionResult> Index() => Request.Query.Count == 0 ? await PageAsync() : BadRequest();

    /// <summary>Saves a strict expected-version proposal; explicit confirmation retires older federated trust.</summary>
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Save()
    {
        var fields = await ReadFieldsWithOptionalSwitchAsync("enabled", "version", "issuer", "clientId", "callbackUri", "groupClaim",
            "administratorGroups", "auditorGroups", "clientSecret", "confirm");
        if (fields is null || !Version(fields["version"], out var version) || fields["confirm"] != "replace-trust" ||
            fields.ContainsKey("enabled") && fields["enabled"] != "true") { return BadRequest(); }
        static string[] Groups(string value) => value.Length == 0 ? [] : value.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        var settings = new OidcConnectionSettings(fields["enabled"] == "true", fields["issuer"].ToString(), fields["clientId"].ToString(),
            fields["callbackUri"].ToString(), fields["groupClaim"].ToString(), Groups(fields["administratorGroups"].ToString()), Groups(fields["auditorGroups"].ToString()));
        var result = await Accounts.SaveOidcConnectionAsync(User, version, settings, fields["clientSecret"].ToString(), keys);
        return result.Succeeded ? LocalRedirect("~/manage/identity/connection") : await PageAsync(Explain(result));
    }

    private async Task<IActionResult> PageAsync(string? error = null)
    {
        if (error is not null) { Response.StatusCode = 400; }
        return View("Index", new OidcConnectionPageModel(await Accounts.ReadOidcConnectionAsync(User), error));
    }
}
