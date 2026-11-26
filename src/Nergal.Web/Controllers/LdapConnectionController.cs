using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Controllers;

/// <summary>Current local Administrator controls for the active LDAPS connection and write-only bind password.</summary>
[SupportedOSPlatform("linux"), Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
[RequestSizeLimit(49152), RequestFormLimits(ValueCountLimit = 16, ValueLengthLimit = 2048, KeyLengthLimit = 128)]
public sealed class LdapConnectionController(LocalAdministratorAccounts accounts, IConfiguration configuration,
    IDataProtectionProvider keys, IStringLocalizer<UiStrings> L) : IdentityUiController(accounts, configuration)
{
    private bool IsLocalAdministrator => User.Identity?.AuthenticationType == IdentityConstants.ApplicationScheme &&
        User.IsInRole(NergalRoles.Administrator);

    /// <summary>Shows the active connection's saved non-secret configuration without contacting the directory.</summary>
    [HttpGet]
    public async Task<IActionResult> Index()
    {
        if (!IsLocalAdministrator) { return Forbid(); }
        return Request.Query.Count == 0 ? await PageAsync() : BadRequest();
    }

    /// <summary>Saves an explicit expected-version configuration after antiforgery and current local authority checks.</summary>
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Save()
    {
        if (!IsLocalAdministrator) { return Forbid(); }
        var form = await ReadFieldsWithOptionalSwitchAsync("enabled", "version", "serverUri", "dialIp", "userBaseDn",
            "searchBindDn", "loginAttribute", "administratorGroupDn", "auditorGroupDn", "displayNameAttribute",
            "givenNameAttribute", "familyNameAttribute", "emailAttribute", "searchPassword", "confirm");
        if (Request.Query.Count != 0 || form is null || !Version(form["version"], out var version) ||
            form["confirm"] != "replace-trust" || form.ContainsKey("enabled") && form["enabled"] != "true")
        { return BadRequest(); }

        var settings = new LdapConnectionSettings(form["enabled"] == "true", form["serverUri"].ToString(),
            form["dialIp"].ToString(), form["userBaseDn"].ToString(), form["searchBindDn"].ToString(),
            form["loginAttribute"].ToString(), form["administratorGroupDn"].ToString(), form["auditorGroupDn"].ToString(),
            new(form["displayNameAttribute"].ToString(), form["givenNameAttribute"].ToString(),
                form["familyNameAttribute"].ToString(), form["emailAttribute"].ToString()));
        var result = await Accounts.SaveLdapConnectionAsync(User, version, settings, form["searchPassword"].ToString(), keys);
        if (result.Succeeded) { return LocalRedirect("~/manage/identity/ldap"); }

        return await PageAsync(result.ErrorCodes.FirstOrDefault() switch
        {
            "provider.invalid" => L["Enter a valid LDAPS endpoint, dial IP, search settings, supported attributes and distinct role group DNs."].Value,
            "provider.secretRequired" => L["Enter a search password when creating the connection or changing its endpoint, dial IP, user base or bind DN."].Value,
            _ => Explain(result, L),
        });
    }

    private async Task<IActionResult> PageAsync(string? error = null)
    {
        if (error is not null) { Response.StatusCode = StatusCodes.Status400BadRequest; }
        return View("Index", new LdapConnectionPageModel(await Accounts.ReadLdapConnectionAsync(User), error));
    }
}

/// <summary>Saved connection settings and safe feedback. The bind password is never part of this model.</summary>
public sealed record LdapConnectionPageModel(LdapConnectionSnapshot? Connection, string? Error = null);
