using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Controllers;

/// <summary>Local Administrator settings for the SMTP relay used by email MFA.</summary>
[SupportedOSPlatform("linux"), Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
[RequestFormLimits(ValueCountLimit = 9, ValueLengthLimit = 6144, KeyLengthLimit = 128)]
public sealed class EmailDeliveryController(LocalAdministratorAccounts accounts, IConfiguration configuration,
    IDataProtectionProvider keys, IStringLocalizer<UiStrings> L) : IdentityUiController(accounts, configuration)
{
    private bool IsLocalAdministrator => User.Identity?.AuthenticationType == IdentityConstants.ApplicationScheme &&
        User.IsInRole(NergalRoles.Administrator);

    /// <summary>Reads the current configuration without opening the SMTP credential.</summary>
    [HttpGet]
    public async Task<IActionResult> Index()
    {
        if (!IsLocalAdministrator) { return Forbid(); }
        return Request.Query.Count == 0 ? await PageAsync() : BadRequest();
    }

    /// <summary>Saves an explicit relay generation. Saving does not send mail.</summary>
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Save()
    {
        if (!IsLocalAdministrator) { return Forbid(); }
        var form = await ReadFieldsWithOptionalSwitchAsync("enabled", "version", "host", "port",
            "fromAddress", "userName", "password");
        if (form is null || Request.Query.Count != 0 || !Version(form["version"], out var version) ||
            !int.TryParse(form["port"], NumberStyles.None, CultureInfo.InvariantCulture, out var port) ||
            form.ContainsKey("enabled") && form["enabled"] != "true") { return BadRequest(); }

        var settings = new EmailDeliverySettings(form["enabled"] == "true", form["host"].ToString(), port,
            form["fromAddress"].ToString(), form["userName"].ToString());
        var result = await Accounts.SaveEmailDeliveryAsync(User, version, settings, form["password"].ToString(), keys);
        if (result.Succeeded) { return LocalRedirect("~/manage/identity/email-delivery"); }
        return await PageAsync(result.ErrorCodes.FirstOrDefault() switch
        {
            "mfa.deliveryPasswordRequired" => L["Enter the SMTP password for the new relay or username."].Value,
            "mfa.deliveryInvalid" => L["Enter a valid server, port and sender address. Leave the username blank for a relay that does not require credentials."].Value,
            "mfa.stale" => L["The relay settings changed. Review the current settings and submit again."].Value,
            _ => Explain(result, L)
        });
    }

    private async Task<IActionResult> PageAsync(string? error = null)
    {
        if (error is not null) { Response.StatusCode = StatusCodes.Status400BadRequest; }
        return View("Index", new EmailDeliveryPageModel(await Accounts.ReadEmailDeliveryAsync(User), error));
    }
}

/// <summary>Saved SMTP details and safe feedback for the local Administrator.</summary>
public sealed record EmailDeliveryPageModel(EmailDeliverySnapshot? Connection, string? Error);
