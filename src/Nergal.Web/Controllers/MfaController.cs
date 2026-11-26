using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Localization;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Controllers;

/// <summary>Authenticator enrollment for local or LDAP identities and shared policy for local Administrators.</summary>
[SupportedOSPlatform("linux"), Authorize(Policy = ControllerAuthorizationPolicies.Reader)]
public sealed class MfaController(LocalAdministratorAccounts accounts, IConfiguration configuration, IDataProtectionProvider keys, IStringLocalizer<UiStrings> L)
    : IdentityUiController(accounts, configuration)
{
    private bool CanEnroll => User.Identity?.AuthenticationType == IdentityConstants.ApplicationScheme ||
        User.Identity?.AuthenticationType == FederatedLogin.LdapSession;
    private bool CanManagePolicy => User.Identity?.AuthenticationType == IdentityConstants.ApplicationScheme &&
        User.IsInRole(NergalRoles.Administrator);

    /// <summary>Shows whether the current identity has an authenticator. Reading status never generates a seed.</summary>
    [HttpGet]
    public async Task<IActionResult> Index()
    {
        if (!CanEnroll) { return Forbid(); }
        return Request.Query.Count == 0 ? await EnrollmentPageAsync() : BadRequest();
    }

    /// <summary>Generates a pending setup key only after an authorized antiforgery-protected request.</summary>
    [HttpPost, ValidateAntiForgeryToken, EnableRateLimiting("mfa-enrollment")]
    public async Task<IActionResult> Begin()
    {
        if (!CanEnroll) { return Forbid(); }
        if (Request.Query.Count != 0 || await ReadFieldsAsync() is null) { return BadRequest(); }

        var enrollment = await Accounts.BeginTotpEnrollmentAsync(User, keys);
        return enrollment is null
            ? await EnrollmentPageAsync(L["Authenticator setup could not start. Review your current enrollment status."].Value)
            : View("Index", new MfaEnrollmentPageModel(false, enrollment));
    }

    /// <summary>Activates a pending authenticator after the identity store verifies its current code.</summary>
    [HttpPost, ValidateAntiForgeryToken, EnableRateLimiting("mfa-enrollment")]
    public async Task<IActionResult> Confirm()
    {
        if (!CanEnroll) { return Forbid(); }
        var form = await ReadFieldsAsync("enrollmentId", "code");
        if (Request.Query.Count != 0 || form is null) { return BadRequest(); }
        var id = form["enrollmentId"].ToString();
        var code = form["code"].ToString();
        if (id.Length == 0 || code.Length != 6 || !code.All(char.IsAsciiDigit)) { return BadRequest(); }

        var result = await Accounts.ConfirmTotpEnrollmentAsync(User, id, code, keys);
        return result.Succeeded ? LocalRedirect("~/login")
            : await EnrollmentPageAsync(L["Authenticator setup could not be confirmed. Check your device time and start setup again."].Value);
    }

    /// <summary>Shows the current versioned local and LDAP MFA requirements.</summary>
    [HttpGet, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    public async Task<IActionResult> Policy()
    {
        if (!CanManagePolicy) { return Forbid(); }
        return Request.Query.Count == 0 ? await PolicyPageAsync() : BadRequest();
    }

    /// <summary>Saves one explicit policy option with an expected version and a current local Administrator recheck.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    public async Task<IActionResult> SavePolicy()
    {
        if (!CanManagePolicy) { return Forbid(); }
        var form = await ReadFieldsAsync("version", "requirement");
        if (Request.Query.Count != 0 || form is null || !Version(form["version"], out var version))
        { return BadRequest(); }
        MfaRequirement? requirement = form["requirement"].ToString() switch
        {
            "Optional" => MfaRequirement.Optional,
            "Administrators" => MfaRequirement.Administrators,
            "All" => MfaRequirement.All,
            _ => null,
        };
        if (requirement is null) { return BadRequest(); }

        var result = await Accounts.SaveMfaPolicyAsync(User, version, requirement.Value, keys);
        if (result.Succeeded) { return LocalRedirect("~/manage/identity/mfa"); }
        return await PolicyPageAsync(result.ErrorCodes.FirstOrDefault() switch
        {
            "mfa.stale" => L["The policy changed. Review the current requirement and submit again."].Value,
            "account.lastAdministrator" => L["Enroll an authenticator for at least one enabled local Administrator before requiring MFA."].Value,
            _ => Explain(result, L),
        });
    }

    private async Task<IActionResult> EnrollmentPageAsync(string? error = null)
    {
        if (error is not null) { Response.StatusCode = StatusCodes.Status400BadRequest; }
        return View("Index", new MfaEnrollmentPageModel(await Accounts.HasTotpAsync(User), Error: error));
    }

    private async Task<IActionResult> PolicyPageAsync(string? error = null)
    {
        if (error is not null) { Response.StatusCode = StatusCodes.Status400BadRequest; }
        return View("Policy", new MfaPolicyPageModel(await Accounts.ReadMfaPolicyAsync(User), error));
    }
}

/// <summary>Current enrollment status with an optional newly generated setup key for the initiating response.</summary>
public sealed record MfaEnrollmentPageModel(bool Enrolled, TotpEnrollment? Setup = null, string? Error = null);

/// <summary>Versioned policy and safe feedback for the local Administrator.</summary>
public sealed record MfaPolicyPageModel(MfaPolicySnapshot Policy, string? Error = null);
