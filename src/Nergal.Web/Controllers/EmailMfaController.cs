using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Controllers;

/// <summary>Allows a signed-in local or LDAP actor to verify an explicit email delivery address.</summary>
[SupportedOSPlatform("linux"), Authorize(Policy = ControllerAuthorizationPolicies.Reader)]
public sealed class EmailMfaController(LocalAdministratorAccounts accounts, IConfiguration configuration,
    IDataProtectionProvider keys, IMfaEmailSender sender) : IdentityUiController(accounts, configuration)
{
    private bool CanEnroll => User.Identity?.AuthenticationType == IdentityConstants.ApplicationScheme ||
        User.Identity?.AuthenticationType == FederatedLogin.LdapSession;

    /// <summary>Shows current enrollment status without sending email or returning the delivery address.</summary>
    [HttpGet]
    public async Task<IActionResult> Index()
    {
        if (!CanEnroll) { return Forbid(); }
        return Request.Query.Count == 0 ? await PageAsync() : BadRequest();
    }

    /// <summary>Requests one verification code for the supplied mailbox after strict form and antiforgery validation.</summary>
    [HttpPost, ValidateAntiForgeryToken, EnableRateLimiting("mfa-enrollment")]
    public async Task<IActionResult> Begin()
    {
        if (!CanEnroll) { return Forbid(); }
        if (Request.Query.Count != 0) { return BadRequest(); }
        var form = await ReadFieldsAsync("address");
        if (form is null || !EmailDeliverySettings.IsMailbox(form["address"].ToString())) { return BadRequest(); }

        var enrollment = await Accounts.BeginEmailMfaEnrollmentAsync(User, form["address"].ToString(), keys, sender, HttpContext.RequestAborted);
        return enrollment is null
            ? await PageAsync("Email setup could not start. Check that delivery is available and try again later.")
            : View("Index", new EmailMfaEnrollmentPageModel(new(false, true), enrollment));
    }

    /// <summary>Activates the address only after the stored verification code is accepted.</summary>
    [HttpPost, ValidateAntiForgeryToken, EnableRateLimiting("mfa-enrollment")]
    public async Task<IActionResult> Confirm()
    {
        if (!CanEnroll) { return Forbid(); }
        if (Request.Query.Count != 0) { return BadRequest(); }
        var form = await ReadFieldsAsync("enrollmentId", "code");
        if (form is null) { return BadRequest(); }
        var id = form["enrollmentId"].ToString();
        var code = form["code"].ToString();
        if (!Guid.TryParseExact(id, "N", out _) || code.Length != 6 || !code.All(char.IsAsciiDigit)) { return BadRequest(); }

        var result = await Accounts.ConfirmEmailMfaEnrollmentAsync(User, id, code, keys, HttpContext.RequestAborted);
        return result.Succeeded
            ? LocalRedirect("~/login")
            : await PageAsync(result.ErrorCodes.Contains("account.lastAdministrator")
                ? "Keep a local Administrator who can sign in without email delivery before verifying this address."
                : "Email setup could not be confirmed. Check the code or start setup again.", new EmailMfaEnrollment(id));
    }

    private async Task<IActionResult> PageAsync(string? error = null, EmailMfaEnrollment? enrollment = null)
    {
        if (error is not null) { Response.StatusCode = StatusCodes.Status400BadRequest; }
        var status = await Accounts.ReadEmailMfaEnrollmentAsync(User, HttpContext.RequestAborted);
        return View("Index", new EmailMfaEnrollmentPageModel(status, status.CanStart ? enrollment : null, error));
    }
}

/// <summary>Current factor status with the initiating browser's optional enrollment identifier.</summary>
public sealed record EmailMfaEnrollmentPageModel(EmailMfaEnrollmentStatus Status, EmailMfaEnrollment? Enrollment = null, string? Error = null);
