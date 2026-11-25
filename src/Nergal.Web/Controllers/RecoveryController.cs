using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Controllers;

/// <summary>Issues actor-scoped recovery authorizations and stages replacement authenticators without issuing application tickets.</summary>
[SupportedOSPlatform("linux")]
public sealed class RecoveryController(LocalAdministratorAccounts accounts, IConfiguration configuration, IDataProtectionProvider keys)
    : IdentityUiController(accounts, configuration)
{
    private const string RecoveryCookie = "__Host-nergal-recovery";
    private bool LocalAdmin => User.Identity?.AuthenticationType == IdentityConstants.ApplicationScheme &&
        User.IsInRole(NergalRoles.Administrator);

    /// <summary>Shows local accounts and the immutable identifier format for directory recipients.</summary>
    [HttpGet, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    public async Task<IActionResult> Issue()
    {
        if (!LocalAdmin) { return Forbid(); }
        if (Request.Query.Count != 0) { return BadRequest(); }
        return await IssuePageAsync();
    }

    /// <summary>Issues a single authorization for out-of-band handoff to the identified recipient.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), EnableRateLimiting("mfa-enrollment")]
    public async Task<IActionResult> AuthorizeRecovery()
    {
        if (!LocalAdmin) { return Forbid(); }
        var form = await ReadFieldsAsync("actorId", "version");
        if (Request.Query.Count != 0 || form is null || !Version(form["version"], out var version)) { return BadRequest(); }
        var issued = await Accounts.IssueRecoveryAsync(User, form["actorId"].ToString(), version);
        if (issued is null)
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return await IssuePageAsync(failed: true);
        }
        return View("Issued", issued);
    }

    private async Task<IActionResult> IssuePageAsync(bool failed = false)
    {
        var policy = await Accounts.ReadMfaPolicyAsync(User);
        var users = await Accounts.ListUsersAsync(User);
        Guid? directoryId = null;
        try
        {
            if (await Accounts.ReadLdapConnectionAsync(User) is { Settings.Enabled: true } connection)
            { directoryId = connection.DirectoryId; }
        }
        catch (AccountStoreException error) when (error.Code == "account.corrupt") { }
        return View("Issue", new RecoveryIssueModel(policy.Version, users, directoryId, failed));
    }

    /// <summary>Displays independent local and generation-bound LDAP credential forms.</summary>
    [HttpGet, AllowAnonymous]
    public async Task<IActionResult> Index()
    {
        if (Request.Query.Count != 0) { return BadRequest(); }
        long? generation;
        try { generation = await Accounts.ReadLdapSignInGenerationAsync(); }
        catch (AccountStoreException) { generation = null; }
        return View(new RecoveryLoginModel(generation));
    }

    /// <summary>Exchanges a local authorization and current password for confirmation-only setup.</summary>
    [HttpPost, AllowAnonymous, ValidateAntiForgeryToken, EnableRateLimiting("local-login")]
    [RequestFormLimits(ValueCountLimit = 4, KeyLengthLimit = 128, ValueLengthLimit = 2048)]
    public async Task<IActionResult> Local()
    {
        var form = await ReadFieldsAsync("authorization", "username", "password");
        if (Request.Query.Count != 0 || form is null) { return BadRequest(); }
        return SetupPage(await Accounts.BeginLocalRecoveryAsync(form["authorization"].ToString(),
            form["username"].ToString(), form["password"].ToString(), keys, HttpContext.RequestAborted));
    }

    /// <summary>Exchanges an LDAP authorization and new immutable-identity bind proof for confirmation-only setup.</summary>
    [HttpPost, AllowAnonymous, ValidateAntiForgeryToken, EnableRateLimiting("ldap-login"), RequestSizeLimit(16384)]
    [RequestFormLimits(ValueCountLimit = 5, KeyLengthLimit = 128, ValueLengthLimit = 12288)]
    public async Task<IActionResult> Ldap()
    {
        var form = await ReadFieldsAsync("authorization", "username", "password", "version");
        if (Request.Query.Count != 0 || form is null || !Version(form["version"], out var version) || version == 0)
        { return BadRequest(); }
        return SetupPage(await Accounts.BeginLdapRecoveryAsync(form["authorization"].ToString(), version,
            form["username"].ToString(), form["password"].ToString(), keys, HttpContext.RequestAborted));
    }

    private IActionResult SetupPage(RecoverySetup? setup)
    {
        if (setup is null)
        {
            Response.StatusCode = StatusCodes.Status401Unauthorized;
            return View("Denied");
        }
        var options = CookieOptions();
        options.Expires = setup.ExpiresUtc;
        Response.Cookies.Append(RecoveryCookie, setup.Continuation, options);
        return View("Confirm", new RecoveryConfirmModel(setup.ManualKey));
    }

    /// <summary>Proves possession of the new authenticator. The recipient then signs in using ordinary MFA.</summary>
    [HttpPost, AllowAnonymous, ValidateAntiForgeryToken, EnableRateLimiting("mfa-enrollment")]
    public async Task<IActionResult> Confirm()
    {
        var form = await ReadFieldsAsync("code");
        if (Request.Query.Count != 0 || form is null) { return BadRequest(); }
        if (!await Accounts.ConfirmRecoveryAsync(Request.Cookies[RecoveryCookie] ?? "", form["code"].ToString(),
            keys, HttpContext.RequestAborted))
        {
            Response.StatusCode = StatusCodes.Status401Unauthorized;
            return View("Confirm", new RecoveryConfirmModel(null, Failed: true));
        }
        Response.Cookies.Delete(RecoveryCookie, CookieOptions());
        return LocalRedirect("~/login");
    }

    private static CookieOptions CookieOptions() => new()
    { Path = "/", Secure = true, HttpOnly = true, SameSite = SameSiteMode.Strict, IsEssential = true };
}

/// <summary>Authorized recipient choices and current policy generation, without delivery metadata.</summary>
public sealed record RecoveryIssueModel(long PolicyVersion, IReadOnlyList<LocalUserSnapshot> Users, Guid? DirectoryId, bool Failed);

/// <summary>Enabled LDAP generation for one explicitly selected directory bind.</summary>
public sealed record RecoveryLoginModel(long? DirectoryGeneration);

/// <summary>Shows the manual key once on fresh setup. Subsequent verification attempts show only a code prompt.</summary>
public sealed record RecoveryConfirmModel(string? ManualKey, bool Failed = false)
{
    /// <summary>Suppresses the setup key from diagnostic output.</summary>
    public override string ToString() => nameof(RecoveryConfirmModel);
}
