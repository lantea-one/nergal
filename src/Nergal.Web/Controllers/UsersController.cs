using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Controllers;

/// <summary>Administrator-only local accounts and identity audit. No route creates Linux users or grants agent authority.</summary>
[SupportedOSPlatform("linux")]
[Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
public sealed class UsersController(LocalAdministratorAccounts accounts, IConfiguration configuration) : IdentityUiController(accounts, configuration)
{
    /// <summary>Lists credential-free accounts and the latest independent identity-store audit events.</summary>
    [HttpGet]
    public async Task<IActionResult> Index() => Request.Query.Count == 0 ? await PageAsync() : BadRequest();

    /// <summary>Creates an explicitly named application account with one supported role.</summary>
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Create()
    {
        var form = await ReadFieldsAsync("userName", "password", "role");
        if (form is null) { return BadRequest(); }
        var result = await Accounts.CreateUserAsync(User, form["userName"].ToString(), form["password"].ToString(), form["role"].ToString());
        return result.Succeeded ? LocalRedirect("~/manage/users") : await PageAsync(Explain(result));
    }

    /// <summary>Changes role/enabled state with explicit versioning and last-administrator protection.</summary>
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Update()
    {
        var form = await ReadFieldsAsync("id", "version", "role", "enabled");
        if (form is null || !Guid.TryParseExact(form["id"], "D", out var id) || id == Guid.Empty ||
            !Version(form["version"], out var version) || form["enabled"].ToString() is not ("true" or "false")) { return BadRequest(); }
        var result = await Accounts.UpdateUserAsync(User, id, version, form["role"].ToString(), form["enabled"] == "true");
        return await CompleteAsync(result, id, form["enabled"] != "true" || form["role"] != User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value);
    }

    /// <summary>Revokes every existing local ticket for a selected account without resetting its password.</summary>
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Revoke()
    {
        var form = await ReadFieldsAsync("id", "version");
        if (form is null || !Guid.TryParseExact(form["id"], "D", out var id) || id == Guid.Empty ||
            !Version(form["version"], out var version)) { return BadRequest(); }
        return await CompleteAsync(await Accounts.RevokeUserAsync(User, id, version), id);
    }

    private async Task<IActionResult> CompleteAsync(LocalProvisionResult result, Guid target, bool revokeOwnSession = true)
    {
        if (!result.Succeeded) { return await PageAsync(Explain(result)); }
        if (revokeOwnSession && User.FindFirst(ControllerActorIdentity.ActorClaimType)?.Value == ControllerActorIdentity.FromLocalAccount(target))
        {
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
            return LocalRedirect("~/login");
        }
        return LocalRedirect("~/manage/users");
    }

    private async Task<IActionResult> PageAsync(string? error = null)
    {
        if (error is not null) { Response.StatusCode = 400; }
        return View("Index", new UsersPageModel(await Accounts.ListUsersAsync(User), await Accounts.ReadIdentityAuditAsync(User), error));
    }
}
