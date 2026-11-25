using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web;

/// <summary>Credential-free Users view, with independently committed identity-store history.</summary>
public sealed record UsersPageModel(IReadOnlyList<LocalUserSnapshot> Users, IReadOnlyList<IdentityAuditEntry> Audit, string? Error = null);

/// <summary>Current actor's profile; entered passwords are never retained in a view model.</summary>
public sealed record ProfilePageModel(UserProfileSnapshot Profile, string? Error = null, string? ProposedDisplayName = null);

[SupportedOSPlatform("linux")]
internal sealed class IdentityUiExceptionFilter : IExceptionFilter
{
    public IdentityUiExceptionFilter() { }
    public void OnException(ExceptionContext context)
    {
        if (context.Exception is not AccountStoreException error) { return; }
        context.Result = error.Code == "account.denied" ? new ForbidResult() : new StatusCodeResult(503);
        context.ExceptionHandled = true;
    }
}

/// <summary>Strict shared form/navigation boundary for authenticated identity views.</summary>
[SupportedOSPlatform("linux")]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
[RequestSizeLimit(8192), RequestFormLimits(ValueCountLimit = 8, ValueLengthLimit = 1024, KeyLengthLimit = 128)]
[TypeFilter(typeof(IdentityUiExceptionFilter))]
public abstract class IdentityUiController(LocalAdministratorAccounts accounts, IConfiguration configuration) : Controller
{
    /// <summary>Protected account operations, independent of firewall/controller state.</summary>
    protected LocalAdministratorAccounts Accounts { get; } = accounts;

    /// <summary>Provides the existing navigation only when the controller is configured.</summary>
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        ViewData["ShowManageNav"] = configuration.GetValue<bool>("ControllerState:Enabled");
        ViewData["ActorRole"] = User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value;
        ViewData["ShowNativeSources"] = User.IsInRole(NergalRoles.Administrator);
        base.OnActionExecuting(context);
    }

    /// <summary>Rejects unknown, omitted and repeated form fields instead of letting default binding broaden a mutation.</summary>
    protected async Task<IFormCollection?> ReadFieldsAsync(params string[] names)
        => await ReadFieldsCoreAsync(null, names);

    /// <summary>Accepts one optional native boolean switch; every other field remains mandatory and all duplicates remain denied.</summary>
    protected async Task<IFormCollection?> ReadFieldsWithOptionalSwitchAsync(string optionalSwitch, params string[] names)
        => await ReadFieldsCoreAsync(optionalSwitch, names);

    private async Task<IFormCollection?> ReadFieldsCoreAsync(string? optionalSwitch, string[] names)
    {
        if (!string.Equals(Request.ContentType?.Split(';')[0].Trim(), "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        { return null; }
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        var allowed = names.Append("__RequestVerificationToken").ToHashSet(StringComparer.Ordinal);
        var requiredPresent = allowed.All(form.ContainsKey);
        if (optionalSwitch is not null) { allowed.Add(optionalSwitch); }
        return requiredPresent && form.All(field => allowed.Contains(field.Key) && field.Value.Count == 1) ? form : null;
    }

    /// <summary>Parses an explicit bounded expected version without accepting signs, whitespace or overflow.</summary>
    protected static bool Version(string? value, out long version) =>
        long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out version) && version >= 0 && version < long.MaxValue;

    /// <summary>Maps stable service codes to actionable hints without reflecting credential or database data.</summary>
    protected static string Explain(LocalProvisionResult result) => result.ErrorCodes.FirstOrDefault() switch
    {
        "account.lastAdministrator" => "Keep at least one enabled local Administrator. Create or promote another Administrator first.",
        "account.stale" or "profile.stale" => "This record changed. Review its current values and submit again.",
        "account.nameExists" => "That sign-in name already exists. Choose another name.",
        "password.bounds" => "Use a password of 15–128 characters.",
        "account.credentialsDenied" => "Current password verification failed. Try again or wait for the account lockout to expire.",
        "profile.displayName" => "Use at most 80 display-name characters without control characters.",
        "account.capacity" => "This installation has reached the supported limit of 256 local accounts.",
        _ => "The change was rejected. Review the fields and try again.",
    };
}

internal static class IdentityUiLabels
{
    internal static string Role(string role) => role switch
    {
        NergalRoles.Administrator => "Administrator",
        NergalRoles.Auditor => "Auditor",
        "operator" => "Offline operator",
        _ => role,
    };
    internal static string Action(string action) => action switch
    {
        "account.bootstrap" => "Initial account created",
        "account.created" => "Account created",
        "account.accessChanged" => "Access changed",
        "account.sessionsRevoked" => "Sessions revoked",
        "account.signedOut" => "Signed out",
        "account.passwordChanged" => "Password changed",
        "account.passwordDenied" => "Password verification denied",
        "profile.updated" => "Profile updated",
        _ => action,
    };
    internal static string Account(string identity, IReadOnlyList<LocalUserSnapshot> users)
    {
        if (identity == "operator:offline") { return "Offline operator"; }
        var value = identity.StartsWith("local:", StringComparison.Ordinal) ? identity[6..] : identity;
        return Guid.TryParseExact(value, "D", out var id)
            ? users.FirstOrDefault(user => user.Id == id)?.UserName ?? "Local account"
            : "External identity";
    }
}
