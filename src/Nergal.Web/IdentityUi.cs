using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Localization;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web;

/// <summary>Credential-free Users view, with independently committed identity-store history.</summary>
public sealed record UsersPageModel(IReadOnlyList<LocalUserSnapshot> Users, IReadOnlyList<IdentityAuditEntry> Audit, string? Error = null);

/// <summary>Current actor's profile; entered passwords are never retained in a view model.</summary>
public sealed record ProfilePageModel(UserProfileSnapshot Profile, string? Error = null, ProfileMetadata? Proposed = null);

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
    protected static string Explain(LocalProvisionResult result, IStringLocalizer<UiStrings>? L = null) => result.ErrorCodes.FirstOrDefault() switch
    {
        "account.lastAdministrator" => L?["Keep at least one enabled local Administrator. Create or promote another Administrator first."].Value ?? "Keep at least one enabled local Administrator. Create or promote another Administrator first.",
        "account.localAdministratorRequired" => L?["Sign in as a local Administrator to grant or restore local Administrator access."].Value ?? "Sign in as a local Administrator to grant or restore local Administrator access.",
        "account.stale" or "profile.stale" => L?["This record changed. Review its current values and submit again."].Value ?? "This record changed. Review its current values and submit again.",
        "account.nameExists" => L?["That sign-in name already exists. Choose another name."].Value ?? "That sign-in name already exists. Choose another name.",
        "password.bounds" => L?["Use a password of 15–128 characters."].Value ?? "Use a password of 15–128 characters.",
        "account.credentialsDenied" => L?["Current password verification failed. Try again or wait for the account lockout to expire."].Value ?? "Current password verification failed. Try again or wait for the account lockout to expire.",
        "profile.metadata" => L?["Use at most 80 characters for each name and a valid profile email address, without control characters."].Value ?? "Use at most 80 characters for each name and a valid profile email address, without control characters.",
        "provider.invalid" => L?["Enter a valid HTTPS issuer and callback, client ID, literal groups claim and distinct role groups. Secrets must be 1–4096 characters without controls."].Value ?? "Enter a valid HTTPS issuer and callback, client ID, literal groups claim and distinct role groups. Secrets must be 1–4096 characters without controls.",
        "provider.stale" => L?["These connection settings changed. Reload the page before saving again."].Value ?? "These connection settings changed. Reload the page before saving again.",
        "provider.secretRequired" => L?["Enter a client secret when creating a connection or changing its issuer or client ID."].Value ?? "Enter a client secret when creating a connection or changing its issuer or client ID.",
        "provider.localAdministratorRequired" => L?["Sign in as a local Administrator to change provider trust."].Value ?? "Sign in as a local Administrator to change provider trust.",
        "profile.mappingInvalid" => L?["Use an exact HTTPS issuer and literal claim names. Identity, role and MFA claims cannot be mapped as metadata."].Value ?? "Use an exact HTTPS issuer and literal claim names. Identity, role and MFA claims cannot be mapped as metadata.",
        "profile.mappingStale" => L?["This mapping changed. Review its current version and submit again."].Value ?? "This mapping changed. Review its current version and submit again.",
        "profile.mappingCapacity" => L?["This installation supports up to 16 issuer profile mappings."].Value ?? "This installation supports up to 16 issuer profile mappings.",
        "account.capacity" => L?["This installation has reached the supported limit of 256 local accounts."].Value ?? "This installation has reached the supported limit of 256 local accounts.",
        _ => L?["The change was rejected. Review the fields and try again."].Value ?? "The change was rejected. Review the fields and try again.",
    };
}

internal static class IdentityUiLabels
{
    internal static string Role(string role, IStringLocalizer<UiStrings> L) => role switch
    {
        NergalRoles.Administrator => L["Administrator"].Value,
        NergalRoles.Auditor => L["Auditor"].Value,
        "operator" => L["Offline operator"].Value,
        _ => role,
    };
    internal static string Action(string action, IStringLocalizer<UiStrings> L) => action switch
    {
        "account.bootstrap" => L["Initial account created"].Value,
        "account.created" => L["Account created"].Value,
        "account.accessChanged" => L["Access changed"].Value,
        "account.sessionsRevoked" => L["Sessions revoked"].Value,
        "account.signedOut" => L["Signed out"].Value,
        "account.passwordChanged" => L["Password changed"].Value,
        "account.passwordDenied" => L["Password verification denied"].Value,
        "profile.updated" => L["Profile updated"].Value,
        "provider.connectionSaved" => L["OIDC connection settings replaced"].Value,
        "provider.oauthConnectionSaved" => L["OAuth connection settings replaced"].Value,
        "oauth.signedIn" => L["OAuth sign-in completed"].Value,
        "profile.mappingSaved" => L["Profile mapping saved"].Value,
        "profile.providerRefreshed" => L["Provider profile refreshed"].Value,
        "provider.ldapConnectionSaved" => L["LDAP connection settings replaced"].Value,
        "local.signedIn" => L["Local sign-in completed"].Value,
        "ldap.signedIn" => L["LDAP sign-in completed"].Value,
        "ldap.signedOut" => L["LDAP session signed out"].Value,
        "mfa.policyChanged" => L["MFA policy changed"].Value,
        "mfa.emailDeliverySaved" => L["Email delivery settings changed"].Value,
        "mfa.emailEnrollmentStarted" => L["Email verification started"].Value,
        "mfa.emailEnrollmentDenied" => L["Email verification denied"].Value,
        "mfa.emailEnrolled" => L["Email factor verified"].Value,
        "mfa.enrollmentStarted" => L["Authenticator setup started"].Value,
        "mfa.enrollmentDenied" => L["Authenticator setup denied"].Value,
        "mfa.totpEnrolled" => L["Authenticator verified"].Value,
        "mfa.challenged" => L["Second-factor code required"].Value,
        "mfa.denied" => L["MFA attempt denied"].Value,
        "mfa.recoveryIssued" => L["MFA recovery authorized"].Value,
        "mfa.recoveryStarted" => L["MFA recovery enrollment started"].Value,
        "mfa.recoveryDenied" => L["MFA recovery attempt denied"].Value,
        "mfa.recovered" => L["MFA recovery completed"].Value,
        _ => action,
    };
    internal static string ProfileDiagnostic(string code, IStringLocalizer<UiStrings>? L = null) => code switch
    {
        "displayName.missing" => L?["The provider did not supply a display name."].Value ?? "The provider did not supply a display name.",
        "displayName.invalid" => L?["The provider supplied an invalid display name."].Value ?? "The provider supplied an invalid display name.",
        "givenName.missing" => L?["The provider did not supply a given name."].Value ?? "The provider did not supply a given name.",
        "givenName.invalid" => L?["The provider supplied an invalid given name."].Value ?? "The provider supplied an invalid given name.",
        "familyName.missing" => L?["The provider did not supply a family name."].Value ?? "The provider did not supply a family name.",
        "familyName.invalid" => L?["The provider supplied an invalid family name."].Value ?? "The provider supplied an invalid family name.",
        "email.missing" => L?["The provider did not supply a profile email address."].Value ?? "The provider did not supply a profile email address.",
        "email.invalid" => L?["The provider supplied an invalid profile email address."].Value ?? "The provider supplied an invalid profile email address.",
        _ => L?["A provider profile field is unavailable."].Value ?? "A provider profile field is unavailable.",
    };
    internal static string Account(string identity, IReadOnlyList<LocalUserSnapshot> users, IStringLocalizer<UiStrings> L)
    {
        if (identity.StartsWith("https://", StringComparison.Ordinal)) { return identity; }
        if (identity == "oidc") { return L["OIDC connection"].Value; }
        if (identity == "operator:offline") { return L["Offline operator"].Value; }
        var value = identity.StartsWith("local:", StringComparison.Ordinal) ? identity[6..] : identity;
        return Guid.TryParseExact(value, "D", out var id)
            ? users.FirstOrDefault(user => user.Id == id)?.UserName ?? L["Local account"].Value
            : L["External identity"].Value;
    }
}
