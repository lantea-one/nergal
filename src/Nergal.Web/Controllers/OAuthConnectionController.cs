using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Controllers;

/// <summary>Versioned OAuth connection settings for local Administrators.</summary>
[SupportedOSPlatform("linux")]
[Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
[RequestFormLimits(ValueCountLimit = 20, ValueLengthLimit = 8192, KeyLengthLimit = 128)]
public sealed class OAuthConnectionController(LocalAdministratorAccounts accounts, IConfiguration configuration, IDataProtectionProvider keys)
    : IdentityUiController(accounts, configuration)
{
    private bool LocalAdministrator => User.Identity?.AuthenticationType == IdentityConstants.ApplicationScheme;

    /// <summary>Reads current settings without decrypting the client secret.</summary>
    [HttpGet]
    public async Task<IActionResult> Index() => !LocalAdministrator ? Forbid() :
        Request.Query.Count != 0 ? BadRequest() : await PageAsync();

    /// <summary>Replaces OAuth trust after explicit confirmation and an expected-version check.</summary>
    [HttpPost, ValidateAntiForgeryToken, RequestSizeLimit(131_072)]
    public async Task<IActionResult> Save()
    {
        if (!LocalAdministrator) { return Forbid(); }
        var form = await ReadFieldsAsync("version", "enabled", "authorizationEndpoint", "tokenEndpoint", "profileEndpoint",
            "callbackUri", "clientId", "clientSecret", "scope", "subjectField", "groupField", "administratorGroups", "auditorGroups",
            "displayName", "givenName", "familyName", "email", "trustProviderMfa", "confirm");
        if (Request.Query.Count != 0 || form is null || !Version(form["version"], out var version) ||
            !Boolean(form["enabled"].ToString(), out var enabled) || !Boolean(form["trustProviderMfa"].ToString(), out var trust))
        { return BadRequest(); }

        string Field(string name) => form[name].ToString();
        var settings = new OAuthConnectionSettings(enabled, Field("authorizationEndpoint"), Field("tokenEndpoint"),
            Field("profileEndpoint"), Field("callbackUri"), Field("clientId"), Field("scope"), Field("subjectField"), Field("groupField"),
            Field("administratorGroups"), Field("auditorGroups"), new(Field("displayName"), Field("givenName"), Field("familyName"), Field("email")), trust);
        if (Field("confirm") != "replace-trust") { return await PageAsync("Confirm the replacement to save OAuth provider trust.", settings, version); }
        var result = await Accounts.SaveOAuthConnectionAsync(User, version, settings, Field("clientSecret"), keys);
        if (result.Succeeded) { return LocalRedirect("~/manage/identity/oauth"); }
        if (result.ErrorCodes.Contains("provider.stale")) { return await PageAsync(Explain(result)); }
        return await PageAsync(result.ErrorCodes.FirstOrDefault() switch
        {
            "provider.oauthInvalid" => "Check the HTTPS endpoints, callback, exact groups and literal JSON field names.",
            "provider.secretRequired" => "Enter the client secret for this new provider identity configuration.",
            _ => Explain(result),
        }, settings, version);
    }

    private async Task<IActionResult> PageAsync(string? error = null, OAuthConnectionSettings? proposed = null, long expectedVersion = 0)
    {
        if (error is not null) { Response.StatusCode = StatusCodes.Status400BadRequest; }
        var saved = await Accounts.ReadOAuthConnectionAsync(User);
        if (proposed is not null && (saved?.Version ?? 0) != expectedVersion)
        { return View("Index", new OAuthConnectionPageModel(saved, null, "These connection settings changed. Reload the page before saving again.")); }
        return View("Index", new OAuthConnectionPageModel(saved, proposed, error));
    }

    private static bool Boolean(string value, out bool result)
    {
        result = value == "true";
        return result || value == "false";
    }
}

/// <summary>Credential-free OAuth form state and validation feedback.</summary>
public sealed record OAuthConnectionPageModel(OAuthConnectionSnapshot? Connection, OAuthConnectionSettings? Proposed, string? Error);
