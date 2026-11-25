using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Nergal.Identity;

namespace Nergal.Web.Controllers;

/// <summary>Browser session endpoints mapped only by the explicitly enabled authentication host.</summary>
[SupportedOSPlatform("linux")]
public sealed class SessionController(LocalAdministratorAccounts accounts, IConfiguration configuration)
    : IdentityUiController(accounts, configuration)
{
    private const string ContinuationCookie = "__Host-nergal-mfa";
    private const int MaxContinuationLength = 4096;

    private readonly bool controllerEnabled = configuration.GetValue<bool>("ControllerState:Enabled");
    private string SignedInDestination => controllerEnabled ? "~/manage" : "~/session";

    /// <summary>Shows blank credential forms; the LDAP form is conditional on the current enabled generation.</summary>
    [HttpGet, AllowAnonymous]
    public IActionResult Login() => User.Identity?.IsAuthenticated == true ? LocalRedirect(SignedInDestination) : LoginPage();

    /// <summary>Verifies a local password and asks the identity store whether an additional factor is required.</summary>
    [HttpPost, AllowAnonymous, ValidateAntiForgeryToken, EnableRateLimiting("local-login")]
    [RequestFormLimits(ValueCountLimit = 3, KeyLengthLimit = 128, ValueLengthLimit = 2048)]
    public async Task<IActionResult> Authenticate([FromServices] IDataProtectionProvider keys, [FromServices] IMfaEmailSender emailSender)
    {
        var form = await ReadFieldsAsync("username", "password");
        if (form is null) { return RejectForm(); }
        var result = await Accounts.BeginLocalSignInAsync(form["username"].ToString(), form["password"].ToString(), keys,
            HttpContext.RequestAborted, emailSender);
        return await FirstFactorAsync(result, IdentityConstants.ApplicationScheme);
    }

    /// <summary>Verifies an LDAP credential against the exact generation rendered in the sign-in form.</summary>
    [HttpPost, AllowAnonymous, ValidateAntiForgeryToken, EnableRateLimiting("ldap-login")]
    [RequestFormLimits(ValueCountLimit = 4, KeyLengthLimit = 128, ValueLengthLimit = 12288)]
    public async Task<IActionResult> AuthenticateLdap([FromServices] IDataProtectionProvider keys, [FromServices] IMfaEmailSender emailSender)
    {
        var form = await ReadFieldsAsync("version", "username", "password");
        if (Request.Query.Count != 0 || form is null || !Version(form["version"], out var version) || version == 0)
        { return RejectForm(); }
        var result = await Accounts.BeginLdapSignInAsync(version, form["username"].ToString(), form["password"].ToString(),
            keys, HttpContext.RequestAborted, emailSender);
        return await FirstFactorAsync(result, FederatedLogin.LdapSession);
    }

    /// <summary>Shows a blank authenticator form when the browser supplies a pending continuation.</summary>
    [HttpGet, AllowAnonymous]
    public IActionResult VerifyMfa()
    {
        if (Request.Query.Count != 0) { return BadRequest(); }
        if (User.Identity?.IsAuthenticated == true) { return LocalRedirect(SignedInDestination); }
        return ReadContinuation() is null ? LocalRedirect("~/login") : View();
    }

    /// <summary>Completes first-factor proof using only the protected browser continuation and a bounded code.</summary>
    [HttpPost, AllowAnonymous, ValidateAntiForgeryToken, EnableRateLimiting("mfa-login")]
    [RequestFormLimits(ValueCountLimit = 2, KeyLengthLimit = 128, ValueLengthLimit = 1024)]
    public async Task<IActionResult> CompleteMfa([FromServices] IDataProtectionProvider keys)
    {
        var form = await ReadFieldsAsync("code");
        if (Request.Query.Count != 0 || form is null) { return RejectForm(); }
        var continuation = ReadContinuation();
        if (continuation is null) { return Denied(); }

        var code = form["code"].ToString();
        var result = await Accounts.CompleteMfaSignInAsync(continuation, code, keys, HttpContext.RequestAborted);
        if (result.Status == MfaSignInStatus.Challenge &&
            string.Equals(result.Continuation, continuation, StringComparison.Ordinal))
        {
            // Keep the original cookie and expiry. Only the same still-current backend proof may retry.
            Response.StatusCode = StatusCodes.Status401Unauthorized;
            return View("VerifyMfa", true);
        }
        return result.Status == MfaSignInStatus.SignedIn ? await FinishAsync(result) : Denied();
    }

    /// <summary>Begins a correlated authorization-code exchange for an explicitly configured external issuer.</summary>
    [HttpPost, AllowAnonymous, ValidateAntiForgeryToken, EnableRateLimiting("local-login"), RequestSizeLimit(8192)]
    public async Task<IActionResult> Federated()
    {
        // Retire Strict cookies on the same-site initiation, before the cross-site form-post callback.
        await RetireDisplacedSessionsAsync();
        ClearContinuation();
        return Challenge(new AuthenticationProperties
        { RedirectUri = controllerEnabled ? "/manage" : "/session" }, FederatedLogin.Protocol);
    }

    /// <summary>Displays the authenticated session page without accessing agent state.</summary>
    [HttpGet, Authorize]
    public IActionResult Index() => View();

    /// <summary>Revokes the authenticated session under its issuing scheme and returns to sign-in.</summary>
    [HttpPost, Authorize, ValidateAntiForgeryToken]
    [RequestFormLimits(ValueCountLimit = 1, KeyLengthLimit = 128, ValueLengthLimit = 1024)]
    public async Task<IActionResult> Logout()
    {
        if (await ReadFieldsAsync() is null) { return BadRequest(); }
        var scheme = User.Identity?.AuthenticationType;
        if (scheme != FederatedLogin.Session && scheme != FederatedLogin.LdapSession && scheme != OAuthLogin.Session)
        {
            await Accounts.RevokeSessionsAsync(User);
            scheme = IdentityConstants.ApplicationScheme;
        }
        await HttpContext.SignOutAsync(scheme);
        OAuthLogin.RetireChallenge(HttpContext);
        ClearContinuation();
        return LocalRedirect("~/login");
    }

    private ViewResult LoginPage(bool failed = false) => View("Login", new LoginPageModel(
        ReadLdapGenerationAsync, () => Accounts.ReadOAuthSignInGenerationAsync(), failed));

    private async Task<long?> ReadLdapGenerationAsync()
    {
        try { return await Accounts.ReadLdapSignInGenerationAsync(); }
        catch (AccountStoreException) { return null; }
    }

    private async Task<IActionResult> FirstFactorAsync(MfaSignInResult result, string scheme)
    {
        if (result.Status == MfaSignInStatus.SignedIn) { return await FinishAsync(result); }
        var now = DateTimeOffset.UtcNow;
        if (result.Status != MfaSignInStatus.Challenge ||
            result.Continuation is not { Length: > 0 and <= MaxContinuationLength } continuation ||
            result.ExpiresUtc is not DateTimeOffset expires || expires <= now)
        { return Denied(); }

        // A displaced provider ticket would still authorize requests and redirect the browser away from MFA.
        await RetireDisplacedSessionsAsync(scheme);
        var options = ContinuationOptions();
        var browserLimit = now.AddMinutes(5);
        options.Expires = expires < browserLimit ? expires : browserLimit;
        Response.Cookies.Append(ContinuationCookie, continuation, options);
        return LocalRedirect("~/login/mfa");
    }

    private async Task<IActionResult> FinishAsync(MfaSignInResult result)
    {
        if (result.LdapPrincipal is { } principal)
        {
            if (result.ExpiresUtc is not DateTimeOffset expires || expires <= DateTimeOffset.UtcNow)
            { return Denied(); }
            await RetireDisplacedSessionsAsync(FederatedLogin.LdapSession);
            await HttpContext.SignInAsync(FederatedLogin.LdapSession, principal, new AuthenticationProperties
            { ExpiresUtc = expires, IsPersistent = false, AllowRefresh = false });
        }
        else { await RetireDisplacedSessionsAsync(IdentityConstants.ApplicationScheme); }

        ClearContinuation();
        return LocalRedirect(SignedInDestination);
    }

    private async Task RetireDisplacedSessionsAsync(string? keep = null)
    {
        if (keep != IdentityConstants.ApplicationScheme) { await FederatedLogin.RetireLocalSessionAsync(HttpContext); }
        if (keep != FederatedLogin.LdapSession && Request.Cookies.ContainsKey(FederatedLogin.LdapCookie))
        { await HttpContext.SignOutAsync(FederatedLogin.LdapSession); }
        if (keep != FederatedLogin.Session && Request.Cookies.ContainsKey(FederatedLogin.Cookie))
        { await HttpContext.SignOutAsync(FederatedLogin.Session); }
        if (keep != OAuthLogin.Session && Request.Cookies.ContainsKey(OAuthLogin.Cookie))
        { await HttpContext.SignOutAsync(OAuthLogin.Session); }
        OAuthLogin.RetireChallenge(HttpContext);
    }

    private IActionResult RejectForm()
    {
        ClearContinuation();
        return BadRequest();
    }

    private IActionResult Denied()
    {
        ClearContinuation();
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return LoginPage(failed: true);
    }

    private string? ReadContinuation() =>
        Request.Cookies[ContinuationCookie] is { Length: > 0 and <= MaxContinuationLength } value ? value : null;

    private void ClearContinuation()
    {
        if (Request.Cookies.ContainsKey(ContinuationCookie))
        { Response.Cookies.Delete(ContinuationCookie, ContinuationOptions()); }
    }

    private static CookieOptions ContinuationOptions() => new()
    { Path = "/", HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, IsEssential = true };
}

/// <summary>Sign-in view with deferred credential-free provider availability lookups.</summary>
public sealed record LoginPageModel(Func<Task<long?>> ReadLdapGenerationAsync, Func<Task<long?>> ReadOAuthGenerationAsync, bool Failed);
