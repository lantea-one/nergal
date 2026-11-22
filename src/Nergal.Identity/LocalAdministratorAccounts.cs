using System.Data;
using System.Security.Claims;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Nergal.Core.Identity;

namespace Nergal.Identity;

/// <summary>Explicit singleton administrator provisioning and serialized password verification and explicit browser session operations.</summary>
/// <remarks>Trusted callers provision through a local administrative boundary, never an unauthenticated registration route. Use a fresh DI scope per operation.</remarks>
[SupportedOSPlatform("linux")]
public sealed class LocalAdministratorAccounts
{
    private readonly LocalAccountContext context;
    private readonly UserManager<LocalAdministrator> users;
    private readonly SignInManager<LocalAdministrator> signIn;
    private readonly DummyPasswordVerification dummy;

    internal LocalAdministratorAccounts(LocalAccountContext context, UserManager<LocalAdministrator> users,
        SignInManager<LocalAdministrator> signIn, DummyPasswordVerification dummy)
    { this.context = context; this.users = users; this.signIn = signIn; this.dummy = dummy; }

    /// <summary>Creates the sole local administrator in an explicitly initialized database; no default credential or replacement is accepted.</summary>
    /// <exception cref="ArgumentNullException">User name or password is null.</exception>
    /// <exception cref="AccountStoreException">Protected storage fails. Validation errors contain only stable codes.</exception>
    /// <exception cref="OperationCanceledException">Cancellation preceded credential reservation.</exception>
    public Task<LocalProvisionResult> ProvisionAsync(string userName, string password, CancellationToken cancellationToken = default)
        => ProvisionAsync(userName, password, NergalRoles.Administrator, cancellationToken);

    /// <summary>Creates the sole local account with an explicit controller role in an explicitly initialized database.</summary>
    /// <exception cref="ArgumentNullException">User name, password, or role is null.</exception>
    /// <exception cref="AccountStoreException">Protected storage fails. Validation errors contain only stable codes.</exception>
    /// <exception cref="OperationCanceledException">Cancellation preceded credential reservation.</exception>
    public async Task<LocalProvisionResult> ProvisionAsync(string userName, string password, string role, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userName);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(role);
        if (!NergalRoles.IsDefined(role)) { return new(["account.role"]); }
        if (!ValidName(userName)) { return new(["account.userName"]); }
        if (!BoundedPasswordValidator.Valid(password)) { return new(["password.bounds"]); }
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
            AccountConnectionPolicy.RequireSchema(context.Database.GetDbConnection(), transaction.GetDbTransaction());
            if (await users.Users.AnyAsync()) { return new(["account.exists"]); }
            var account = new LocalAdministrator { UserName = userName };
            var result = await users.CreateAsync(account, password);
            if (!result.Succeeded) { return new(result.Errors.Select(error => error.Code)); }
            if (role != NergalRoles.Administrator)
            {
                var claimResult = await users.AddClaimAsync(account, new Claim(ClaimTypes.Role, role));
                if (!claimResult.Succeeded) { return new(claimResult.Errors.Select(error => error.Code)); }
            }
            // Once a credential operation begins, finish its durable decision even if
            // an HTTP caller later disconnects. Cancellation must not erase attempts.
            await transaction.CommitAsync(CancellationToken.None);
            return new([]);
        }
        catch (Exception error) when (error is SqliteException or DbUpdateException)
        { throw new AccountStoreException("account.databaseError"); }
    }

    /// <summary>Verifies a password and commits failure/reset state under a serialized transaction. Unknown, bad and locked-out credentials return the same denial.</summary>
    /// <remarks>Cancellation is accepted before reservation. Once verification begins its decision completes, so disconnecting cannot roll back failed-attempt accounting.</remarks>
    /// <exception cref="ArgumentNullException">User name or password is null.</exception>
    /// <exception cref="AccountStoreException">Protected storage fails; no partial credential result is returned.</exception>
    /// <exception cref="OperationCanceledException">Cancellation preceded credential reservation.</exception>
    public async Task<LocalCredentialResult> VerifyAsync(string userName, string password, CancellationToken cancellationToken = default)
    {
        var user = await VerifyPasswordAsync(userName, password, cancellationToken);
        return new(user is null ? null : Guid.Parse(user.Id));
    }

    /// <summary>Checks that the existing store contains one administrator with supported password and session state before accepting requests.</summary>
    public async Task RequireProvisionedAsync(CancellationToken cancellationToken = default)
    {
        var user = await users.Users.AsNoTracking().SingleOrDefaultAsync(cancellationToken)
            ?? throw new AccountStoreException("account.unprovisioned");
        RequireSupported(user);
    }

    /// <summary>Issues a nonpersistent application cookie from the account snapshot whose password was verified under reservation.</summary>
    /// <remarks>The calling host must install the protected local cookie scheme and enforce HTTPS, antiforgery and rate limits.</remarks>
    public async Task<bool> SignInAsync(string userName, string password, CancellationToken cancellationToken = default)
    {
        var user = await VerifyPasswordAsync(userName, password, cancellationToken);
        if (user is null) { return false; }
        await signIn.SignInAsync(user, isPersistent: false);
        return true;
    }

    internal async Task<bool> ValidateSessionAsync(ClaimsPrincipal principal)
    {
        var user = await signIn.ValidateSecurityStampAsync(principal);
        if (user is null) { return false; }
        RequireSupported(user);
        var storedRole = await ResolveValidatedRoleAsync(users, user);
        var claimRole = principal.FindFirstValue(ClaimTypes.Role);
        var claimActor = principal.FindFirstValue(ControllerActorIdentity.ActorClaimType);
        return string.Equals(claimRole, storedRole, StringComparison.Ordinal) &&
               string.Equals(claimActor, ControllerActorIdentity.FromLocalAccount(Guid.Parse(user.Id)), StringComparison.Ordinal);
    }

    internal static async Task<string> ResolveValidatedRoleAsync(UserManager<LocalAdministrator> userManager, LocalAdministrator user)
    {
        var claims = await userManager.GetClaimsAsync(user);
        var roles = claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToArray();
        if (roles.Length == 0)
        {
            return NergalRoles.Administrator;
        }

        if (roles.Length == 1 && NergalRoles.IsDefined(roles[0]))
        {
            return roles[0];
        }

        throw new AccountStoreException("account.unsupportedState");
    }

    /// <summary>Revokes sessions for the authenticated account by replacing its security stamp. The host also clears the local cookie.</summary>
    public async Task RevokeSessionsAsync(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        var user = await signIn.ValidateSecurityStampAsync(principal);
        if (user is null) { throw new AccountStoreException("account.sessionInvalid"); }
        RequireSupported(user);
        if (!(await users.UpdateSecurityStampAsync(user)).Succeeded)
        { throw new AccountStoreException("account.revokeFailed"); }
    }

    private static void RequireSupported(LocalAdministrator user)
    {
        if (!user.LockoutEnabled || user.TwoFactorEnabled || string.IsNullOrWhiteSpace(user.PasswordHash) ||
            string.IsNullOrWhiteSpace(user.SecurityStamp) || string.IsNullOrWhiteSpace(user.ConcurrencyStamp))
        { throw new AccountStoreException("account.unsupportedState"); }
        if (!Guid.TryParse(user.Id, out var parsed) || parsed == Guid.Empty)
        { throw new AccountStoreException("account.corrupt"); }
    }

    private async Task<LocalAdministrator?> VerifyPasswordAsync(string userName, string password, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(userName);
        ArgumentNullException.ThrowIfNull(password);
        cancellationToken.ThrowIfCancellationRequested();
        if (!ValidName(userName) || !BoundedPasswordValidator.Valid(password)) { return null; }
        try
        {
            await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
            AccountConnectionPolicy.RequireSchema(context.Database.GetDbConnection(), transaction.GetDbTransaction());
            var user = await users.FindByNameAsync(userName);
            if (user is not null) { RequireSupported(user); }
            if (user is null || await users.IsLockedOutAsync(user))
            {
                dummy.Verify(password);
                await transaction.CommitAsync(CancellationToken.None);
                return null;
            }
            var result = await signIn.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);
            await transaction.CommitAsync(CancellationToken.None);
            return result.Succeeded ? user : null;
        }
        catch (Exception error) when (error is SqliteException or DbUpdateException)
        { throw new AccountStoreException("account.databaseError"); }
        catch (FormatException) { throw new AccountStoreException("account.corrupt"); }
    }

    private static bool ValidName(string value) => value.Length is >= 1 and <= 64 &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
}

[SupportedOSPlatform("linux")]
internal sealed class LocalAccountClaimsPrincipalFactory(
    UserManager<LocalAdministrator> userManager,
    IOptions<IdentityOptions> optionsAccessor) : UserClaimsPrincipalFactory<LocalAdministrator>(userManager, optionsAccessor)
{
    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(LocalAdministrator user)
    {
        var identity = await base.GenerateClaimsAsync(user);
        var role = await LocalAdministratorAccounts.ResolveValidatedRoleAsync(UserManager, user);
        foreach (var existing in identity.FindAll(ClaimTypes.Role).ToArray())
        {
            identity.RemoveClaim(existing);
        }

        foreach (var existing in identity.FindAll(ControllerActorIdentity.ActorClaimType).ToArray())
        {
            identity.RemoveClaim(existing);
        }

        identity.AddClaim(new Claim(ClaimTypes.Role, role));
        identity.AddClaim(new Claim(ControllerActorIdentity.ActorClaimType,
            ControllerActorIdentity.FromLocalAccount(Guid.Parse(user.Id))));
        return identity;
    }
}
