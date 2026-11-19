using System.Data;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Nergal.Identity;

/// <summary>Explicit singleton administrator provisioning and serialized local password/lockout verification. Issues no browser session.</summary>
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
    public async Task<LocalProvisionResult> ProvisionAsync(string userName, string password, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userName);
        ArgumentNullException.ThrowIfNull(password);
        if (!ValidName(userName)) { return new(["account.userName"]); }
        if (!BoundedPasswordValidator.Valid(password)) { return new(["password.bounds"]); }
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
            AccountConnectionPolicy.RequireSchema(context.Database.GetDbConnection(), transaction.GetDbTransaction());
            if (await users.Users.AnyAsync()) { return new(["account.exists"]); }
            var result = await users.CreateAsync(new LocalAdministrator { UserName = userName }, password);
            if (!result.Succeeded) { return new(result.Errors.Select(error => error.Code)); }
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
        ArgumentNullException.ThrowIfNull(userName);
        ArgumentNullException.ThrowIfNull(password);
        cancellationToken.ThrowIfCancellationRequested();
        if (!ValidName(userName) || !BoundedPasswordValidator.Valid(password)) { return new(null); }
        try
        {
            await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
            AccountConnectionPolicy.RequireSchema(context.Database.GetDbConnection(), transaction.GetDbTransaction());
            var user = await users.FindByNameAsync(userName);
            if (user is not null && (!user.LockoutEnabled || user.TwoFactorEnabled || string.IsNullOrWhiteSpace(user.PasswordHash) ||
                string.IsNullOrWhiteSpace(user.SecurityStamp) || string.IsNullOrWhiteSpace(user.ConcurrencyStamp)))
            { throw new AccountStoreException("account.unsupportedState"); }
            if (user is null || await users.IsLockedOutAsync(user))
            {
                dummy.Verify(password);
                await transaction.CommitAsync(CancellationToken.None);
                return new(null);
            }
            var result = await signIn.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);
            Guid? identifier = null;
            if (result.Succeeded)
            {
                if (!Guid.TryParse(user.Id, out var parsed) || parsed == Guid.Empty) { throw new AccountStoreException("account.corrupt"); }
                identifier = parsed;
            }
            await transaction.CommitAsync(CancellationToken.None);
            return new(identifier);
        }
        catch (Exception error) when (error is SqliteException or DbUpdateException)
        { throw new AccountStoreException("account.databaseError"); }
        catch (FormatException) { throw new AccountStoreException("account.corrupt"); }
    }

    private static bool ValidName(string value) => value.Length is >= 1 and <= 64 &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
}
