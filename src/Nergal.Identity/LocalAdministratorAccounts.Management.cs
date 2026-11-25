using System.Data;
using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Nergal.Core.Identity;

namespace Nergal.Identity;

public sealed partial class LocalAdministratorAccounts
{
    /// <summary>Lists bounded credential-free account state for a currently authorized Administrator.</summary>
    public async Task<IReadOnlyList<LocalUserSnapshot>> ListUsersAsync(ClaimsPrincipal principal)
    {
        context.ChangeTracker.Clear();
        _ = await ActorAsync(principal, administrator: true);
        var all = await users.Users.AsNoTracking().OrderBy(user => user.NormalizedUserName).Take(257).ToArrayAsync();
        if (all.Length > 256) { throw new AccountStoreException("account.capacity"); }
        var result = new List<LocalUserSnapshot>();
        foreach (var user in all)
        {
            RequireSupported(user);
            var state = await StateAsync(user.Id);
            result.Add(new(Guid.Parse(user.Id), user.UserName!, await ResolveValidatedRoleAsync(users, user),
                state.Enabled, state.Version, ReadTime(state.CreatedUtc)!.Value, ReadTime(state.UpdatedUtc)!.Value));
        }
        return result.AsReadOnly();
    }

    /// <summary>Reads only the current validated actor's profile; a missing override is an empty read, never an implicit write.</summary>
    public async Task<UserProfileSnapshot> ReadProfileAsync(ClaimsPrincipal principal)
    {
        context.ChangeTracker.Clear();
        var actor = await ActorAsync(principal, administrator: false);
        var profile = await context.Set<LocalProfile>().AsNoTracking().SingleOrDefaultAsync(p => p.ActorId == actor.Id);
        if (profile is not null && (profile.Version < 1 || !new ProfileMetadata(profile.DisplayName, profile.GivenName, profile.FamilyName, profile.Email).IsValid)) { throw new AccountStoreException("account.corrupt"); }
        return new(actor.Id, actor.Name, actor.Role, actor.LocalId,
            actor.LocalId is null ? null : (await StateAsync(actor.LocalId.Value.ToString("D"))).Version,
            profile?.DisplayName ?? "", profile?.Version ?? 0,
            ReadTime(profile?.UpdatedUtc), profile?.GivenName ?? "", profile?.FamilyName ?? "", profile?.Email ?? "",
            actor.Id.StartsWith("oidc:", StringComparison.Ordinal) ? await ReadProviderAsync(actor.Id, principal.FindFirstValue("iss")!) :
                actor.Id.StartsWith("oauth:", StringComparison.Ordinal) ? await ReadOAuthProfileAsync(actor.Id, principal.FindFirstValue("iss")!) : null,
            actor.Id.StartsWith("ldap:", StringComparison.Ordinal) ? await ReadLdapProfileAsync(actor.Id) : null);
    }

    /// <summary>Creates a local account under serialized Administrator authorization. Creating a local Administrator requires a current local Administrator.</summary>
    public Task<LocalProvisionResult> CreateUserAsync(ClaimsPrincipal principal, string userName, string password, string role)
        => MutateAsync(principal, true, async actor =>
        {
            if (!ValidName(userName) || !NergalRoles.IsDefined(role)) { return Failure("account.invalidInput"); }
            if (role == NergalRoles.Administrator && actor.LocalId is null)
            { return Failure("account.localAdministratorRequired"); }
            if (!BoundedPasswordValidator.Valid(password)) { return Failure("password.bounds"); }
            if (await users.Users.CountAsync() >= 256) { return Failure("account.capacity"); }
            if (await users.FindByNameAsync(userName) is not null) { return Failure("account.nameExists"); }
            var user = new LocalAdministrator { UserName = userName };
            var created = await users.CreateAsync(user, password);
            if (!created.Succeeded) { return Failure("account.createDenied"); }
            if (!(await users.AddClaimAsync(user, new(ClaimTypes.Role, role))).Succeeded) { return Failure("account.createDenied"); }
            context.Add(new LocalAccountState { UserId = user.Id, CreatedUtc = Now(), UpdatedUtc = Now() });
            Audit(actor.Id, actor.Role, "account.created", user.Id);
            return Success();
        });

    /// <summary>Updates access and revokes affected tickets atomically while preserving independent local recovery.</summary>
    /// <remarks>Only a current local Administrator can promote or reactivate a local Administrator.</remarks>
    public Task<LocalProvisionResult> UpdateUserAsync(ClaimsPrincipal principal, Guid id, long expectedVersion, string role, bool enabled,
        IDataProtectionProvider? keys = null)
        => MutateAsync(principal, true, async actor =>
        {
            if (!NergalRoles.IsDefined(role)) { return Failure("account.role"); }
            var user = await users.FindByIdAsync(id.ToString("D"));
            if (user is null) { return Failure("account.notFound"); }
            RequireSupported(user);
            var state = await StateAsync(user.Id);
            if (state.Version != expectedVersion) { return Failure("account.stale"); }
            var oldRole = await ResolveValidatedRoleAsync(users, user);
            if (actor.LocalId is null && role == NergalRoles.Administrator &&
                (oldRole != NergalRoles.Administrator || (!state.Enabled && enabled)))
            { return Failure("account.localAdministratorRequired"); }
            if (state.Enabled && oldRole == NergalRoles.Administrator && (!enabled || role != NergalRoles.Administrator))
            {
                if (!await HasIndependentLocalRecoveryAsync(user.Id, keys))
                { return Failure("account.lastAdministrator"); }
            }
            if (state.Enabled == enabled && oldRole == role) { return Success(); }
            var claims = (await users.GetClaimsAsync(user)).Where(claim => claim.Type == ClaimTypes.Role).ToArray();
            if (!(await users.RemoveClaimsAsync(user, claims)).Succeeded ||
                !(await users.AddClaimAsync(user, new(ClaimTypes.Role, role))).Succeeded)
            { return Failure("account.updateDenied"); }
            state.Enabled = enabled;
            await RotateAsync(user, state);
            Audit(actor.Id, actor.Role, "account.accessChanged", user.Id);
            return Success();
        });

    /// <summary>Explicitly revokes all tickets for a selected local account without changing its credential or role.</summary>
    public Task<LocalProvisionResult> RevokeUserAsync(ClaimsPrincipal principal, Guid id, long expectedVersion)
        => MutateAsync(principal, true, async actor =>
        {
            var user = await users.FindByIdAsync(id.ToString("D"));
            if (user is null) { return Failure("account.notFound"); }
            RequireSupported(user);
            var state = await StateAsync(user.Id);
            if (state.Version != expectedVersion) { return Failure("account.stale"); }
            await RotateAsync(user, state);
            Audit(actor.Id, actor.Role, "account.sessionsRevoked", user.Id);
            return Success();
        });

    /// <summary>Saves only the current actor's profile metadata overrides; identity, role and other people's profiles cannot be supplied.</summary>
    public Task<LocalProvisionResult> SaveProfileAsync(ClaimsPrincipal principal, long expectedVersion, ProfileMetadata metadata)
        => MutateAsync(principal, false, async actor =>
        {
            if (metadata is null || !metadata.IsValid) { return Failure("profile.metadata"); }
            var profile = await context.Set<LocalProfile>().SingleOrDefaultAsync(p => p.ActorId == actor.Id);
            if ((profile?.Version ?? 0) != expectedVersion) { return Failure("profile.stale"); }
            if (profile is null) { profile = new() { ActorId = actor.Id }; context.Add(profile); }
            profile.DisplayName = metadata.DisplayName;
            profile.GivenName = metadata.GivenName;
            profile.FamilyName = metadata.FamilyName;
            profile.Email = metadata.Email;
            profile.Version = checked(profile.Version + 1);
            profile.UpdatedUtc = Now();
            Audit(actor.Id, actor.Role, "profile.updated", actor.Id);
            return Success();
        });

    /// <summary>Changes only the current local account's password after lockout-counted verification, then revokes its existing sessions.</summary>
    public Task<LocalProvisionResult> ChangeOwnPasswordAsync(ClaimsPrincipal principal, long expectedVersion, string currentPassword, string newPassword)
        => MutateAsync(principal, false, async actor =>
        {
            if (actor.LocalId is null) { return Failure("account.externalCredential"); }
            if (!BoundedPasswordValidator.Valid(newPassword) || !BoundedPasswordValidator.Valid(currentPassword)) { return Failure("password.bounds"); }
            var user = (await users.FindByIdAsync(actor.LocalId.Value.ToString("D")))!;
            var state = await StateAsync(user.Id);
            if (state.Version != expectedVersion) { return Failure("account.stale"); }
            if (!(await signIn.CheckPasswordSignInAsync(user, currentPassword, lockoutOnFailure: true)).Succeeded)
            {
                Audit(actor.Id, actor.Role, "account.passwordDenied", user.Id);
                return Failure("account.credentialsDenied");
            }
            if (!(await users.ChangePasswordAsync(user, currentPassword, newPassword)).Succeeded) { return Failure("account.passwordDenied"); }
            state.Version = checked(state.Version + 1); state.UpdatedUtc = Now();
            Audit(actor.Id, actor.Role, "account.passwordChanged", user.Id);
            return Success();
        }, commitCredentialFailure: true);

    /// <summary>Reads bounded identity-store audit events for an Administrator. It does not combine independently committed controller events.</summary>
    public async Task<IReadOnlyList<IdentityAuditEntry>> ReadIdentityAuditAsync(ClaimsPrincipal principal)
    {
        context.ChangeTracker.Clear();
        _ = await ActorAsync(principal, true);
        var entries = await context.Set<IdentityAudit>().AsNoTracking().OrderByDescending(e => e.Sequence).Take(100).ToArrayAsync();
        return Array.AsReadOnly(entries.Select(e => new IdentityAuditEntry(e.Sequence, ReadTime(e.TimestampUtc)!.Value,
            e.ActorId, e.ActorRole, e.Action, e.Target)).ToArray());
    }

    private async Task<LocalProvisionResult> MutateAsync(ClaimsPrincipal principal, bool administrator,
        Func<AccountActor, Task<LocalProvisionResult>> operation, bool commitCredentialFailure = false)
    {
        context.ChangeTracker.Clear();
        try
        {
            await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
            AccountConnectionPolicy.RequireSchema(context.Database.GetDbConnection(), transaction.GetDbTransaction());
            var actor = await ActorAsync(principal, administrator);
            var result = await operation(actor);
            if (result.Succeeded || (commitCredentialFailure && result.ErrorCodes.Contains("account.credentialsDenied")))
            {
                await context.SaveChangesAsync(CancellationToken.None);
                await transaction.CommitAsync(CancellationToken.None);
            }
            return result;
        }
        catch (Exception error) when (error is SqliteException or DbUpdateException)
        { throw new AccountStoreException("account.databaseError"); }
    }

    private async Task<AccountActor> ActorAsync(ClaimsPrincipal principal, bool administrator)
    {
        ArgumentNullException.ThrowIfNull(principal);
        var id = principal.FindFirstValue(ControllerActorIdentity.ActorClaimType);
        var role = principal.FindFirstValue(ClaimTypes.Role);
        if (principal.Identity?.IsAuthenticated != true || !ControllerActorIdentity.IsValid(id) || !NergalRoles.IsDefined(role) ||
            principal.FindAll(ClaimTypes.Role).Count() != 1 || principal.FindAll(ControllerActorIdentity.ActorClaimType).Count() != 1 ||
            (administrator && role != NergalRoles.Administrator)) { throw new AccountStoreException("account.denied"); }
        if (id!.StartsWith("local:", StringComparison.Ordinal))
        {
            var user = await signIn.ValidateSecurityStampAsync(principal);
            if (user is null) { throw new AccountStoreException("account.denied"); }
            RequireSupported(user);
            if (!(await StateAsync(user.Id)).Enabled || ControllerActorIdentity.FromLocalAccount(Guid.Parse(user.Id)) != id ||
                await ResolveValidatedRoleAsync(users, user) != role || !await ValidLocalMfaSessionAsync(principal)) { throw new AccountStoreException("account.denied"); }
            return new(id, role!, user.UserName!, Guid.Parse(user.Id));
        }
        if (id.StartsWith("ldap:", StringComparison.Ordinal))
        {
            var session = await ReadCurrentLdapSessionAsync(principal);
            if (session is null) { throw new AccountStoreException("account.denied"); }
            return new(id, session.Role, session.Name, null);
        }
        if (id.StartsWith("oauth:", StringComparison.Ordinal))
        { return await ReadCurrentOAuthActorAsync(principal) ?? throw new AccountStoreException("account.denied"); }

        // The web handler validates the OIDC protocol and its session registration.
        var assurance = principal.FindAll("nergal.oidc-mfa-assured").Take(2).ToArray();
        if (assurance.Length > 1 || assurance.Length == 1 && assurance[0].Value is not ("true" or "false"))
        { throw new AccountStoreException("account.denied"); }

        var mfaGeneration = await ReadOidcMfaGenerationAsync(role, assurance.SingleOrDefault()?.Value == "true");
        var ticketGeneration = principal.FindFirstValue("nergal.oidc-mfa-generation");
        if (mfaGeneration is null || (ticketGeneration ?? "1") != mfaGeneration.Value.ToString(CultureInfo.InvariantCulture))
        { throw new AccountStoreException("account.denied"); }
        var issuer = principal.FindFirstValue("iss");
        var subject = principal.FindFirstValue("sub");
        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject))
        { throw new AccountStoreException("account.denied"); }

        var connectionGeneration = principal.FindFirstValue("nergal.oidc-generation");
        if (connectionGeneration is null ? assurance.Length != 0 :
            !await IsCurrentOidcGenerationAsync(connectionGeneration, issuer))
        { throw new AccountStoreException("account.denied"); }

        try
        {
            if (id != ControllerActorIdentity.FromFederatedAccount(issuer, subject))
            { throw new AccountStoreException("account.denied"); }
        }
        catch (ArgumentException) { throw new AccountStoreException("account.denied"); }
        return new(id, role!, principal.Identity.Name ?? "", null);
    }

    private async Task<LocalAccountState> StateAsync(string id)
    {
        var state = await context.Set<LocalAccountState>().SingleOrDefaultAsync(s => s.UserId == id)
            ?? throw new AccountStoreException("account.corrupt");
        if (state.Version < 1) { throw new AccountStoreException("account.corrupt"); }
        _ = ReadTime(state.CreatedUtc) ?? throw new AccountStoreException("account.corrupt");
        _ = ReadTime(state.UpdatedUtc) ?? throw new AccountStoreException("account.corrupt");
        return state;
    }

    private async Task RotateAsync(LocalAdministrator user, LocalAccountState state)
    {
        if (!(await users.UpdateSecurityStampAsync(user)).Succeeded) { throw new AccountStoreException("account.revokeFailed"); }
        state.Version = checked(state.Version + 1); state.UpdatedUtc = Now();
    }

    private void Audit(string actor, string role, string action, string target) => context.Add(new IdentityAudit
    { TimestampUtc = Now(), ActorId = actor, ActorRole = role, Action = action, Target = target });
    private string Now() => clock.GetUtcNow().UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
    private static DateTimeOffset? ReadTime(string? value) => value is null ? null :
        DateTime.TryParseExact(value, "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var time) && time.Kind == DateTimeKind.Utc
            ? new DateTimeOffset(time) : throw new AccountStoreException("account.corrupt");
    private static LocalProvisionResult Success() => new([]);
    private static LocalProvisionResult Failure(string code) => new([code]);
    private sealed record AccountActor(string Id, string Role, string Name, Guid? LocalId);
}
