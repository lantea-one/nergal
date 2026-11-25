using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Nergal.Core.Identity;

namespace Nergal.Identity;

public sealed partial class LocalAdministratorAccounts
{
    private const string MfaGenerationClaim = "nergal.mfa-generation";
    private const string PolicyChanged = "mfa.policyChanged";
    private const string TotpEnrolled = "mfa.totpEnrolled";

    /// <summary>Reads the current local MFA policy under local Administrator authority.</summary>
    public async Task<MfaPolicySnapshot> ReadMfaPolicyAsync(ClaimsPrincipal principal)
    {
        context.ChangeTracker.Clear();
        if ((await ActorAsync(principal, true)).LocalId is null)
        { throw new AccountStoreException("provider.localAdministratorRequired"); }
        return await CurrentMfaPolicyAsync();
    }

    /// <summary>Changes the expected policy version and audit together. Enforcement requires a local Administrator who can currently sign in with TOTP.</summary>
    public Task<LocalProvisionResult> SaveMfaPolicyAsync(ClaimsPrincipal principal, long expectedVersion,
        MfaRequirement requirement, IDataProtectionProvider keys)
        => MutateAsync(principal, true, async actor =>
        {
            if (actor.LocalId is null) { return Failure("provider.localAdministratorRequired"); }
            if (!Enum.IsDefined(requirement)) { return Failure("mfa.invalidPolicy"); }
            var current = await CurrentMfaPolicyAsync();
            if (current.Version != expectedVersion) { return Failure("mfa.stale"); }
            if (current.Requirement == requirement) { return Success(); }
            if (RequiresMfa(requirement, NergalRoles.Administrator) && !await HasRecoveryAdministratorAsync(keys, requirement))
            { return Failure("account.lastAdministrator"); }
            var row = await context.Set<MfaPolicy>().SingleAsync();
            row.Version = checked(row.Version + 1);
            row.Requirement = requirement;
            Audit(actor.Id, actor.Role, PolicyChanged, requirement.ToString());
            return Success();
        });

    private async Task<MfaPolicySnapshot> CurrentMfaPolicyAsync()
    {
        // The seed has generation one. Each later generation has exactly one policy event.
        // Read the last audited requirement and count with the row in one SQLite snapshot.
        var changes = context.Set<IdentityAudit>().Where(entry => entry.Action == PolicyChanged);
        var rows = await context.Set<MfaPolicy>().AsNoTracking().Select(row => new
        {
            row.Id,
            row.Version,
            row.Requirement,
            Changes = changes.LongCount(),
            Last = changes.OrderByDescending(entry => entry.Sequence).Select(entry => entry.Target).FirstOrDefault()
        }).Take(2).ToArrayAsync();
        if (rows.Length != 1) { throw new AccountStoreException("account.corrupt"); }
        var policy = rows[0];
        if (policy.Id != 1 || !Enum.IsDefined(policy.Requirement) || policy.Version is < 1 or >= long.MaxValue ||
            policy.Version - 1 != policy.Changes || (policy.Last ?? nameof(MfaRequirement.Optional)) != policy.Requirement.ToString())
        { throw new AccountStoreException("account.corrupt"); }
        return new(policy.Version, policy.Requirement);
    }

    private static bool RequiresMfa(MfaRequirement requirement, string role)
        => requirement == MfaRequirement.All || (requirement == MfaRequirement.Administrators && role == NergalRoles.Administrator);

    private async Task<bool> HasRecoveryAdministratorAsync(IDataProtectionProvider? keys, MfaRequirement requirement,
        string? excludedUserId = null)
    {
        var now = clock.GetUtcNow();
        foreach (var account in await users.Users.AsNoTracking().ToArrayAsync())
        {
            if (account.Id == excludedUserId) { continue; }
            RequireSupported(account);
            if (!(await StateAsync(account.Id)).Enabled ||
                await ResolveValidatedRoleAsync(users, account) != NergalRoles.Administrator ||
                await users.IsLockedOutAsync(account)) { continue; }

            var actorId = ControllerActorIdentity.FromLocalAccount(Guid.Parse(account.Id));
            var state = await ReadMfaActorStateAsync(actorId);
            if (state is not null && AttemptsExhausted(state, now)) { continue; }
            if (state is { LastAcceptedStep: >= 0 })
            {
                if (keys is not null && HasUsableLocalTotp(state, keys)) { return true; }
                continue;
            }

            // Optional policy permits password-only recovery when no factor has been activated.
            if (!RequiresMfa(requirement, NergalRoles.Administrator) &&
                await ReadEmailMfaActorStateAsync(actorId) is not { AddressId.Length: > 0 }) { return true; }
        }
        return false;
    }

    private async Task<bool> HasUsableLocalMfaAsync(string userId, IDataProtectionProvider keys)
    {
        var user = await users.FindByIdAsync(userId);
        if (user is null || await users.IsLockedOutAsync(user)) { return false; }
        var actorId = ControllerActorIdentity.FromLocalAccount(Guid.Parse(userId));
        var state = await ReadMfaActorStateAsync(actorId);
        return state is { LastAcceptedStep: >= 0 } && !AttemptsExhausted(state, clock.GetUtcNow()) &&
            HasUsableLocalTotp(state, keys);
    }

    private static bool HasUsableLocalTotp(MfaActorState state, IDataProtectionProvider keys)
    {
        // Recovery must survive a disabled delivery configuration or an unavailable SMTP peer.
        try
        {
            var seed = OpenSeed(state, keys);
            CryptographicOperations.ZeroMemory(seed);
            return true;
        }
        catch (CryptographicException) { return false; }
    }

    private async Task<bool> ValidLocalMfaSessionAsync(ClaimsPrincipal principal)
    {
        var policy = await CurrentMfaPolicyAsync();
        var claims = principal.FindAll(MfaGenerationClaim).Take(2).ToArray();
        if (claims.Length == 1) { return claims[0].Value == policy.Version.ToString(CultureInfo.InvariantCulture); }
        // Legacy directly constructed verification principals are only meaningful in a pristine optional installation.
        return claims.Length == 0 && policy is { Version: 1, Requirement: MfaRequirement.Optional } &&
            !await context.Set<IdentityAudit>().AnyAsync(entry => entry.Action == TotpEnrolled || entry.Action == EmailEnrolled) &&
            !await context.Set<MfaActorState>().AnyAsync(row => row.LastAcceptedStep >= 0) &&
            !await context.Set<EmailMfaActorState>().AnyAsync(row => row.AddressId != "");
    }

    private async Task<MfaActorState?> ReadMfaActorStateAsync(string actorId)
    {
        // A concurrent enrollment must expose both its row and its audit (or neither).
        var events = context.Database.SqlQuery<long>(
            $"SELECT count(*) AS Value FROM IdentityAudit WHERE ActorId = {actorId} AND Action = {TotpEnrolled}");
        var observation = await (from count in events
                                 from row in context.Set<MfaActorState>().Where(state => state.ActorId == actorId).DefaultIfEmpty()
                                 select new { Count = count, Row = row }).SingleAsync();
        if (observation.Count != (observation.Row is { LastAcceptedStep: >= 0 } ? 1 : 0))
        { throw new AccountStoreException("account.corrupt"); }
        return observation.Row;
    }

    private async Task<MfaActorState> GetMfaActorStateAsync(string actorId)
    {
        var state = await ReadMfaActorStateAsync(actorId);
        return state ?? context.Add(new MfaActorState { ActorId = actorId }).Entity;
    }
}
