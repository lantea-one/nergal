using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Nergal.Core.Identity;

namespace Nergal.Identity;

public sealed partial class LocalAdministratorAccounts
{
    private const string OfflineIssuer = "operator:offline";
    private const string RecoveryPurpose = "Nergal.Mfa.RecoveryConfirmation.v1";
    private static readonly TimeSpan RecoveryLifetime = TimeSpan.FromMinutes(10);

    /// <summary>Replaces any outstanding authorization for this exact local or observed LDAP actor under current local Administrator authority.</summary>
    public Task<RecoveryAuthorization?> IssueRecoveryAsync(ClaimsPrincipal principal, string actorId, long policyVersion)
        => WithCredentialTransactionAsync<RecoveryAuthorization?>(async () =>
        {
            if (principal.Identity?.AuthenticationType != IdentityConstants.ApplicationScheme)
            { throw new AccountStoreException("account.denied"); }
            var issuer = await ActorAsync(principal, true);
            if (issuer.LocalId is not { } id) { throw new AccountStoreException("account.denied"); }
            var policy = await CurrentMfaPolicyAsync();
            if (policy.Version != policyVersion) { return null; }
            return await IssueRecoveryGrantAsync(actorId, issuer.Id, (await StateAsync(id.ToString("D"))).Version, policy);
        });

    /// <summary>Protected operator command for a local Administrator who has lost the last usable authenticator.</summary>
    /// <remarks>Access to the owner-only identity database is the offline authority. Never expose this operation as an HTTP endpoint.</remarks>
    public Task<RecoveryAuthorization?> IssueOfflineAdministratorRecoveryAsync(Guid accountId)
        => WithCredentialTransactionAsync<RecoveryAuthorization?>(async () =>
        {
            if (accountId == Guid.Empty || await users.FindByIdAsync(accountId.ToString("D")) is not { } user ||
                await ResolveValidatedRoleAsync(users, user) != NergalRoles.Administrator) { return null; }
            return await IssueRecoveryGrantAsync(ControllerActorIdentity.FromLocalAccount(accountId), OfflineIssuer, 0,
                await CurrentMfaPolicyAsync());
        });

    private async Task<RecoveryAuthorization?> IssueRecoveryGrantAsync(string actorId, string issuer, long issuerVersion,
        MfaPolicySnapshot policy)
    {
        if (!ControllerActorIdentity.IsValid(actorId)) { return null; }
        long trustVersion;
        var stamp = "";
        MfaActorState state;
        if (actorId.StartsWith("local:", StringComparison.Ordinal))
        {
            var user = await users.FindByIdAsync(actorId["local:".Length..]);
            if (user is null) { return null; }
            RequireSupported(user);
            var account = await StateAsync(user.Id);
            if (!account.Enabled) { return null; }
            trustVersion = account.Version;
            stamp = user.SecurityStamp!;
            state = await GetMfaActorStateAsync(actorId);
        }
        else
        {
            if (!actorId.StartsWith("ldap:", StringComparison.Ordinal) ||
                await ReadLdapConnectionSnapshotAsync() is not { Settings.Enabled: true } connection ||
                !IsDirectoryActor(actorId, connection.DirectoryId) ||
                await ReadMfaActorStateAsync(actorId) is not { } observed) { return null; }
            trustVersion = connection.Version;
            state = observed;
        }

        var grant = await context.Set<RecoveryGrant>().FindAsync(actorId) ??
            context.Add(new RecoveryGrant { ActorId = actorId }).Entity;
        var secret = NewRecoveryBearer();
        var now = clock.GetUtcNow();
        grant.Issuer = issuer;
        grant.IssuerVersion = issuerVersion;
        grant.PolicyVersion = policy.Version;
        grant.TrustVersion = trustVersion;
        grant.LocalStamp = stamp;
        grant.Watermark = state.LatestProofUtcTicks;
        grant.Digest = LdapTokenDigest(secret);
        grant.IssuedUtcTicks = now.UtcTicks;
        grant.ExpiresUtcTicks = (now + RecoveryLifetime).UtcTicks;
        grant.Attempts = 0;
        grant.Role = "";
        grant.EnrollmentId = "";
        grant.ProtectedSeed = [];
        Audit(issuer, issuer == OfflineIssuer ? "operator" : NergalRoles.Administrator, "mfa.recoveryIssued", actorId);
        return new(secret, now + RecoveryLifetime);
    }

    private static string NewRecoveryBearer() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    // Called under the credential write reservation on both sides of any directory I/O.
    private async Task<RecoveryGrant?> CurrentRecoveryGrantAsync(string bearer, bool confirmation)
    {
        if (bearer is not { Length: 64 } || !bearer.All(char.IsAsciiHexDigit)) { return null; }
        var digest = LdapTokenDigest(bearer);
        var grant = await context.Set<RecoveryGrant>().SingleOrDefaultAsync(row => row.Digest == digest);
        var now = clock.GetUtcNow().UtcTicks;
        if (grant is null || (grant.EnrollmentId.Length != 0) != confirmation ||
            grant.IssuedUtcTicks > now || grant.ExpiresUtcTicks <= now ||
            grant.ExpiresUtcTicks - grant.IssuedUtcTicks > (confirmation ? PendingLifetime : RecoveryLifetime).Ticks ||
            (await CurrentMfaPolicyAsync()).Version != grant.PolicyVersion ||
            (await ReadMfaActorStateAsync(grant.ActorId))?.LatestProofUtcTicks != grant.Watermark)
        { return null; }

        if (grant.Issuer != OfflineIssuer)
        {
            if (!ControllerActorIdentity.IsValid(grant.Issuer) || !grant.Issuer.StartsWith("local:", StringComparison.Ordinal) ||
                await users.FindByIdAsync(grant.Issuer["local:".Length..]) is not { } issuer ||
                await ResolveValidatedRoleAsync(users, issuer) != NergalRoles.Administrator ||
                await StateAsync(issuer.Id) is not { Enabled: true } issuerState || issuerState.Version != grant.IssuerVersion)
            { return null; }
            RequireSupported(issuer);
        }

        if (!ControllerActorIdentity.IsValid(grant.ActorId)) { return null; }
        if (grant.ActorId.StartsWith("local:", StringComparison.Ordinal))
        {
            if (await users.FindByIdAsync(grant.ActorId["local:".Length..]) is not { } user) { return null; }
            RequireSupported(user);
            var account = await StateAsync(user.Id);
            return account.Enabled && account.Version == grant.TrustVersion && user.SecurityStamp == grant.LocalStamp &&
                !await users.IsLockedOutAsync(user) ? grant : null;
        }
        return grant.Issuer != OfflineIssuer && await ReadLdapConnectionSnapshotAsync() is { Settings.Enabled: true } connection &&
            connection.Version == grant.TrustVersion && IsDirectoryActor(grant.ActorId, connection.DirectoryId) ? grant : null;
    }

    /// <summary>Verifies the target local account's current password with ordinary lockout accounting. Returns only a staged authenticator.</summary>
    public Task<RecoverySetup?> BeginLocalRecoveryAsync(string authorization, string username, string password,
        IDataProtectionProvider keys, CancellationToken token = default)
        => WithCredentialTransactionAsync<RecoverySetup?>(async () =>
        {
            if (!ValidCredentialInput(username, password, token) ||
                await CurrentRecoveryGrantAsync(authorization, false) is not { } grant ||
                !grant.ActorId.StartsWith("local:", StringComparison.Ordinal) || grant.Attempts >= ProofAttemptLimit)
            { return null; }
            grant.Attempts++;
            var target = await users.FindByIdAsync(grant.ActorId["local:".Length..]);
            if (target?.NormalizedUserName != users.NormalizeName(username) || await VerifyPasswordAsync(username, password) is not { } user ||
                ControllerActorIdentity.FromLocalAccount(Guid.Parse(user.Id)) != grant.ActorId) { return null; }
            // Identity can rehash a valid password and update the security stamp during verification.
            grant.LocalStamp = user.SecurityStamp!;
            return StageRecovery(grant, await ResolveValidatedRoleAsync(users, user), clock.GetUtcNow(), keys);
        }, token);

    /// <summary>Verifies fresh credentials against the rendered LDAP generation and matches its immutable actor before staging setup.</summary>
    public async Task<RecoverySetup?> BeginLdapRecoveryAsync(string authorization, long generation, string username, string password,
        IDataProtectionProvider keys, CancellationToken token = default)
    {
        if (generation < 1 || !LdapUserLookup.IsValidUsername(username) || !LdapDirectoryAuthenticator.ValidPassword(password))
        { return null; }
        var reserved = await WithCredentialTransactionAsync(async () =>
        {
            if (await CurrentRecoveryGrantAsync(authorization, false) is not { } grant ||
                !grant.ActorId.StartsWith("ldap:", StringComparison.Ordinal) || grant.TrustVersion != generation ||
                grant.Attempts >= ProofAttemptLimit) { return false; }
            grant.Attempts++;
            return true;
        }, token);
        if (!reserved) { return null; }

        var runtime = await ReadLdapRuntimeAsync(generation, keys);
        if (runtime is null) { return null; }
        var proof = await new LdapDirectoryAuthenticator(clock).VerifyAsync(runtime.Directory, runtime.DialAddress,
            runtime.SearchPassword, username, password, token);
        if (proof is null) { return null; }

        return await WithCredentialTransactionAsync<RecoverySetup?>(async () =>
        {
            var grant = await CurrentRecoveryGrantAsync(authorization, false);
            var now = clock.GetUtcNow();
            if (grant is null || grant.ActorId != proof.ActorId || grant.TrustVersion != generation ||
                proof.VerifiedAtUtc.UtcTicks < grant.IssuedUtcTicks || proof.VerifiedAtUtc.UtcTicks <= grant.Watermark ||
                proof.VerifiedAtUtc > now || now - proof.VerifiedAtUtc >= PendingLifetime) { return null; }
            return StageRecovery(grant, proof.Role, proof.VerifiedAtUtc, keys);
        }, token);
    }

    private RecoverySetup? StageRecovery(RecoveryGrant grant, string role, DateTimeOffset proofTime, IDataProtectionProvider keys)
    {
        if (proofTime.UtcTicks < grant.IssuedUtcTicks || clock.GetUtcNow().UtcTicks >= grant.ExpiresUtcTicks) { return null; }
        var seed = RandomNumberGenerator.GetBytes(Totp.SeedLength);
        try
        {
            var bearer = NewRecoveryBearer();
            grant.Digest = LdapTokenDigest(bearer);
            grant.Role = role;
            grant.EnrollmentId = Guid.NewGuid().ToString("N");
            var candidate = new MfaActorState { ActorId = grant.ActorId, EnrollmentId = grant.EnrollmentId };
            grant.ProtectedSeed = SeedProtector(candidate, keys).Protect(seed);
            grant.Attempts = 0;
            grant.IssuedUtcTicks = proofTime.UtcTicks;
            grant.ExpiresUtcTicks = Math.Min(grant.ExpiresUtcTicks, (proofTime + PendingLifetime).UtcTicks);
            Audit(grant.ActorId, role, "mfa.recoveryStarted", grant.ActorId);
            return new(Totp.ManualKey(seed), keys.CreateProtector(RecoveryPurpose).Protect(bearer),
                new DateTimeOffset(grant.ExpiresUtcTicks, TimeSpan.Zero));
        }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }

    /// <summary>Consumes the scoped confirmation and new TOTP step, installs the verified factor, revokes tickets and audits in one transaction.</summary>
    public async Task<bool> ConfirmRecoveryAsync(string continuation, string code, IDataProtectionProvider keys,
        CancellationToken token = default)
    {
        if (continuation is not { Length: > 0 and <= 4096 }) { return false; }
        string bearer;
        try { bearer = keys.CreateProtector(RecoveryPurpose).Unprotect(continuation); }
        catch (Exception error) when (error is CryptographicException or FormatException) { return false; }

        return await WithCredentialTransactionAsync(async () =>
        {
            var grant = await CurrentRecoveryGrantAsync(bearer, true);
            if (grant is null || grant.Attempts >= ProofAttemptLimit || !NergalRoles.IsDefined(grant.Role)) { return false; }
            var state = (await ReadMfaActorStateAsync(grant.ActorId))!;
            var candidate = new MfaActorState
            { ActorId = grant.ActorId, EnrollmentId = grant.EnrollmentId, ProtectedSeed = grant.ProtectedSeed };
            var now = clock.GetUtcNow();
            if (MatchTotp(candidate, keys, code, now, enrollment: true) is not { } step)
            {
                grant.Attempts++;
                Audit(grant.ActorId, grant.Role, "mfa.recoveryDenied", grant.ActorId);
                return false;
            }

            if (grant.ActorId.StartsWith("local:", StringComparison.Ordinal))
            {
                var user = (await users.FindByIdAsync(grant.ActorId["local:".Length..]))!;
                if (await ResolveValidatedRoleAsync(users, user) != grant.Role) { return false; }
                await RotateAsync(user, await StateAsync(user.Id));
                var pending = await context.Set<MfaPendingProof>().FindAsync(grant.ActorId);
                if (pending is not null) { context.Remove(pending); }
            }
            else { await RetireLdapSessionAsync(grant.ActorId); }

            await context.Set<EmailMfaCode>().Where(row => row.ActorId == grant.ActorId).ExecuteDeleteAsync();
            // The audit invariant requires one enrollment event for an active actor even after replacement.
            if (state.LastAcceptedStep < 0) { Audit(grant.ActorId, grant.Role, TotpEnrolled, grant.ActorId); }
            state.LastAcceptedStep = step;
            state.EnrollmentId = candidate.EnrollmentId;
            state.ProtectedSeed = candidate.ProtectedSeed;
            state.EnrollmentPolicyVersion = grant.PolicyVersion;
            state.EnrollmentAuthority = "";
            state.EnrollmentEndsUtcTicks = 0;
            state.LatestProofUtcTicks = Math.Max(state.LatestProofUtcTicks, now.UtcTicks);
            ResetAttempts(state);
            context.Remove(grant);
            Audit(grant.ActorId, grant.Role, "mfa.recovered", grant.ActorId);
            return true;
        }, token);
    }
}
