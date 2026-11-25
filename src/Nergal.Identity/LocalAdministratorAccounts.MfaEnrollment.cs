using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace Nergal.Identity;

public sealed partial class LocalAdministratorAccounts
{
    private static readonly TimeSpan EnrollmentLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan AttemptWindow = TimeSpan.FromMinutes(15);
    private const int ActorAttemptLimit = 5;

    /// <summary>Reports verified enrollment only for the current authorized actor. No seed is returned.</summary>
    public async Task<bool> HasTotpAsync(ClaimsPrincipal principal)
    {
        context.ChangeTracker.Clear();
        var actor = await ActorAsync(principal, false);
        return await ReadMfaActorStateAsync(actor.Id) is { LastAcceptedStep: >= 0 };
    }

    /// <summary>Creates a short-lived enrollment for the signed-in local or LDAP actor. Existing verified factors cannot be replaced.</summary>
    public Task<TotpEnrollment?> BeginTotpEnrollmentAsync(ClaimsPrincipal principal, IDataProtectionProvider keys)
        => WithCredentialTransactionAsync<TotpEnrollment?>(async () =>
        {
            var actor = await ActorAsync(principal, false);
            var policy = await CurrentMfaPolicyAsync();
            if (!CanEnroll(actor, policy)) { return null; }
            var state = await GetMfaActorStateAsync(actor.Id);
            var now = clock.GetUtcNow();
            if (state.LastAcceptedStep >= 0 || AttemptsExhausted(state, now)) { return null; }
            var seed = RandomNumberGenerator.GetBytes(Totp.SeedLength);
            try
            {
                state.EnrollmentId = Guid.NewGuid().ToString("N");
                state.ProtectedSeed = SeedProtector(state, keys).Protect(seed);
                state.EnrollmentPolicyVersion = policy.Version;
                state.EnrollmentAuthority = await EnrollmentAuthorityAsync(actor, principal);
                state.EnrollmentEndsUtcTicks = (now + EnrollmentLifetime).UtcTicks;
                Audit(actor.Id, actor.Role, "mfa.enrollmentStarted", actor.Id);
                return new TotpEnrollment(state.EnrollmentId, Totp.ManualKey(seed));
            }
            finally { CryptographicOperations.ZeroMemory(seed); }
        });

    /// <summary>Checks a current code against the actor's pending enrollment, consumes its step and revokes existing sessions in the same transaction.</summary>
    public Task<LocalProvisionResult> ConfirmTotpEnrollmentAsync(ClaimsPrincipal principal, string enrollmentId,
        string code, IDataProtectionProvider keys)
        => WithCredentialTransactionAsync(async () =>
        {
            var actor = await ActorAsync(principal, false);
            var policy = await CurrentMfaPolicyAsync();
            if (!CanEnroll(actor, policy)) { return Failure("mfa.enrollmentDenied"); }
            var state = await ReadMfaActorStateAsync(actor.Id);
            var now = clock.GetUtcNow();
            if (state is null || state.LastAcceptedStep >= 0 || string.IsNullOrEmpty(enrollmentId) ||
                state.EnrollmentId != enrollmentId || state.EnrollmentPolicyVersion != policy.Version ||
                state.EnrollmentEndsUtcTicks <= now.UtcTicks || state.EnrollmentEndsUtcTicks > (now + EnrollmentLifetime).UtcTicks ||
                AttemptsExhausted(state, now) || state.EnrollmentAuthority != await EnrollmentAuthorityAsync(actor, principal))
            { return Failure("mfa.enrollmentDenied"); }

            if (MatchTotp(state, keys, code, now, enrollment: true) is not { } step)
            {
                CountFailedAttempt(state, now);
                Audit(actor.Id, actor.Role, "mfa.enrollmentDenied", actor.Id);
                return Failure("mfa.enrollmentDenied");
            }
            state.LastAcceptedStep = step;
            state.EnrollmentEndsUtcTicks = 0;
            state.EnrollmentAuthority = "";
            ResetAttempts(state);
            if (actor.LocalId is { } id)
            {
                var user = (await users.FindByIdAsync(id.ToString("D")))!;
                await RotateAsync(user, await StateAsync(user.Id));
            }
            else { await RetireLdapSessionAsync(actor.Id); }
            Audit(actor.Id, actor.Role, TotpEnrolled, actor.Id);
            return Success();
        });

    // Account changes and explicit revocation advance the local management version.
    // LDAP binds enrollment to the already validated session so retired trust cannot activate a pending seed.
    private async Task<string> EnrollmentAuthorityAsync(AccountActor actor, ClaimsPrincipal principal)
        => actor.LocalId is { } id
            ? (await StateAsync(id.ToString("D"))).Version.ToString(CultureInfo.InvariantCulture)
            : LdapTokenDigest(principal.FindFirstValue(LdapSessionIdClaim) ?? throw new AccountStoreException("account.denied"));

    private static bool CanEnroll(AccountActor actor, MfaPolicySnapshot policy)
        => (actor.LocalId.HasValue || actor.Id.StartsWith("ldap:", StringComparison.Ordinal)) &&
            !RequiresMfa(policy.Requirement, actor.Role);

    private static IDataProtector SeedProtector(MfaActorState state, IDataProtectionProvider keys)
        => keys.CreateProtector("Nergal.Mfa.TotpSeed.v1", state.ActorId, state.EnrollmentId);

    private static byte[] OpenSeed(MfaActorState state, IDataProtectionProvider keys)
    {
        var seed = SeedProtector(state, keys).Unprotect(state.ProtectedSeed);
        if (seed.Length == Totp.SeedLength) { return seed; }
        CryptographicOperations.ZeroMemory(seed);
        throw new CryptographicException();
    }

    private static long? MatchTotp(MfaActorState state, IDataProtectionProvider keys, string code, DateTimeOffset now, bool enrollment)
    {
        var seed = OpenSeed(state, keys);
        try { return Totp.Match(seed, code, now, state.LastAcceptedStep, enrollment); }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }

    private static bool AttemptsExhausted(MfaActorState state, DateTimeOffset now)
        => state.FailedAttempts >= ActorAttemptLimit && state.AttemptWindowEndsUtcTicks > now.UtcTicks;

    private static void CountFailedAttempt(MfaActorState state, DateTimeOffset now)
    {
        if (state.AttemptWindowEndsUtcTicks <= now.UtcTicks)
        {
            state.FailedAttempts = 0;
            state.AttemptWindowEndsUtcTicks = (now + AttemptWindow).UtcTicks;
        }
        state.FailedAttempts++;
    }

    private static void ResetAttempts(MfaActorState state)
    {
        state.FailedAttempts = 0;
        state.AttemptWindowEndsUtcTicks = 0;
    }
}
