using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Nergal.Core.Identity;

namespace Nergal.Identity;

public sealed partial class LocalAdministratorAccounts
{
    private const int ProofAttemptLimit = 3;
    private static readonly TimeSpan PendingLifetime = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromMinutes(15);
    private const string ContinuationPurpose = "Nergal.Mfa.BrowserContinuation.v1";

    // Local principals remain private until the transaction commits and the backend emits the cookie.
    private sealed record SignInDecision(MfaSignInResult Result, ClaimsPrincipal? LocalPrincipal = null,
        EmailMfaDelivery? Delivery = null);
    private static readonly SignInDecision DeniedSignIn = new(new(MfaSignInStatus.Denied));

    /// <summary>Verifies local credentials and either commits a session or returns a pending protected continuation for the browser.</summary>
    public async Task<MfaSignInResult> BeginLocalSignInAsync(string username, string password, IDataProtectionProvider keys,
        CancellationToken token = default, IMfaEmailSender? sender = null)
    {
        if (!ValidCredentialInput(username, password, token)) { return DeniedSignIn.Result; }
        var decision = await WithCredentialTransactionAsync(async () =>
        {
            var user = await VerifyPasswordAsync(username, password);
            if (user is null) { return DeniedSignIn; }
            var proof = new MfaFirstFactor(ControllerActorIdentity.FromLocalAccount(Guid.Parse(user.Id)), user.UserName!,
                await ResolveValidatedRoleAsync(users, user), user.SecurityStamp!, 0, clock.GetUtcNow(),
                ProfileMetadata.Empty, []);
            return await ReserveMfaSignInAsync(proof, keys, user, sender is not null);
        }, token);
        if (!await DeliverSignInCodeAsync(decision, sender, token)) { return DeniedSignIn.Result; }
        return await IssueCommittedSessionAsync(decision);
    }

    // Directory I/O has completed. All further checks, including connection generation,
    // proof ordering and profile/session writes, share the local account transaction.
    internal async Task<MfaSignInResult> BeginMfaSignInAsync(MfaFirstFactor proof, IDataProtectionProvider keys,
        CancellationToken token, IMfaEmailSender? sender = null)
    {
        var decision = await WithCredentialTransactionAsync(async () =>
        {
            if (!proof.ActorId.StartsWith("ldap:", StringComparison.Ordinal) || !await CheckLdapProofAsync(proof))
            { return DeniedSignIn; }
            return await ReserveMfaSignInAsync(proof, keys, null, sender is not null);
        }, token);
        return await DeliverSignInCodeAsync(decision, sender, token) ? decision.Result : DeniedSignIn.Result;
    }

    private async Task<SignInDecision> ReserveMfaSignInAsync(MfaFirstFactor proof, IDataProtectionProvider keys,
        LocalAdministrator? local, bool senderAvailable)
    {
        var now = clock.GetUtcNow();
        if (!FreshProof(proof, now)) { return DeniedSignIn; }
        var policy = await CurrentMfaPolicyAsync();
        var state = await GetMfaActorStateAsync(proof.ActorId);
        // Directory binds happen outside this transaction. Ties cannot establish their order.
        // Local password checks are already serialized and can share a coarse clock tick.
        if (state.LatestProofUtcTicks > proof.VerifiedAtUtc.UtcTicks ||
            local is null && state.LatestProofUtcTicks == proof.VerifiedAtUtc.UtcTicks) { return DeniedSignIn; }
        state.LatestProofUtcTicks = proof.VerifiedAtUtc.UtcTicks;
        var pending = await context.Set<MfaPendingProof>().SingleOrDefaultAsync(row => row.ActorId == proof.ActorId);
        var hasTotp = state.LastAcceptedStep >= 0;
        var email = hasTotp ? null : await ReadEmailMfaActorStateAsync(proof.ActorId);
        var usesEmail = email is { AddressId.Length: > 0 };
        if ((!hasTotp && !usesEmail) || AttemptsExhausted(state, now))
        {
            if (pending is not null) { context.Remove(pending); }
            if (hasTotp || usesEmail || RequiresMfa(policy.Requirement, proof.Role))
            {
                Audit(proof.ActorId, proof.Role, "mfa.denied", proof.ActorId);
                return DeniedSignIn;
            }
            return await RecordSessionAsync(proof, policy, local);
        }

        var id = Guid.NewGuid().ToString("N");
        var expiresUtc = proof.VerifiedAtUtc + PendingLifetime;
        EmailMfaDelivery? delivery = null;
        if (usesEmail)
        {
            if (!senderAvailable || await EnabledEmailDeliveryGenerationAsync() is not { } generation ||
                !TryReserveEmailSend(email!, now))
            {
                if (pending is not null) { context.Remove(pending); }
                Audit(proof.ActorId, proof.Role, "mfa.denied", proof.ActorId);
                return DeniedSignIn;
            }
            var address = OpenVerifiedEmailAddress(email!, keys);
            (_, delivery) = await ReserveEmailCodeAsync(proof.ActorId, EmailMfaStage.SignIn, policy.Version, generation,
                id, expiresUtc, address, keys);
        }

        pending ??= context.Add(new MfaPendingProof { ActorId = proof.ActorId }).Entity;
        pending.Id = id;
        pending.PolicyVersion = policy.Version;
        pending.FailedAttempts = 0;
        pending.UsesEmail = usesEmail;
        pending.ProtectedProof = PendingProtector(pending, state, keys).Protect(JsonSerializer.Serialize(proof));
        var continuation = keys.CreateProtector(ContinuationPurpose).Protect(pending.Id);
        Audit(proof.ActorId, proof.Role, "mfa.challenged", proof.ActorId);
        return new(new(MfaSignInStatus.Challenge, continuation, ExpiresUtc: expiresUtc), Delivery: delivery);
    }

    private static async Task<bool> DeliverSignInCodeAsync(SignInDecision decision, IMfaEmailSender? sender, CancellationToken token)
        => decision.Delivery is not { } delivery || sender is not null && await TryDeliverEmailCodeAsync(sender, delivery, token);

    /// <summary>Consumes a browser continuation and its factor after rechecking authority, ordering and delivery generation under a write reservation.</summary>
    /// <remarks>The host transports the continuation in a short-lived host-only HttpOnly Secure cookie. A continuation grants no application access. Completion performs no delivery.</remarks>
    public async Task<MfaSignInResult> CompleteMfaSignInAsync(string continuation, string code, IDataProtectionProvider keys,
        CancellationToken token = default, IMfaEmailSender? sender = null)
    {
        token.ThrowIfCancellationRequested();
        if (continuation is not { Length: > 0 and <= 4096 }) { return DeniedSignIn.Result; }
        string id;
        try { id = keys.CreateProtector(ContinuationPurpose).Unprotect(continuation); }
        catch (Exception error) when (error is CryptographicException or FormatException) { return DeniedSignIn.Result; }
        if (!Guid.TryParseExact(id, "N", out _)) { return DeniedSignIn.Result; }

        var decision = await WithCredentialTransactionAsync(async () =>
        {
            var pending = await context.Set<MfaPendingProof>().SingleOrDefaultAsync(row => row.Id == id);
            if (pending is null) { return DeniedSignIn; }
            var policy = await CurrentMfaPolicyAsync();
            var state = await ReadMfaActorStateAsync(pending.ActorId);
            // A TOTP activation retires email continuations. Withdrawing or losing an authenticator
            // cannot convert a TOTP continuation into an email continuation.
            if (pending.PolicyVersion != policy.Version || state is null || pending.UsesEmail == (state.LastAcceptedStep >= 0))
            {
                context.Remove(pending);
                return DeniedSignIn;
            }

            MfaFirstFactor proof;
            try
            {
                var payload = PendingProtector(pending, state, keys).Unprotect(pending.ProtectedProof);
                proof = JsonSerializer.Deserialize<MfaFirstFactor>(payload) ?? throw new JsonException();
            }
            catch (Exception error) when (error is CryptographicException or FormatException or JsonException)
            { throw new AccountStoreException("mfa.proofUnavailable"); }
            var now = clock.GetUtcNow();
            if (proof.ActorId != pending.ActorId || proof.VerifiedAtUtc.UtcTicks != state.LatestProofUtcTicks ||
                !FreshProof(proof, now) || pending.FailedAttempts >= ProofAttemptLimit || AttemptsExhausted(state, now))
            {
                context.Remove(pending);
                return DeniedSignIn;
            }

            LocalAdministrator? local = null;
            if (proof.ActorId.StartsWith("local:", StringComparison.Ordinal))
            {
                local = await users.FindByIdAsync(proof.ActorId["local:".Length..]);
                if (local is null || !await LocalProofCurrentAsync(local, proof))
                {
                    context.Remove(pending);
                    return DeniedSignIn;
                }
            }
            else if (!await CheckLdapProofAsync(proof))
            {
                context.Remove(pending);
                return DeniedSignIn;
            }

            EmailMfaCode? emailCode = null;
            bool accepted;
            if (pending.UsesEmail)
            {
                emailCode = await ReadEmailCodeAsync(proof.ActorId, EmailMfaStage.SignIn);
                if (emailCode is null || emailCode.Binding != pending.Id ||
                    await ReadEmailMfaActorStateAsync(proof.ActorId) is not { AddressId.Length: > 0 } ||
                    !await EmailCodeCurrentAsync(emailCode, policy.Version, now))
                {
                    context.Remove(pending);
                    return DeniedSignIn;
                }
                accepted = MatchesEmailCode(emailCode, keys, code);
            }
            else
            {
                var step = MatchTotp(state, keys, code, now, enrollment: false);
                accepted = step.HasValue;
                if (step is { } acceptedStep) { state.LastAcceptedStep = acceptedStep; }
            }
            if (!accepted)
            {
                CountFailedAttempt(state, now);
                pending.FailedAttempts++;
                Audit(proof.ActorId, proof.Role, "mfa.denied", proof.ActorId);
                if (pending.FailedAttempts == ProofAttemptLimit || AttemptsExhausted(state, now))
                {
                    if (emailCode is not null) { context.Remove(emailCode); }
                    context.Remove(pending);
                    return DeniedSignIn;
                }
                return new SignInDecision(new(MfaSignInStatus.Challenge, continuation, ExpiresUtc: proof.VerifiedAtUtc + PendingLifetime));
            }

            if (emailCode is not null) { context.Remove(emailCode); }
            ResetAttempts(state);
            context.Remove(pending);
            return await RecordSessionAsync(proof, policy, local);
        }, token);
        return await IssueCommittedSessionAsync(decision);
    }

    private static bool FreshProof(MfaFirstFactor proof, DateTimeOffset now)
        => proof.VerifiedAtUtc <= now && now - proof.VerifiedAtUtc < PendingLifetime;

    private static IDataProtector PendingProtector(MfaPendingProof pending, MfaActorState state, IDataProtectionProvider keys)
        => keys.CreateProtector("Nergal.Mfa.PendingFirstFactor.v2", state.ActorId, pending.Id,
            pending.UsesEmail ? "Email" : "Totp:" + state.EnrollmentId,
            pending.PolicyVersion.ToString(CultureInfo.InvariantCulture));

    private async Task<bool> LocalProofCurrentAsync(LocalAdministrator user, MfaFirstFactor proof)
    {
        RequireSupported(user);
        return proof.LocalStamp == user.SecurityStamp && proof.Name == user.UserName &&
            (await StateAsync(user.Id)).Enabled && !await users.IsLockedOutAsync(user) &&
            proof.Role == await ResolveValidatedRoleAsync(users, user);
    }

    private async Task<SignInDecision> RecordSessionAsync(MfaFirstFactor proof, MfaPolicySnapshot policy, LocalAdministrator? local)
    {
        var expires = proof.VerifiedAtUtc + SessionLifetime;
        if (local is null)
        {
            var principal = await RecordLdapSignInAsync(proof, policy.Version, expires);
            return new(new(MfaSignInStatus.SignedIn, LdapPrincipal: principal, ExpiresUtc: expires));
        }

        // A new local session supersedes previous tickets without changing the account management version.
        if (!(await users.UpdateSecurityStampAsync(local)).Succeeded) { throw new AccountStoreException("account.revokeFailed"); }
        var localPrincipal = await signIn.CreateUserPrincipalAsync(local);
        ((ClaimsIdentity)localPrincipal.Identity!).AddClaim(new(MfaGenerationClaim, policy.Version.ToString(CultureInfo.InvariantCulture)));
        Audit(proof.ActorId, proof.Role, "local.signedIn", proof.ActorId);
        return new(new(MfaSignInStatus.SignedIn, ExpiresUtc: expires), localPrincipal);
    }

    private async Task<MfaSignInResult> IssueCommittedSessionAsync(SignInDecision decision)
    {
        if (decision.LocalPrincipal is { } principal)
        {
            await signIn.Context.SignInAsync(signIn.AuthenticationScheme, principal, new AuthenticationProperties
            {
                IsPersistent = false,
                AllowRefresh = false,
                ExpiresUtc = decision.Result.ExpiresUtc
            });
            signIn.Context.User = principal;
        }
        return decision.Result;
    }
}
