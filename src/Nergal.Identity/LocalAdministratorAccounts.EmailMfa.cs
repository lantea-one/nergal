using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Nergal.Core.Identity;

namespace Nergal.Identity;

public sealed partial class LocalAdministratorAccounts
{
    private const string EmailEnrolled = "mfa.emailEnrolled";
    private const int EmailSendLimit = 3;

    /// <summary>Reads enrollment state for the authenticated actor without exposing the verified address or sending mail.</summary>
    public Task<EmailMfaEnrollmentStatus> ReadEmailMfaEnrollmentAsync(ClaimsPrincipal principal, CancellationToken token = default)
        => WithCredentialTransactionAsync(async () =>
        {
            var actor = await ActorAsync(principal, false);
            var enrolled = await ReadEmailMfaActorStateAsync(actor.Id) is { AddressId.Length: > 0 };
            var canStart = !enrolled && CanEnroll(actor, await CurrentMfaPolicyAsync()) &&
                await EnabledEmailDeliveryGenerationAsync() is not null;
            return new EmailMfaEnrollmentStatus(enrolled, canStart);
        }, token);

    /// <summary>Reserves and sends an enrollment code for a mailbox explicitly supplied by the authenticated actor.</summary>
    /// <remarks>A pending address cannot satisfy MFA. Beginning again replaces the previous enrollment without replenishing its shared send or attempt budgets.</remarks>
    public async Task<EmailMfaEnrollment?> BeginEmailMfaEnrollmentAsync(ClaimsPrincipal principal, string address,
        IDataProtectionProvider keys, IMfaEmailSender sender, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(sender);
        token.ThrowIfCancellationRequested();
        if (!EmailDeliverySettings.IsMailbox(address)) { return null; }
        var reservation = await WithCredentialTransactionAsync<(EmailMfaEnrollment Enrollment, EmailMfaDelivery Delivery)?>(async () =>
        {
            var actor = await ActorAsync(principal, false);
            var policy = await CurrentMfaPolicyAsync();
            if (!CanEnroll(actor, policy) || await EnabledEmailDeliveryGenerationAsync() is not { } generation) { return null; }

            var state = await GetMfaActorStateAsync(actor.Id);
            var now = clock.GetUtcNow();
            if (AttemptsExhausted(state, now) || !await PreservesRecoveryOnEmailEnrollmentAsync(actor, keys)) { return null; }
            var email = await ReadEmailMfaActorStateAsync(actor.Id);
            if (email is { AddressId.Length: > 0 }) { return null; }
            email ??= context.Add(new EmailMfaActorState { ActorId = actor.Id }).Entity;
            if (!TryReserveEmailSend(email, now)) { return null; }

            var binding = await EmailEnrollmentBindingAsync(actor, principal);
            var (row, delivery) = await ReserveEmailCodeAsync(actor.Id, EmailMfaStage.Enrollment, policy.Version, generation,
                binding, now + PendingLifetime, address, keys);
            Audit(actor.Id, actor.Role, "mfa.emailEnrollmentStarted", actor.Id);
            return (new EmailMfaEnrollment(row.Id), delivery);
        }, token);
        if (reservation is not { } reserved || !await TryDeliverEmailCodeAsync(sender, reserved.Delivery, token))
        { return null; }
        return reserved.Enrollment;
    }

    /// <summary>Verifies and consumes an enrollment code, activates the address and revokes the actor's sessions atomically.</summary>
    public Task<LocalProvisionResult> ConfirmEmailMfaEnrollmentAsync(ClaimsPrincipal principal, string enrollmentId,
        string code, IDataProtectionProvider keys, CancellationToken token = default)
        => WithCredentialTransactionAsync(async () =>
        {
            var actor = await ActorAsync(principal, false);
            var policy = await CurrentMfaPolicyAsync();
            var state = await ReadMfaActorStateAsync(actor.Id);
            var email = await ReadEmailMfaActorStateAsync(actor.Id);
            var row = await ReadEmailCodeAsync(actor.Id, EmailMfaStage.Enrollment);
            var now = clock.GetUtcNow();
            if (!CanEnroll(actor, policy) || state is null || email is not { AddressId.Length: 0 } ||
                row is null || row.Id != enrollmentId || !await EmailCodeCurrentAsync(row, policy.Version, now) ||
                AttemptsExhausted(state, now) || row.Binding != await EmailEnrollmentBindingAsync(actor, principal))
            { return Failure("mfa.enrollmentDenied"); }
            if (!await PreservesRecoveryOnEmailEnrollmentAsync(actor, keys)) { return Failure("account.lastAdministrator"); }

            if (!MatchesEmailCode(row, keys, code))
            {
                CountFailedAttempt(state, now);
                row.FailedAttempts++;
                if (row.FailedAttempts >= ProofAttemptLimit || AttemptsExhausted(state, now)) { context.Remove(row); }
                Audit(actor.Id, actor.Role, "mfa.emailEnrollmentDenied", actor.Id);
                return Failure("mfa.enrollmentDenied");
            }

            var address = EmailCodeProtector(row, keys, "Address").Unprotect(row.ProtectedAddress);
            if (!EmailDeliverySettings.IsMailbox(address)) { throw new CryptographicException(); }
            email.AddressId = row.Id;
            email.ProtectedAddress = VerifiedEmailProtector(email, keys).Protect(address);
            context.Remove(row);
            ResetAttempts(state);
            if (actor.LocalId is { } id)
            {
                var user = (await users.FindByIdAsync(id.ToString("D")))!;
                await RotateAsync(user, await StateAsync(user.Id));
                var pending = await context.Set<MfaPendingProof>().SingleOrDefaultAsync(proof => proof.ActorId == actor.Id);
                if (pending is not null) { context.Remove(pending); }
            }
            else { await RetireLdapSessionAsync(actor.Id); }
            Audit(actor.Id, actor.Role, EmailEnrolled, actor.Id);
            return Success();
        }, token);

    private async Task<bool> PreservesRecoveryOnEmailEnrollmentAsync(AccountActor actor, IDataProtectionProvider keys)
    {
        if (actor.LocalId is not { } id || actor.Role != NergalRoles.Administrator) { return true; }
        var userId = id.ToString("D");
        return await HasUsableLocalMfaAsync(userId, keys) || await HasIndependentLocalRecoveryAsync(userId, keys);
    }

    private async Task<string> EmailEnrollmentBindingAsync(AccountActor actor, ClaimsPrincipal principal)
    {
        var authority = await EnrollmentAuthorityAsync(actor, principal);
        if (actor.LocalId is null) { return authority; }
        var stamp = principal.FindFirstValue(signIn.Options.ClaimsIdentity.SecurityStampClaimType)
            ?? throw new AccountStoreException("account.denied");
        return LdapTokenDigest(authority + ":" + stamp);
    }

    private async Task<EmailMfaActorState?> ReadEmailMfaActorStateAsync(string actorId)
    {
        var events = context.Database.SqlQuery<long>(
            $"SELECT count(*) AS Value FROM IdentityAudit WHERE ActorId = {actorId} AND Action = {EmailEnrolled}");
        var observation = await (from count in events
                                 from row in context.Set<EmailMfaActorState>().Where(email => email.ActorId == actorId).DefaultIfEmpty()
                                 select new { Count = count, Row = row }).SingleAsync();
        if (observation.Count != (observation.Row is { AddressId.Length: > 0 } ? 1 : 0))
        { throw new AccountStoreException("account.corrupt"); }
        return observation.Row;
    }

    private static IDataProtector VerifiedEmailProtector(EmailMfaActorState email, IDataProtectionProvider keys)
        => keys.CreateProtector("Nergal.Mfa.VerifiedEmail.v1", email.ActorId, email.AddressId);

    private static string OpenVerifiedEmailAddress(EmailMfaActorState email, IDataProtectionProvider keys)
    {
        var address = VerifiedEmailProtector(email, keys).Unprotect(email.ProtectedAddress);
        return EmailDeliverySettings.IsMailbox(address) ? address : throw new CryptographicException();
    }

    private Task<EmailMfaCode?> ReadEmailCodeAsync(string actorId, EmailMfaStage stage)
        => context.Set<EmailMfaCode>().SingleOrDefaultAsync(row => row.ActorId == actorId && row.Stage == stage);

    // One per actor across enrollment and sign-in. Resends consume this budget even when transport fails.
    private static bool TryReserveEmailSend(EmailMfaActorState email, DateTimeOffset now)
    {
        if (email.SendWindowEndsUtcTicks <= now.UtcTicks)
        {
            email.Sends = 0;
            email.SendWindowEndsUtcTicks = (now + AttemptWindow).UtcTicks;
        }
        if (email.Sends >= EmailSendLimit) { return false; }
        email.Sends++;
        return true;
    }

    private async Task<(EmailMfaCode Row, EmailMfaDelivery Delivery)> ReserveEmailCodeAsync(string actorId, EmailMfaStage stage,
        long policyVersion, long deliveryGeneration, string binding, DateTimeOffset endsUtc, string address, IDataProtectionProvider keys)
    {
        var row = await ReadEmailCodeAsync(actorId, stage) ??
            context.Add(new EmailMfaCode { ActorId = actorId, Stage = stage }).Entity;
        row.Id = Guid.NewGuid().ToString("N");
        row.Binding = binding;
        row.PolicyVersion = policyVersion;
        row.DeliveryGeneration = deliveryGeneration;
        row.EndsUtcTicks = endsUtc.UtcTicks;
        row.FailedAttempts = 0;
        var code = RandomNumberGenerator.GetInt32(1_000_000).ToString("D6", CultureInfo.InvariantCulture);
        row.ProtectedCode = EmailCodeProtector(row, keys, "Code").Protect(code);
        if (stage == EmailMfaStage.Enrollment)
        { row.ProtectedAddress = EmailCodeProtector(row, keys, "Address").Protect(address); }
        return (row, new EmailMfaDelivery(address, code, deliveryGeneration));
    }

    private async Task<bool> EmailCodeCurrentAsync(EmailMfaCode row, long policyVersion, DateTimeOffset now)
        => row.PolicyVersion == policyVersion && row.EndsUtcTicks > now.UtcTicks &&
            row.EndsUtcTicks <= (now + PendingLifetime).UtcTicks &&
            row.DeliveryGeneration == await EnabledEmailDeliveryGenerationAsync();

    private static IDataProtector EmailCodeProtector(EmailMfaCode row, IDataProtectionProvider keys, string content)
        => keys.CreateProtector("Nergal.Mfa.EmailChallenge.v1", row.Stage.ToString(), content, row.ActorId, row.Id, row.Binding,
            row.PolicyVersion.ToString(CultureInfo.InvariantCulture), row.DeliveryGeneration.ToString(CultureInfo.InvariantCulture),
            row.EndsUtcTicks.ToString(CultureInfo.InvariantCulture));

    private static bool MatchesEmailCode(EmailMfaCode row, IDataProtectionProvider keys, string code)
    {
        if (code is not { Length: 6 } || !code.All(char.IsAsciiDigit)) { return false; }
        var expected = EmailCodeProtector(row, keys, "Code").Unprotect(row.ProtectedCode);
        if (expected.Length != 6 || !expected.All(char.IsAsciiDigit)) { throw new CryptographicException(); }
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(code));
    }

    private static async Task<bool> TryDeliverEmailCodeAsync(IMfaEmailSender sender, EmailMfaDelivery delivery, CancellationToken token)
    {
        try
        {
            token.ThrowIfCancellationRequested();
            await sender.SendAsync(delivery, token);
            return true;
        }
        catch (Exception)
        {
            // Transport exceptions can contain peer text, mailbox or credential data.
            token.ThrowIfCancellationRequested();
            return false;
        }
    }
}
