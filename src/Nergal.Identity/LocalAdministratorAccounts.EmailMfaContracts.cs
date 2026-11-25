namespace Nergal.Identity;

/// <summary>Delivers one reserved MFA code through the enabled configuration at the reserved generation.</summary>
/// <remarks>Implementations must reject stale configurations and keep delivery evidence out of diagnostics.</remarks>
public interface IMfaEmailSender
{
    /// <summary>Delivers the code or throws if delivery cannot be confirmed. Called outside the identity transaction.</summary>
    Task SendAsync(EmailMfaDelivery delivery, CancellationToken cancellationToken);
}

/// <summary>Transient delivery evidence for one exact verified or explicitly entered address.</summary>
/// <param name="Address">Exact destination mailbox.</param>
/// <param name="Code">Six-digit code for the reserved challenge.</param>
/// <param name="Generation">Version of the enabled SMTP configuration required for this send.</param>
public sealed record EmailMfaDelivery(string Address, string Code, long Generation)
{
    /// <summary>Omits the mailbox, code and configuration metadata from diagnostic text.</summary>
    public override string ToString() => nameof(EmailMfaDelivery);
}

/// <summary>Current actor's email factor and whether delivery is enabled for new enrollment.</summary>
public sealed record EmailMfaEnrollmentStatus(bool Enrolled, bool CanStart);

/// <summary>Identifier for the initiating authenticated browser to submit with the delivered code.</summary>
public sealed record EmailMfaEnrollment(string Id)
{
    /// <summary>Omits the enrollment identifier from diagnostic text.</summary>
    public override string ToString() => nameof(EmailMfaEnrollment);
}
