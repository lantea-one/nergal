using System.Security.Claims;
using Nergal.Core.Identity;

namespace Nergal.Identity;

/// <summary>Outcome of the local or directory password and optional second-factor gate.</summary>
public enum MfaSignInStatus
{
    /// <summary>The submitted evidence cannot authorize a session.</summary>
    Denied,
    /// <summary>Only a protected, short-lived browser continuation has been issued.</summary>
    Challenge,
    /// <summary>Authentication and the identity-store transaction have completed.</summary>
    SignedIn
}

/// <summary>A local session cookie is issued by the backend. For LDAP, the host issues its dedicated cookie from the committed principal and deadline.</summary>
public sealed record MfaSignInResult(MfaSignInStatus Status, string? Continuation = null,
    ClaimsPrincipal? LdapPrincipal = null, DateTimeOffset? ExpiresUtc = null)
{
    /// <summary>Diagnostic text excludes bearer continuations and principal claims.</summary>
    public override string ToString() => Status.ToString();
}

/// <summary>Specifies which local and LDAP users must already have a verified factor to sign in.</summary>
public enum MfaRequirement
{
    /// <summary>Only users with an enrolled factor must complete MFA.</summary>
    Optional,
    /// <summary>Every Administrator and every enrolled user must complete MFA.</summary>
    Administrators,
    /// <summary>Every user must complete MFA.</summary>
    All
}

/// <summary>Committed policy and the generation that invalidates older proofs and sessions.</summary>
public sealed record MfaPolicySnapshot(long Version, MfaRequirement Requirement);

/// <summary>Single enrollment display. The secret is an unpadded Base32 key for six-digit SHA-1 TOTP with a 30-second period.</summary>
public sealed record TotpEnrollment(string Id, string ManualKey)
{
    /// <summary>Suppresses enrollment evidence in diagnostic text.</summary>
    public override string ToString() => nameof(TotpEnrollment);
}

internal sealed record MfaFirstFactor(string ActorId, string Name, string Role, string LocalStamp, long LdapGeneration,
    DateTimeOffset VerifiedAtUtc, ProfileMetadata Metadata, string[] Diagnostics)
{
    public override string ToString() => nameof(MfaFirstFactor);
}
