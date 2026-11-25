namespace Nergal.Core.Identity;

/// <summary>A credential-free local account view.</summary>
/// <param name="Id">Stable local account identity.</param>
/// <param name="UserName">Sign-in name; never a profile-based identity link.</param>
/// <param name="Role">Canonical application role.</param>
/// <param name="Enabled">Whether new and existing local sessions are allowed.</param>
/// <param name="Version">Expected version for security-state mutations.</param>
/// <param name="CreatedUtc">Known UTC creation instant.</param>
/// <param name="UpdatedUtc">Known UTC update instant.</param>
public sealed record LocalUserSnapshot(Guid Id, string UserName, string Role, bool Enabled, long Version,
    DateTimeOffset CreatedUtc, DateTimeOffset UpdatedUtc);

/// <summary>Personal metadata kept separate from the verified sign-in identity and role.</summary>
/// <param name="ActorId">Exact canonical local or federated actor identity.</param>
/// <param name="LoginName">Verified sign-in name, never replaced by profile metadata.</param>
/// <param name="Role">Verified current authorization role.</param>
/// <param name="LocalAccountId">Local account identity, or null for an external identity.</param>
/// <param name="AccountVersion">Expected local security-state version, or null for external credentials.</param>
/// <param name="DisplayName">Optional local display-name override; empty retains the identity's default.</param>
/// <param name="Version">Expected profile version; zero represents no saved override.</param>
/// <param name="UpdatedUtc">UTC metadata update instant, or null for no saved profile.</param>
public sealed record UserProfileSnapshot(string ActorId, string LoginName, string Role, Guid? LocalAccountId, long? AccountVersion,
    string DisplayName, long Version, DateTimeOffset? UpdatedUtc);

/// <summary>An immutable, credential-free event from the protected identity store.</summary>
/// <param name="Sequence">Monotonic identity-store sequence, independent of controller events.</param>
/// <param name="TimestampUtc">UTC decision instant.</param>
/// <param name="ActorId">Verified actor, or explicit offline operator attribution.</param>
/// <param name="ActorRole">Verified role at decision time.</param>
/// <param name="Action">Stable action code.</param>
/// <param name="Target">Affected account/profile identity.</param>
public sealed record IdentityAuditEntry(long Sequence, DateTimeOffset TimestampUtc, string ActorId, string ActorRole,
    string Action, string Target);
