namespace Nergal.Core.Identity;

/// <summary>Canonical RBAC roles enforced across local and federated web controller sessions.</summary>
public static class NergalRoles
{
    /// <summary>Full administrative authority, permitted to register hosts, author policies, and trigger confirmed apply.</summary>
    public const string Administrator = "nergal:administrator";

    /// <summary>Read-only oversight role, permitted to inspect host status, policy revisions, and audit history.</summary>
    public const string Auditor = "nergal:auditor";

    /// <summary>Returns whether <paramref name="role"/> matches a defined controller role.</summary>
    public static bool IsDefined(string? role) =>
        string.Equals(role, Administrator, StringComparison.Ordinal) ||
        string.Equals(role, Auditor, StringComparison.Ordinal);
}

/// <summary>Authorization policy identifiers registered by the web host.</summary>
public static class ControllerAuthorizationPolicies
{
    /// <summary>Requires <see cref="NergalRoles.Administrator"/> for mutating controller operations.</summary>
    public const string Administrator = "NergalAdministrator";

    /// <summary>Allows either <see cref="NergalRoles.Administrator"/> or <see cref="NergalRoles.Auditor"/> for read-only views.</summary>
    public const string Reader = "NergalReader";
}

/// <summary>Canonical controller actor identifiers recorded in audit logs (`local:&lt;uuid&gt;` or `oidc:&lt;issuer&gt;:&lt;subject&gt;`).</summary>
public static class ControllerActorIdentity
{
    /// <summary>Custom claim storing the canonical actor attribution string on authenticated principals.</summary>
    public const string ActorClaimType = "nergal_actor";

    /// <summary>Formats a canonical actor identifier for an authenticated local account UUID.</summary>
    /// <exception cref="ArgumentException"><paramref name="userId"/> is empty.</exception>
    public static string FromLocalAccount(Guid userId)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException("Local account ID cannot be empty.", nameof(userId));
        }

        return "local:" + userId.ToString("D");
    }

    /// <summary>Formats a canonical actor identifier for an authenticated OIDC issuer and subject pair.</summary>
    /// <exception cref="ArgumentException">Issuer or subject is empty, oversized, or contains control characters.</exception>
    public static string FromFederatedAccount(string issuer, string subject)
    {
        if (string.IsNullOrWhiteSpace(issuer) || issuer.Length > 512 || issuer.Any(char.IsControl) || issuer.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("A valid OIDC issuer identifier is required.", nameof(issuer));
        }

        if (string.IsNullOrWhiteSpace(subject) || subject.Length > 255 || subject.Any(char.IsControl))
        {
            throw new ArgumentException("A valid OIDC subject identifier is required.", nameof(subject));
        }

        return $"oidc:{issuer}:{subject}";
    }

    /// <summary>Validates canonical <c>local:&lt;uuid&gt;</c> or <c>oidc:&lt;issuer&gt;:&lt;subject&gt;</c> syntax.</summary>
    public static bool IsValid(string? actorId)
    {
        if (string.IsNullOrWhiteSpace(actorId) || actorId.Length > 1024 || actorId.Any(char.IsControl))
        {
            return false;
        }

        if (actorId.StartsWith("local:", StringComparison.Ordinal))
        {
            return Guid.TryParseExact(actorId.AsSpan("local:".Length), "D", out var parsed) && parsed != Guid.Empty;
        }

        if (actorId.StartsWith("oidc:https://", StringComparison.Ordinal))
        {
            var rest = actorId.AsSpan("oidc:".Length);
            var separator = rest.LastIndexOf(':');
            if (separator <= "https://".Length)
            {
                return false;
            }

            var issuer = rest[..separator];
            var subject = rest[(separator + 1)..];
            return !issuer.IsWhiteSpace() && subject.Length is >= 1 and <= 255;
        }

        return false;
    }
}
