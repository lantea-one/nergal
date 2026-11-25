using System.Globalization;
using System.Text;

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

/// <summary>Canonical controller actor identifiers recorded in audit logs (`local:&lt;uuid&gt;` or `oidc:&lt;issuer-length&gt;:&lt;issuer&gt;:&lt;subject&gt;`).</summary>
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
    /// <remarks>The issuer length is its UTF-16 code-unit count. The fields are preserved exactly, without normalization.</remarks>
    /// <exception cref="ArgumentException">Issuer is not a bounded HTTPS identity URL, or either field is empty, oversized or contains controls.</exception>
    public static string FromFederatedAccount(string issuer, string subject)
    {
        if (string.IsNullOrWhiteSpace(issuer) || issuer.Length > 512 || !WellFormed(issuer) || issuer.Any(char.IsControl) || issuer.Any(char.IsWhiteSpace) ||
            !Uri.TryCreate(issuer, UriKind.Absolute, out var uri) || uri.Scheme != "https" ||
            uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0)
        {
            throw new ArgumentException("A valid OIDC issuer identifier is required.", nameof(issuer));
        }

        if (string.IsNullOrWhiteSpace(subject) || subject.Length > 255 || !WellFormed(subject) || subject.Any(char.IsControl))
        {
            throw new ArgumentException("A valid OIDC subject identifier is required.", nameof(subject));
        }

        return $"oidc:{issuer.Length.ToString(CultureInfo.InvariantCulture)}:{issuer}:{subject}";
    }

    /// <summary>Validates canonical <c>local:&lt;uuid&gt;</c> or <c>oidc:&lt;issuer-length&gt;:&lt;issuer&gt;:&lt;subject&gt;</c> syntax.</summary>
    public static bool IsValid(string? actorId)
    {
        if (string.IsNullOrWhiteSpace(actorId) || actorId.Length > 1024 || actorId.Any(char.IsControl))
        {
            return false;
        }

        if (actorId.StartsWith("local:", StringComparison.Ordinal))
        {
            return Guid.TryParseExact(actorId.AsSpan("local:".Length), "D", out var parsed) && parsed != Guid.Empty &&
                FromLocalAccount(parsed) == actorId;
        }

        if (actorId.StartsWith("oidc:", StringComparison.Ordinal))
        {
            var rest = actorId.AsSpan("oidc:".Length);
            var separator = rest.IndexOf(':');
            if (separator < 1 || !int.TryParse(rest[..separator], NumberStyles.None, CultureInfo.InvariantCulture, out var length) ||
                length is < 1 or > 512) { return false; }
            var pair = rest[(separator + 1)..];
            if (pair.Length <= length + 1 || pair[length] != ':') { return false; }
            try { return FromFederatedAccount(pair[..length].ToString(), pair[(length + 1)..].ToString()) == actorId; }
            catch (ArgumentException) { return false; }
        }

        return false;
    }

    private static bool WellFormed(string value)
    {
        try { _ = new UTF8Encoding(false, true).GetByteCount(value); return true; }
        catch (EncoderFallbackException) { return false; }
    }
}
