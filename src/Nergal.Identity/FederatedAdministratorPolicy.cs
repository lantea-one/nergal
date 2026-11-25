using System.Text.Json;
using Nergal.Core.Identity;

namespace Nergal.Identity;

/// <summary>Role-aware OIDC authorization policy applied only after signature verification of an ID token.</summary>
/// <remarks>This policy performs no signature verification and must never be applied to browser-supplied claims.</remarks>
public sealed class FederatedAdministratorPolicy
{
    private readonly HashSet<string> groups;
    private readonly HashSet<string> auditorGroups;
    private readonly string groupClaim;

    /// <summary>Requires one explicit HTTPS issuer, one client audience, and one or more exact administrator group names.</summary>
    public FederatedAdministratorPolicy(string issuer, string clientId, string groupClaim, IEnumerable<string> groups)
        : this(issuer, clientId, groupClaim, groups, [])
    {
    }

    /// <summary>Requires one explicit HTTPS issuer, one client audience, and disjoint exact administrator/auditor group allowlists.</summary>
    public FederatedAdministratorPolicy(
        string issuer,
        string clientId,
        string groupClaim,
        IEnumerable<string> administratorGroups,
        IEnumerable<string>? auditorGroups)
    {
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out var uri) || uri.Scheme != "https" ||
            uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0 || issuer.Length > 512 || issuer.Any(char.IsWhiteSpace))
        { throw new ArgumentException("An absolute HTTPS issuer is required.", nameof(issuer)); }
        if (!Bounded(clientId, 256)) { throw new ArgumentException("An explicit client identifier is required.", nameof(clientId)); }
        if (!Bounded(groupClaim, 128) || groupClaim is "iss" or "sub" or "aud" or "azp" or "nonce" or "exp" or "iat" or "nbf" or "auth_time")
        { throw new ArgumentException("An explicit group claim is required.", nameof(groupClaim)); }
        ArgumentNullException.ThrowIfNull(administratorGroups);
        var admins = administratorGroups.Take(33).ToArray();
        var auditors = (auditorGroups ?? []).Take(33).ToArray();
        if (admins.Length > 32 || admins.Any(name => !Bounded(name, 256)) ||
            admins.Distinct(StringComparer.Ordinal).Count() != admins.Length)
        { throw new ArgumentException("At most thirty-two distinct exact administrator group values are required.", nameof(administratorGroups)); }
        if (auditors.Length > 32 || auditors.Any(name => !Bounded(name, 256)) ||
            auditors.Distinct(StringComparer.Ordinal).Count() != auditors.Length)
        { throw new ArgumentException("At most thirty-two distinct exact auditor group values are permitted.", nameof(auditorGroups)); }
        if (admins.Length + auditors.Length == 0)
        { throw new ArgumentException("At least one exact administrator or auditor group value is required.", nameof(administratorGroups)); }
        var adminSet = new HashSet<string>(admins, StringComparer.Ordinal);
        var auditorSet = new HashSet<string>(auditors, StringComparer.Ordinal);
        if (adminSet.Overlaps(auditorSet))
        { throw new ArgumentException("Administrator and auditor group sets must be disjoint.", nameof(auditorGroups)); }
        Issuer = issuer;
        ClientId = clientId;
        this.groupClaim = groupClaim;
        this.groups = adminSet;
        this.auditorGroups = auditorSet;
    }

    /// <summary>Gets the case-sensitive issuer identifier used for federated identity and token validation.</summary>
    public string Issuer { get; }

    /// <summary>Gets the only supported audience.</summary>
    public string ClientId { get; }

    /// <summary>Authorizes a verified token payload, returning the immutable issuer/subject identity, resolved role, and maximum session deadline.</summary>
    /// <remarks>Missing, malformed, ambiguous, expired or unmatched claims yield no identity. Authorization never extends token lifetime.</remarks>
    public FederatedAdministrator? AuthorizeVerifiedClaims(JsonElement claims, DateTimeOffset now)
    {
        if (claims.ValueKind != JsonValueKind.Object) { return null; }
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var field in claims.EnumerateObject())
        {
            if (!names.Add(field.Name)) { return null; }
        }
        if (Text(claims, "iss") != Issuer || !claims.TryGetProperty("aud", out var audience) || !IsSingleAudience(audience) ||
            (claims.TryGetProperty("azp", out _) && Text(claims, "azp") != ClientId)) { return null; }
        var subject = Text(claims, "sub");
        if (subject is null || !Bounded(subject, 255) || !subject.All(character => character is >= '!' and <= '~')) { return null; }
        if (!Time(claims, "iat", out var issued) || !Time(claims, "exp", out var expires) || issued > now || expires <= now ||
            now - issued >= TimeSpan.FromMinutes(15)) { return null; }
        if (!claims.TryGetProperty(groupClaim, out var values) || values.ValueKind != JsonValueKind.Array ||
            values.GetArrayLength() is < 1 or > 256) { return null; }
        var isAdministrator = false;
        var isAuditor = false;
        foreach (var value in values.EnumerateArray())
        {
            if (value.ValueKind != JsonValueKind.String || !Bounded(value.GetString(), 256)) { return null; }
            var group = value.GetString()!;
            isAdministrator |= groups.Contains(group);
            isAuditor |= auditorGroups.Contains(group);
        }
        if (!isAdministrator && !isAuditor) { return null; }
        var role = isAdministrator ? NergalRoles.Administrator : NergalRoles.Auditor;
        var maximum = issued.ToUnixTimeSeconds() + 900;
        return new(Issuer, subject, DateTimeOffset.FromUnixTimeSeconds(Math.Min(expires.ToUnixTimeSeconds(), maximum)), role);
    }

    private bool IsSingleAudience(JsonElement audience) =>
        audience.ValueKind == JsonValueKind.String ? audience.GetString() == ClientId :
        audience.ValueKind == JsonValueKind.Array && audience.GetArrayLength() == 1 &&
        audience[0].ValueKind == JsonValueKind.String && audience[0].GetString() == ClientId;

    private static bool Time(JsonElement claims, string name, out DateTimeOffset time)
    {
        time = default;
        if (!claims.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Number ||
            !value.TryGetInt64(out var seconds) || seconds is < 0 or > 253402300799) { return false; }
        time = DateTimeOffset.FromUnixTimeSeconds(seconds);
        return true;
    }

    private static bool Bounded(string? value, int maximum) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximum && !value.Any(char.IsControl);

    private static string? Text(JsonElement claims, string name) =>
        claims.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}

/// <summary>Exact external identity, RBAC role, and absolute authorization deadline. A value alone is never a login credential.</summary>
public sealed record FederatedAdministrator(string Issuer, string Subject, DateTimeOffset Expires, string Role = NergalRoles.Administrator);
