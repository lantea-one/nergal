using System.Text.Json;

namespace Nergal.Core.Identity;

/// <summary>Decides whether a verified OIDC sign-in can satisfy the local MFA requirement.</summary>
public enum OidcMfaAssuranceMode
{
    /// <summary>OIDC sign-in cannot satisfy a required MFA policy.</summary>
    Deny = 0,
    /// <summary>Explicitly trust the provider to enforce MFA for this connection.</summary>
    ProviderBypass = 1,
    /// <summary>Require an exact value from a configured signed ID-token claim.</summary>
    SignedClaim = 2,
}

/// <summary>Immutable credential-free OIDC trust settings. A snapshot is configuration, never evidence of authentication.</summary>
public sealed class OidcConnectionSettings
{
    /// <summary>Copies bounded group lists; callers cannot mutate a saved trust proposal through their collections.</summary>
    public OidcConnectionSettings(bool enabled, string issuer, string clientId, string callbackUri, string groupClaim,
        IEnumerable<string> administratorGroups, IEnumerable<string> auditorGroups,
        OidcMfaAssuranceMode mfaAssuranceMode = OidcMfaAssuranceMode.Deny, string mfaAssuranceClaim = "", string mfaAssuranceValue = "")
    {
        ArgumentNullException.ThrowIfNull(administratorGroups);
        ArgumentNullException.ThrowIfNull(auditorGroups);
        Enabled = enabled; Issuer = issuer; ClientId = clientId; CallbackUri = callbackUri; GroupClaim = groupClaim;
        AdministratorGroups = Array.AsReadOnly(administratorGroups.Take(33).ToArray());
        AuditorGroups = Array.AsReadOnly(auditorGroups.Take(33).ToArray());
        MfaAssuranceMode = mfaAssuranceMode;
        MfaAssuranceClaim = mfaAssuranceClaim;
        MfaAssuranceValue = mfaAssuranceValue;
    }
    /// <summary>Whether fresh federated sign-ins are permitted.</summary>
    public bool Enabled { get; }
    /// <summary>Exact HTTPS issuer, without query, fragment, credentials or whitespace.</summary>
    public string Issuer { get; }
    /// <summary>Exact client audience.</summary>
    public string ClientId { get; }
    /// <summary>Explicit registered HTTPS callback ending at /signin-oidc.</summary>
    public string CallbackUri { get; }
    /// <summary>Literal top-level signed claim containing role-group values.</summary>
    public string GroupClaim { get; }
    /// <summary>Distinct exact groups granting Administrator.</summary>
    public IReadOnlyList<string> AdministratorGroups { get; }
    /// <summary>Distinct exact groups granting Auditor, disjoint from Administrator groups.</summary>
    public IReadOnlyList<string> AuditorGroups { get; }
    /// <summary>Explicit decision about provider MFA when required for the proven role.</summary>
    public OidcMfaAssuranceMode MfaAssuranceMode { get; }
    /// <summary>Literal top-level signed claim selected in signed-claim mode, or empty otherwise.</summary>
    public string MfaAssuranceClaim { get; }
    /// <summary>Case-sensitive evidence value selected in signed-claim mode, or empty otherwise.</summary>
    public string MfaAssuranceValue { get; }

    /// <summary>Validates supported trust inputs even while disabled; no normalization or expressions are interpreted.</summary>
    public bool IsValid
    {
        get
        {
            try { _ = ControllerActorIdentity.FromFederatedAccount(Issuer, "connection-validation"); }
            catch (ArgumentException) { return false; }
            static bool Groups(IReadOnlyList<string> values) => values.Count <= 32 && values.All(v => Text(v, 256)) && values.Distinct(StringComparer.Ordinal).Count() == values.Count;
            return Text(ClientId, 256) && LiteralClaim(GroupClaim) &&
                GroupClaim is not ("iss" or "sub" or "aud" or "azp" or "nonce" or "exp" or "iat" or "nbf" or "auth_time" or "acr" or "amr") &&
                CallbackUri is { Length: <= 512 } && !CallbackUri.Any(char.IsWhiteSpace) &&
                Uri.TryCreate(CallbackUri, UriKind.Absolute, out var callback) && callback.Scheme == "https" &&
                callback.UserInfo.Length == 0 && callback.PathAndQuery == "/signin-oidc" && callback.Fragment.Length == 0 &&
                Groups(AdministratorGroups) && Groups(AuditorGroups) && AdministratorGroups.Count + AuditorGroups.Count > 0 &&
                !AdministratorGroups.Intersect(AuditorGroups, StringComparer.Ordinal).Any() && ValidMfaAssurance;
        }
    }

    /// <summary>Determines whether an already verified ID-token payload satisfies this connection's MFA assurance decision.</summary>
    /// <remarks>Use only after signature and protocol verification. A selected claim must occur once and be a string or an array of
    /// 1–32 distinct nonempty strings. Every value is bounded to 256 characters, and one must match exactly.</remarks>
    public bool AssuresVerifiedMfa(JsonElement verifiedClaims)
    {
        if (!Enabled || !ValidMfaAssurance || verifiedClaims.ValueKind != JsonValueKind.Object) { return false; }
        if (MfaAssuranceMode == OidcMfaAssuranceMode.ProviderBypass) { return true; }
        if (MfaAssuranceMode != OidcMfaAssuranceMode.SignedClaim) { return false; }

        JsonElement evidence = default;
        foreach (var property in verifiedClaims.EnumerateObject())
        {
            if (!property.NameEquals(MfaAssuranceClaim)) { continue; }
            if (evidence.ValueKind != JsonValueKind.Undefined) { return false; }
            evidence = property.Value;
        }
        if (evidence.ValueKind == JsonValueKind.String) { return EvidenceText(evidence) == MfaAssuranceValue; }
        if (evidence.ValueKind != JsonValueKind.Array || evidence.GetArrayLength() is < 1 or > 32) { return false; }

        var values = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in evidence.EnumerateArray())
        {
            var value = EvidenceText(item);
            if (value is null || !values.Add(value)) { return false; }
        }
        return values.Contains(MfaAssuranceValue);
    }

    private bool ValidMfaAssurance => MfaAssuranceMode switch
    {
        OidcMfaAssuranceMode.Deny or OidcMfaAssuranceMode.ProviderBypass => MfaAssuranceClaim == "" && MfaAssuranceValue == "",
        OidcMfaAssuranceMode.SignedClaim => LiteralClaim(MfaAssuranceClaim) && MfaAssuranceClaim != GroupClaim &&
            MfaAssuranceClaim is not ("iss" or "sub" or "aud" or "azp" or "nonce" or "exp" or "iat" or "nbf" or "auth_time" or
                "at_hash" or "c_hash" or "sid" or "email" or "email_verified" or "name" or "given_name" or "family_name" or "preferred_username") &&
            Text(MfaAssuranceValue, 256),
        _ => false,
    };

    private static bool Text(string? value, int size) => !string.IsNullOrWhiteSpace(value) && value.Length <= size && ProfileMetadata.ValidText(value, size);

    private static string? EvidenceText(JsonElement item)
    {
        if (item.ValueKind != JsonValueKind.String) { return null; }
        try
        {
            var value = item.GetString();
            return Text(value, 256) ? value : null;
        }
        catch (InvalidOperationException) { return null; }
    }

    private static bool LiteralClaim(string value) => Text(value, 128) &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' or ':' or '/');
}

/// <summary>Credential-free persisted connection status and concurrency token.</summary>
public sealed record OidcConnectionSnapshot(long Version, OidcConnectionSettings Settings, bool HasSecret, DateTimeOffset UpdatedUtc);
