namespace Nergal.Core.Identity;

/// <summary>Immutable credential-free OIDC trust settings. A snapshot is configuration, never evidence of authentication.</summary>
public sealed class OidcConnectionSettings
{
    /// <summary>Copies bounded group lists; callers cannot mutate a saved trust proposal through their collections.</summary>
    public OidcConnectionSettings(bool enabled, string issuer, string clientId, string callbackUri, string groupClaim,
        IEnumerable<string> administratorGroups, IEnumerable<string> auditorGroups)
    {
        ArgumentNullException.ThrowIfNull(administratorGroups);
        ArgumentNullException.ThrowIfNull(auditorGroups);
        Enabled = enabled; Issuer = issuer; ClientId = clientId; CallbackUri = callbackUri; GroupClaim = groupClaim;
        AdministratorGroups = Array.AsReadOnly(administratorGroups.Take(33).ToArray());
        AuditorGroups = Array.AsReadOnly(auditorGroups.Take(33).ToArray());
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

    /// <summary>Validates supported trust inputs even while disabled; no normalization or expressions are interpreted.</summary>
    public bool IsValid
    {
        get
        {
            try { _ = ControllerActorIdentity.FromFederatedAccount(Issuer, "connection-validation"); }
            catch (ArgumentException) { return false; }
            static bool Text(string? value, int size) => !string.IsNullOrWhiteSpace(value) && value.Length <= size && ProfileMetadata.ValidText(value, size);
            static bool Groups(IReadOnlyList<string> values) => values.Count <= 32 && values.All(v => Text(v, 256)) && values.Distinct(StringComparer.Ordinal).Count() == values.Count;
            return Text(ClientId, 256) && Text(GroupClaim, 128) &&
                GroupClaim.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' or ':' or '/') &&
                GroupClaim is not ("iss" or "sub" or "aud" or "azp" or "nonce" or "exp" or "iat" or "nbf" or "auth_time" or "acr" or "amr") &&
                CallbackUri is { Length: <= 512 } && !CallbackUri.Any(char.IsWhiteSpace) &&
                Uri.TryCreate(CallbackUri, UriKind.Absolute, out var callback) && callback.Scheme == "https" &&
                callback.UserInfo.Length == 0 && callback.PathAndQuery == "/signin-oidc" && callback.Fragment.Length == 0 &&
                Groups(AdministratorGroups) && Groups(AuditorGroups) && AdministratorGroups.Count + AuditorGroups.Count > 0 &&
                !AdministratorGroups.Intersect(AuditorGroups, StringComparer.Ordinal).Any();
        }
    }
}

/// <summary>Credential-free persisted connection status and concurrency token.</summary>
public sealed record OidcConnectionSnapshot(long Version, OidcConnectionSettings Settings, bool HasSecret, DateTimeOffset UpdatedUtc);
