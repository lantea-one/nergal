using System.Text.Json;

namespace Nergal.Core.Identity;

/// <summary>Pure bounded metadata projection. Callers must independently verify the signed ID token and complete protocol validation first.</summary>
public static class OidcProfileMapper
{
    /// <summary>Checks exact issuer and literal claim names; empty names turn off individual metadata fields.</summary>
    public static bool IsValid(OidcProfileMapping mapping)
    {
        if (mapping is null || mapping.Version < 0 || mapping.Version == long.MaxValue) { return false; }
        try { _ = ControllerActorIdentity.FromFederatedAccount(mapping.Issuer, "metadata-validation"); }
        catch (ArgumentException) { return false; }
        return new[] { mapping.DisplayNameClaim, mapping.GivenNameClaim, mapping.FamilyNameClaim, mapping.EmailClaim }.All(ValidClaim);
    }

    /// <summary>Extracts optional string metadata, explicitly reporting missing/invalid values without granting authority or interpreting expressions.</summary>
    /// <exception cref="ArgumentException">Mapping, object shape or duplicate JSON members are invalid.</exception>
    public static ProviderProfileSnapshot Project(OidcProfileMapping mapping, JsonElement verifiedClaims, DateTimeOffset observedUtc)
    {
        if (!IsValid(mapping) || mapping.Version < 1 || !mapping.Enabled || verifiedClaims.ValueKind != JsonValueKind.Object) { throw new ArgumentException("Invalid profile projection."); }
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in verifiedClaims.EnumerateObject())
        { if (!names.Add(item.Name) || names.Count > 1024) { throw new ArgumentException("Ambiguous or oversized profile claims."); } }
        var diagnostics = new List<string>();
        string Read(string claim, string field, Func<string?, bool> valid)
        {
            if (claim.Length == 0) { return ""; }
            if (!verifiedClaims.TryGetProperty(claim, out var value) || value.ValueKind == JsonValueKind.Null)
            { diagnostics.Add(field + ".missing"); return ""; }
            try
            {
                if (value.ValueKind == JsonValueKind.String)
                {
                    var text = value.GetString()!;
                    if (string.IsNullOrWhiteSpace(text)) { diagnostics.Add(field + ".missing"); return ""; }
                    if (valid(text)) { return text; }
                }
            }
            catch (InvalidOperationException) { /* Invalid Unicode in optional JSON string metadata is unavailable. */ }
            diagnostics.Add(field + ".invalid"); return "";
        }
        var metadata = new ProfileMetadata(Read(mapping.DisplayNameClaim, "displayName", s => ProfileMetadata.ValidText(s, 80)),
            Read(mapping.GivenNameClaim, "givenName", s => ProfileMetadata.ValidText(s, 80)),
            Read(mapping.FamilyNameClaim, "familyName", s => ProfileMetadata.ValidText(s, 80)),
            Read(mapping.EmailClaim, "email", ProfileMetadata.ValidEmail));
        return new(mapping.Issuer, mapping.Version, metadata, observedUtc.ToUniversalTime(), diagnostics);
    }

    private static bool ValidClaim(string? claim) => claim is not null && claim.Length <= 128 &&
        claim.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' or ':' or '/') &&
        claim is not ("iss" or "sub" or "aud" or "azp" or "iat" or "exp" or "nbf" or "nonce" or "auth_time" or "sid" or
            "role" or "roles" or "groups" or "acr" or "amr" or "email_verified");
}
