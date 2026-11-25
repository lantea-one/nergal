using System.Net.Mail;
using System.Text;

namespace Nergal.Core.Identity;

/// <summary>Descriptive personal metadata. Email is not a verified delivery address, identity key, role or authentication factor.</summary>
/// <param name="DisplayName">Optional display name, at most 80 Unicode scalar values.</param>
/// <param name="GivenName">Optional given name, at most 80 Unicode scalar values.</param>
/// <param name="FamilyName">Optional family name, at most 80 Unicode scalar values.</param>
/// <param name="Email">Optional exact mailbox address without a display name, at most 254 characters.</param>
public sealed record ProfileMetadata(string DisplayName = "", string GivenName = "", string FamilyName = "", string Email = "")
{
    /// <summary>Gets empty metadata without any authority or identity meaning.</summary>
    public static ProfileMetadata Empty { get; } = new();

    /// <summary>Checks bounded well-formed Unicode and denies control characters and malformed mailboxes.</summary>
    public bool IsValid => ValidText(DisplayName, 80) && ValidText(GivenName, 80) && ValidText(FamilyName, 80) && ValidEmail(Email);

    /// <summary>Resolves individual nonempty local overrides over defaults after validating both metadata values.</summary>
    /// <exception cref="ArgumentNullException">Defaults are null.</exception>
    /// <exception cref="ArgumentException">Either metadata value is malformed or outside supported bounds.</exception>
    public ProfileMetadata Over(ProfileMetadata defaults)
    {
        ArgumentNullException.ThrowIfNull(defaults);
        if (!IsValid || !defaults.IsValid) { throw new ArgumentException("Invalid profile metadata."); }
        return new(
        DisplayName.Length == 0 ? defaults.DisplayName : DisplayName,
        GivenName.Length == 0 ? defaults.GivenName : GivenName,
        FamilyName.Length == 0 ? defaults.FamilyName : FamilyName,
        Email.Length == 0 ? defaults.Email : Email);
    }

    /// <summary>Checks descriptive text bounds without normalization, replacement or hidden controls.</summary>
    public static bool ValidText(string? value, int maximum)
    {
        if (value is null || maximum is < 1 or > 512 || value.Length > maximum * 2 ||
            value.EnumerateRunes().Count() > maximum || value.Any(char.IsControl)) { return false; }
        try { _ = new UTF8Encoding(false, true).GetByteCount(value); return true; }
        catch (EncoderFallbackException) { return false; }
    }

    /// <summary>Checks optional mailbox syntax only; it does not establish delivery, ownership or verification.</summary>
    public static bool ValidEmail(string? value) => ValidText(value, 254) && (value!.Length == 0 ||
        value.Length <= 254 && !value.Any(char.IsWhiteSpace) && MailAddress.TryCreate(value, out var parsed) &&
        parsed.DisplayName.Length == 0 && parsed.Address == value);
}

/// <summary>A versioned current provider observation, eligible only for the current enabled issuer mapping.</summary>
public sealed class ProviderProfileSnapshot
{
    /// <summary>Creates a defensive credential-free observation snapshot.</summary>
    public ProviderProfileSnapshot(string issuer, long mappingVersion, ProfileMetadata metadata,
        DateTimeOffset observedUtc, IEnumerable<string> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(diagnostics);
        _ = ControllerActorIdentity.FromFederatedAccount(issuer, "metadata-validation");
        var items = diagnostics.Take(5).ToArray();
        var allowed = new[] { "displayName", "givenName", "familyName", "email" }
            .SelectMany(field => new[] { field + ".missing", field + ".invalid" }).ToHashSet(StringComparer.Ordinal);
        if (mappingVersion < 1 || !metadata.IsValid || items.Length > 4 ||
            items.Distinct(StringComparer.Ordinal).Count() != items.Length || items.Any(item => !allowed.Contains(item)) ||
            items.Select(item => item.Split('.')[0]).Distinct(StringComparer.Ordinal).Count() != items.Length)
        { throw new ArgumentException("Invalid provider metadata snapshot."); }
        Issuer = issuer; MappingVersion = mappingVersion; Metadata = metadata;
        ObservedUtc = observedUtc.ToUniversalTime(); Diagnostics = Array.AsReadOnly(items);
    }
    /// <summary>Gets the exact validated issuer.</summary>
    public string Issuer { get; }
    /// <summary>Gets the configuration version that selected these defaults.</summary>
    public long MappingVersion { get; }
    /// <summary>Gets optional provider defaults without authentication meaning.</summary>
    public ProfileMetadata Metadata { get; }
    /// <summary>Gets the UTC successful-sign-in observation instant.</summary>
    public DateTimeOffset ObservedUtc { get; }
    /// <summary>Gets immutable value-free missing/invalid field diagnostics.</summary>
    public IReadOnlyList<string> Diagnostics { get; }
}

/// <summary>Administrator-owned literal top-level claim mapping. A mapping cannot activate an authentication provider.</summary>
public sealed record OidcProfileMapping(string Issuer, long Version, bool Enabled, string DisplayNameClaim,
    string GivenNameClaim, string FamilyNameClaim, string EmailClaim, DateTimeOffset? UpdatedUtc);
