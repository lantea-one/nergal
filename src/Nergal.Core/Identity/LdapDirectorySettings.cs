namespace Nergal.Core.Identity;

/// <summary>Credential-free configuration for one trusted LDAPS directory and its direct role groups.</summary>
/// <param name="DirectoryId">Nergal-assigned namespace for immutable directory entry IDs.</param>
/// <param name="ServerUri">One absolute LDAPS endpoint, with an optional explicit port.</param>
/// <param name="UserBaseDn">Search base for user entries.</param>
/// <param name="SearchBindDn">Distinguished name of a read-only search account.</param>
/// <param name="LoginAttribute">Literal attribute for exact username lookup.</param>
/// <param name="AdministratorGroupDn">Directory group that grants the Administrator role.</param>
/// <param name="AuditorGroupDn">Directory group that grants the Auditor role.</param>
/// <param name="ProfileMapping">Optional descriptive attributes selected independently of role and identity.</param>
public sealed record LdapDirectorySettings(Guid DirectoryId, string ServerUri, string UserBaseDn, string SearchBindDn,
    string LoginAttribute, string AdministratorGroupDn, string AuditorGroupDn,
    LdapProfileMapping ProfileMapping)
{
    /// <summary>Checks input bounds and the single-peer contract. The directory validates DN syntax and matching rules.</summary>
    public bool IsValid => DirectoryId != Guid.Empty && TryEndpoint(ServerUri, out _) &&
        new[] { UserBaseDn, SearchBindDn, AdministratorGroupDn, AuditorGroupDn }.All(ValidDn) &&
        !string.Equals(AdministratorGroupDn, AuditorGroupDn, StringComparison.OrdinalIgnoreCase) &&
        LdapUserLookup.IsValidAttribute(LoginAttribute) &&
        ProfileMapping is { IsValid: true };

    /// <summary>Gets the validated endpoint. When no port is specified, LDAP over TLS uses port 636.</summary>
    /// <exception cref="InvalidOperationException">The endpoint is malformed or outside the supported LDAPS form.</exception>
    public Uri GetEndpoint() => TryEndpoint(ServerUri, out var endpoint)
        ? endpoint!
        : throw new InvalidOperationException("Invalid LDAPS endpoint.");

    private static bool TryEndpoint(string? value, out Uri? endpoint)
    {
        endpoint = null;
        if (value is not { Length: > 8 and <= 320 } || !value.StartsWith("ldaps://", StringComparison.Ordinal) ||
            value.Any(character => !char.IsAscii(character) || char.IsWhiteSpace(character) || char.IsControl(character) ||
                character is '\\' or '%' or '@' or '?' or '#') ||
            value.AsSpan(8).TrimEnd('/').Contains('/') || value.EndsWith("//", StringComparison.Ordinal) ||
            value.AsSpan().TrimEnd('/').EndsWith(":", StringComparison.Ordinal) ||
            !Uri.TryCreate(value, UriKind.Absolute, out var parsed) || !parsed.IsWellFormedOriginalString() ||
            parsed.HostNameType is not (UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6) ||
            parsed.Port == 0 || parsed.AbsolutePath != "/")
        { return false; }
        endpoint = parsed.Port < 0 ? new UriBuilder(parsed) { Port = 636 }.Uri : parsed;
        return true;
    }

    private static bool ValidDn(string? value) => !string.IsNullOrWhiteSpace(value) && value == value.Trim() &&
        ProfileMetadata.ValidText(value, 512);
}
