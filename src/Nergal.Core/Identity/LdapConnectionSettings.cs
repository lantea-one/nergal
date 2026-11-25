using System.Net;

namespace Nergal.Core.Identity;

/// <summary>Credential-free trust proposal for the single managed LDAPS connection.</summary>
/// <param name="Enabled">Whether fresh LDAP sign-ins are permitted.</param>
/// <param name="ServerUri">Exact supported LDAPS URI identifying the TLS peer and port.</param>
/// <param name="DialIp">One canonical IPv4 or IPv6 address without an interface scope.</param>
/// <param name="UserBaseDn">Search base for user entries.</param>
/// <param name="SearchBindDn">Distinguished name of the read-only search account.</param>
/// <param name="LoginAttribute">Literal attribute for exact username lookup.</param>
/// <param name="AdministratorGroupDn">Directory group granting Administrator.</param>
/// <param name="AuditorGroupDn">Directory group granting Auditor.</param>
/// <param name="ProfileMapping">Optional descriptive attribute selectors.</param>
public sealed record LdapConnectionSettings(bool Enabled, string ServerUri, string DialIp, string UserBaseDn,
    string SearchBindDn, string LoginAttribute, string AdministratorGroupDn, string AuditorGroupDn,
    LdapProfileMapping ProfileMapping)
{
    /// <summary>Validates trust inputs even while disabled, using the proposed or assigned directory identity.</summary>
    public bool IsValid(Guid directoryId)
    {
        var directory = ToDirectorySettings(directoryId);
        if (!directory.IsValid || DialIp is not { Length: > 0 and <= 45 } ||
            !IPAddress.TryParse(DialIp, out var address) || address.ToString() != DialIp || DialIp.Contains('%'))
        { return false; }

        return !IPAddress.TryParse(directory.GetEndpoint().IdnHost, out var peerAddress) || peerAddress.Equals(address);
    }

    /// <summary>Combines the proposal with the server-assigned actor namespace for directory verification.</summary>
    public LdapDirectorySettings ToDirectorySettings(Guid directoryId) => new(directoryId, ServerUri, UserBaseDn,
        SearchBindDn, LoginAttribute, AdministratorGroupDn, AuditorGroupDn, ProfileMapping);
}

/// <summary>Credential-free configuration, persisted actor namespace and optimistic concurrency token.</summary>
/// <param name="Version">Committed generation, starting at one and advancing on each save.</param>
/// <param name="DirectoryId">Server-assigned namespace for immutable directory entry IDs.</param>
/// <param name="Settings">The management configuration at this generation.</param>
/// <param name="HasSecret">Whether a protected value is stored, without testing whether it can be decrypted.</param>
/// <param name="UpdatedUtc">UTC instant of the committed settings update.</param>
public sealed record LdapConnectionSnapshot(long Version, Guid DirectoryId, LdapConnectionSettings Settings,
    bool HasSecret, DateTimeOffset UpdatedUtc);
