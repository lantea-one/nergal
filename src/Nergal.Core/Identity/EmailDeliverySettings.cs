namespace Nergal.Core.Identity;

/// <summary>Credential-free settings for one SMTP STARTTLS relay.</summary>
public sealed record EmailDeliverySettings(bool Enabled, string Host, int Port, string FromAddress, string UserName)
{
    /// <summary>Checks an explicit SMTP endpoint and a single sender address without network access.</summary>
    public bool IsValid => Host is { Length: > 0 and <= 253 } &&
        Host.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or ':') &&
        Uri.CheckHostName(Host) is UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6 &&
        Port is >= 1 and <= 65535 && IsMailbox(FromAddress) && UserName is { Length: <= 256 } &&
        ProfileMetadata.ValidText(UserName, 256) && (UserName.Length == 0 || !string.IsNullOrWhiteSpace(UserName));

    /// <summary>Checks a single ASCII mailbox for the SMTP envelope and headers.</summary>
    public static bool IsMailbox(string? address) => address is { Length: > 0 } && address.All(char.IsAscii) &&
        ProfileMetadata.ValidEmail(address);
}

/// <summary>Current delivery configuration with optimistic concurrency and credential presence.</summary>
public sealed record EmailDeliverySnapshot(long Version, EmailDeliverySettings Settings, bool HasPassword, DateTimeOffset UpdatedUtc);
