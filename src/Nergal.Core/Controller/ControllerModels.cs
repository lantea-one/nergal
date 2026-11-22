using System.Text;

namespace Nergal.Core.Controller;

/// <summary>Supported authenticated agent transport channels configured on the controller.</summary>
public enum AgentTransportKind
{
    /// <summary>Local kernel peer-UID Unix domain socket transport (`control-serve` / `status-serve`).</summary>
    Unix,

    /// <summary>Remote TLS 1.3 pinned mutual-authentication transport (`tls-serve`).</summary>
    Tls,
}

/// <summary>Immutable registration record for one firewall host managed by the controller.</summary>
public sealed record ManagedHostRecord
{
    /// <summary>Creates a validated managed host endpoint registration.</summary>
    /// <exception cref="ArgumentException">Identifier, name, endpoint, UID, or pinned thumbprint violates transport bounds.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Numeric UID/GID or enum value is unsupported.</exception>
    public ManagedHostRecord(
        Guid id,
        string name,
        AgentTransportKind transportKind,
        string endpoint,
        uint? expectedServerUserId = null,
        uint? socketGroupId = null,
        string? pinnedServerThumbprint = null,
        ulong lastKnownRevision = 0,
        DateTimeOffset? createdAtUtc = null)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("Host identity cannot be empty.", nameof(id));
        }

        if (!IsValidHostName(name))
        {
            throw new ArgumentException("Host name must be 1..128 ASCII letters, digits, dots, underscores, or hyphens.", nameof(name));
        }

        if (!Enum.IsDefined(transportKind))
        {
            throw new ArgumentOutOfRangeException(nameof(transportKind));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(endpoint);
        if (endpoint.Any(char.IsControl) || endpoint.Length > 512)
        {
            throw new ArgumentException("Endpoint is invalid or exceeds 512 characters.", nameof(endpoint));
        }

        string? normalizedPin = null;
        if (transportKind == AgentTransportKind.Unix)
        {
            if (!endpoint.StartsWith('/') || endpoint.Contains('\0') || new UTF8Encoding(false, true).GetByteCount(endpoint) > 107)
            {
                throw new ArgumentException("Unix transport endpoint must be an absolute path of at most 107 UTF-8 bytes.", nameof(endpoint));
            }

            if (expectedServerUserId is null || expectedServerUserId.Value == uint.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(expectedServerUserId));
            }

            if (socketGroupId == uint.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(socketGroupId));
            }

            if (pinnedServerThumbprint is not null)
            {
                throw new ArgumentException("Unix transport cannot carry a TLS thumbprint.", nameof(pinnedServerThumbprint));
            }
        }
        else
        {
            if (!TryValidateHostPort(endpoint))
            {
                throw new ArgumentException("TLS endpoint must be formatted as host:port or [ipv6]:port.", nameof(endpoint));
            }

            if (expectedServerUserId.HasValue || socketGroupId.HasValue)
            {
                throw new ArgumentException("TLS transport cannot carry Unix UID/GID fields.", nameof(expectedServerUserId));
            }

            normalizedPin = NormalizeSha256(pinnedServerThumbprint);
        }

        Id = id;
        Name = name;
        TransportKind = transportKind;
        Endpoint = endpoint;
        ExpectedServerUserId = expectedServerUserId;
        SocketGroupId = socketGroupId;
        PinnedServerThumbprint = normalizedPin;
        LastKnownRevision = lastKnownRevision;
        CreatedAtUtc = (createdAtUtc ?? DateTimeOffset.UtcNow).ToUniversalTime();
    }

    /// <summary>Gets the stable registered host UUID.</summary>
    public Guid Id { get; }

    /// <summary>Gets the unique display name of the managed host.</summary>
    public string Name { get; }

    /// <summary>Gets the configured control transport type.</summary>
    public AgentTransportKind TransportKind { get; }

    /// <summary>Gets the Unix socket path or remote <c>host:port</c> address.</summary>
    public string Endpoint { get; }

    /// <summary>Gets the expected Linux server UID for Unix transport.</summary>
    public uint? ExpectedServerUserId { get; }

    /// <summary>Gets the optional socket parent GID for Unix transport.</summary>
    public uint? SocketGroupId { get; }

    /// <summary>Gets the canonical lowercase 64-hex SHA-256 server cert thumbprint for TLS transport.</summary>
    public string? PinnedServerThumbprint { get; }

    /// <summary>Gets the latest confirmed or observed policy revision recorded by the controller (0 when unknown).</summary>
    public ulong LastKnownRevision { get; }

    /// <summary>Gets the UTC registration timestamp.</summary>
    public DateTimeOffset CreatedAtUtc { get; }

    internal static bool IsValidHostName(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 128)
        {
            return false;
        }

        foreach (var ch in value)
        {
            if (ch is not ((>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '.' or '-' or '_'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Validates and normalizes a 64-character SHA-256 hex digest into lowercase canonical form.</summary>
    /// <exception cref="ArgumentException">Digest is null, not 64 hex characters, or contains non-hex characters.</exception>
    public static string NormalizeSha256(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length != 64)
        {
            throw new ArgumentException("Pinned SHA-256 thumbprint must be 64 hex characters.", nameof(value));
        }

        Span<char> lower = stackalloc char[64];
        for (var i = 0; i < 64; i++)
        {
            var ch = value[i];
            if (ch is >= '0' and <= '9' or >= 'a' and <= 'f')
            {
                lower[i] = ch;
            }
            else if (ch is >= 'A' and <= 'F')
            {
                lower[i] = (char)(ch + ('a' - 'A'));
            }
            else
            {
                throw new ArgumentException("Pinned SHA-256 thumbprint must contain only hexadecimal characters.", nameof(value));
            }
        }

        return new string(lower);
    }

    private static bool TryValidateHostPort(string endpoint)
    {
        var colon = endpoint.LastIndexOf(':');
        if (colon <= 0 || colon >= endpoint.Length - 1)
        {
            return false;
        }

        if (!int.TryParse(endpoint.AsSpan(colon + 1), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var port) ||
            port is < 1 or > 65535)
        {
            return false;
        }

        var host = endpoint[..colon];
        return !string.IsNullOrWhiteSpace(host) && !host.Any(char.IsWhiteSpace);
    }
}

/// <summary>Immutable controller-persisted policy bundle snapshot indexed by monotonic revision.</summary>
public sealed record PolicyRevisionRecord(
    ulong Revision,
    string PolicyJson,
    string CandidateDigest,
    string CreatedByActor,
    DateTimeOffset CreatedAtUtc,
    string? Summary = null);

/// <summary>Append-only audit record capturing actor attribution, role, action, target, and outcome.</summary>
public sealed record ControllerAuditEntry(
    long Sequence,
    DateTimeOffset TimestampUtc,
    string ActorId,
    string ActorRole,
    string Action,
    string Target,
    ulong? Revision,
    string Outcome,
    string? DetailCode);
