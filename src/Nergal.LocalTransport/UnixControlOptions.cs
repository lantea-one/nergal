using System.Collections.Frozen;
using System.Text;

namespace Nergal.LocalTransport;

/// <summary>Immutable local control listener policy; configured UIDs are kernel identities, never request claims.</summary>
public sealed class UnixControlOptions
{
    /// <summary>Creates an explicit local control listener policy with a bounded exchange deadline.</summary>
    /// <param name="socketPath">Absolute NUL-free pathname, at most 107 UTF-8 bytes.</param>
    /// <param name="trustedUserIds">Nonempty explicit UID allowlist; root has no implicit privilege.</param>
    /// <param name="socketGroupId">Optional explicitly provisioned setgid directory group; null selects owner-only access.</param>
    /// <param name="exchangeTimeout">Positive timeout up to 60 seconds; defaults to five seconds.</param>
    /// <exception cref="ArgumentException">Path or peer policy is missing or invalid.</exception>
    /// <exception cref="ArgumentOutOfRangeException">UID/GID is reserved or timeout is unsupported.</exception>
    public UnixControlOptions(
        string socketPath,
        IEnumerable<uint> trustedUserIds,
        uint? socketGroupId = null,
        TimeSpan? exchangeTimeout = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(socketPath);
        ArgumentNullException.ThrowIfNull(trustedUserIds);
        if (!Path.IsPathFullyQualified(socketPath) || socketPath.Contains('\0') || new UTF8Encoding(false, true).GetByteCount(socketPath) > 107)
        {
            throw new ArgumentException("An absolute NUL-free Unix socket pathname of at most 107 UTF-8 bytes is required.", nameof(socketPath));
        }

        SocketPath = Path.GetFullPath(socketPath);
        TrustedUserIds = trustedUserIds.ToFrozenSet();
        if (TrustedUserIds.Count == 0)
        {
            throw new ArgumentException("An explicit nonempty peer UID policy is required.", nameof(trustedUserIds));
        }

        if (TrustedUserIds.Contains(uint.MaxValue))
        {
            throw new ArgumentOutOfRangeException(nameof(trustedUserIds));
        }

        if (socketGroupId == uint.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(socketGroupId));
        }

        SocketGroupId = socketGroupId;
        ExchangeTimeout = exchangeTimeout ?? TimeSpan.FromSeconds(5);
        if (ExchangeTimeout <= TimeSpan.Zero || ExchangeTimeout > TimeSpan.FromSeconds(60))
        {
            throw new ArgumentOutOfRangeException(nameof(exchangeTimeout));
        }
    }

    /// <summary>Gets the canonical absolute listener path.</summary>
    public string SocketPath { get; }

    /// <summary>Gets the immutable explicit peer UID allowlist.</summary>
    public IReadOnlySet<uint> TrustedUserIds { get; }

    /// <summary>Gets the provisioned socket-directory group, or null for owner-only mode.</summary>
    public uint? SocketGroupId { get; }

    /// <summary>Gets the per-connection deadline for framing, execution, and reply delivery.</summary>
    public TimeSpan ExchangeTimeout { get; }
}
