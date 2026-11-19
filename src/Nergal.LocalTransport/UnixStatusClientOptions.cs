namespace Nergal.LocalTransport;

/// <summary>Explicit expected local server identity and bounded status exchange policy.</summary>
public sealed class UnixStatusClientOptions
{
    /// <summary>Creates a status client policy with no implicit server UID or automatic discovery.</summary>
    /// <param name="socketPath">Absolute NUL-free pathname, at most 107 UTF-8 bytes.</param>
    /// <param name="expectedServerUserId">Explicit server kernel UID; root is accepted only when explicitly configured.</param>
    /// <param name="socketGroupId">Provisioned socket group, or null for the owner-only path policy.</param>
    /// <param name="exchangeTimeout">Positive total exchange timeout up to 30 seconds, default two seconds.</param>
    /// <exception cref="ArgumentException">Path is missing or invalid.</exception>
    /// <exception cref="ArgumentOutOfRangeException">UID/GID is reserved or timeout is unsupported.</exception>
    public UnixStatusClientOptions(string socketPath, uint expectedServerUserId, uint? socketGroupId = null, TimeSpan? exchangeTimeout = null)
    {
        if (expectedServerUserId == uint.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedServerUserId));
        }

        // Reuse the same pathname, group and deadline invariants on both sides.
        var validated = new UnixStatusOptions(socketPath, [expectedServerUserId], socketGroupId, exchangeTimeout);
        SocketPath = validated.SocketPath;
        ExpectedServerUserId = expectedServerUserId;
        SocketGroupId = validated.SocketGroupId;
        ExchangeTimeout = validated.ExchangeTimeout;
    }
    /// <summary>Gets the canonical absolute server pathname.</summary>
    public string SocketPath { get; }
    /// <summary>Gets the explicit expected kernel server UID.</summary>
    public uint ExpectedServerUserId { get; }
    /// <summary>Gets the provisioned socket group, or null for owner-only mode.</summary>
    public uint? SocketGroupId { get; }
    /// <summary>Gets the deadline for the entire exchange, including connect and reply EOF.</summary>
    public TimeSpan ExchangeTimeout { get; }
}
