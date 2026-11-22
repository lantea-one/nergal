using System.Collections.Frozen;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace Nergal.RemoteTransport;

/// <summary>Immutable TLS 1.3 mutual-authentication listener configuration.</summary>
public sealed class TlsControlServerOptions
{
    internal readonly IReadOnlyList<byte[]> PinnedClientDigests;

    /// <summary>Creates a pinned mTLS server policy; ambient OS trust stores are never relied upon.</summary>
    /// <param name="listenEndPoint">Local IP address and TCP port to bind (port may be 0 for ephemeral allocation).</param>
    /// <param name="serverCertificate">Server certificate with private key and TLS Server Authentication EKU.</param>
    /// <param name="trustedClientThumbprints">Nonempty set of 64-hex-char SHA-256 client certificate pins.</param>
    /// <param name="exchangeTimeout">Positive per-connection exchange deadline up to 60 seconds; defaults to five seconds.</param>
    /// <param name="timeProvider">Optional UTC clock source for deterministic expiry checks.</param>
    /// <exception cref="ArgumentNullException">Required argument is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Port or exchange timeout is out of range.</exception>
    /// <exception cref="ArgumentException">Certificate lacks a private key or required EKU, or pins are invalid/empty.</exception>
    public TlsControlServerOptions(
        IPEndPoint listenEndPoint,
        X509Certificate2 serverCertificate,
        IEnumerable<string> trustedClientThumbprints,
        TimeSpan? exchangeTimeout = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(listenEndPoint);
        ArgumentNullException.ThrowIfNull(serverCertificate);
        if (listenEndPoint.Port is < 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(listenEndPoint));
        }

        if (!serverCertificate.HasPrivateKey)
        {
            throw new ArgumentException("Server TLS certificate must include its private key.", nameof(serverCertificate));
        }

        if (TlsThumbprintPolicy.IsCertificateAuthority(serverCertificate) ||
            !TlsThumbprintPolicy.HasEnhancedKeyUsage(serverCertificate, TlsThumbprintPolicy.ServerAuthenticationOid))
        {
            throw new ArgumentException("Server TLS certificate must be a non-CA leaf certificate with TLS Server Authentication EKU.", nameof(serverCertificate));
        }

        PinnedClientDigests = TlsThumbprintPolicy.DecodePins(trustedClientThumbprints, out var normalized);
        TrustedClientThumbprints = normalized.ToFrozenSet(StringComparer.Ordinal);
        ListenEndPoint = new IPEndPoint(listenEndPoint.Address, listenEndPoint.Port);
        ServerCertificate = serverCertificate;

        ExchangeTimeout = exchangeTimeout ?? TimeSpan.FromSeconds(5);
        if (ExchangeTimeout <= TimeSpan.Zero || ExchangeTimeout > TimeSpan.FromSeconds(60))
        {
            throw new ArgumentOutOfRangeException(nameof(exchangeTimeout));
        }

        TimeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Gets the configured TCP endpoint to bind.</summary>
    public IPEndPoint ListenEndPoint { get; }

    /// <summary>Gets the server TLS certificate.</summary>
    public X509Certificate2 ServerCertificate { get; }

    /// <summary>Gets the immutable set of allowed canonical client SHA-256 thumbprints.</summary>
    public IReadOnlySet<string> TrustedClientThumbprints { get; }

    /// <summary>Gets the per-connection handshake, request, execution, and reply deadline.</summary>
    public TimeSpan ExchangeTimeout { get; }

    /// <summary>Gets the UTC clock source used for certificate validity checks.</summary>
    public TimeProvider TimeProvider { get; }
}
