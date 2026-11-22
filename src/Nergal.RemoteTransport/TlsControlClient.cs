using System.Collections.Frozen;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Nergal.Core.Agent;

namespace Nergal.RemoteTransport;

/// <summary>Immutable TLS 1.3 mutual-authentication client configuration.</summary>
public sealed class TlsControlClientOptions
{
    internal readonly IReadOnlyList<byte[]> PinnedServerDigests;

    /// <summary>Creates a pinned mTLS client policy; ambient OS root CAs are never relied upon.</summary>
    /// <param name="targetHost">Remote agent IP address or hostname to connect to.</param>
    /// <param name="port">Remote TLS control TCP port in 1..65535.</param>
    /// <param name="clientCertificate">Client certificate with private key and TLS Client Authentication EKU.</param>
    /// <param name="trustedServerThumbprints">Nonempty set of 64-hex-char SHA-256 server certificate pins.</param>
    /// <param name="serverNameIndication">Optional SNI value; defaults to <paramref name="targetHost"/>.</param>
    /// <param name="exchangeTimeout">Positive total exchange deadline up to 60 seconds; defaults to five seconds.</param>
    /// <param name="timeProvider">Optional UTC clock source for deterministic expiry checks.</param>
    /// <exception cref="ArgumentNullException">Required argument is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Port or timeout is out of range.</exception>
    /// <exception cref="ArgumentException">Host, certificate, or pins are invalid.</exception>
    public TlsControlClientOptions(
        string targetHost,
        int port,
        X509Certificate2 clientCertificate,
        IEnumerable<string> trustedServerThumbprints,
        string? serverNameIndication = null,
        TimeSpan? exchangeTimeout = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetHost);
        ArgumentNullException.ThrowIfNull(clientCertificate);
        if (port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }

        if (!clientCertificate.HasPrivateKey)
        {
            throw new ArgumentException("Client TLS certificate must include its private key.", nameof(clientCertificate));
        }

        if (TlsThumbprintPolicy.IsCertificateAuthority(clientCertificate) ||
            !TlsThumbprintPolicy.HasEnhancedKeyUsage(clientCertificate, TlsThumbprintPolicy.ClientAuthenticationOid))
        {
            throw new ArgumentException("Client TLS certificate must be a non-CA leaf certificate with TLS Client Authentication EKU.", nameof(clientCertificate));
        }

        PinnedServerDigests = TlsThumbprintPolicy.DecodePins(trustedServerThumbprints, out var normalized);
        TrustedServerThumbprints = normalized.ToFrozenSet(StringComparer.Ordinal);
        TargetHost = targetHost.Trim();
        Port = port;
        ClientCertificate = clientCertificate;

        var sni = string.IsNullOrWhiteSpace(serverNameIndication) ? TargetHost : serverNameIndication.Trim();
        ServerNameIndication = sni;

        ExchangeTimeout = exchangeTimeout ?? TimeSpan.FromSeconds(5);
        if (ExchangeTimeout <= TimeSpan.Zero || ExchangeTimeout > TimeSpan.FromSeconds(60))
        {
            throw new ArgumentOutOfRangeException(nameof(exchangeTimeout));
        }

        TimeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Gets the target agent host or IP address.</summary>
    public string TargetHost { get; }

    /// <summary>Gets the target TCP port.</summary>
    public int Port { get; }

    /// <summary>Gets the client mTLS certificate.</summary>
    public X509Certificate2 ClientCertificate { get; }

    /// <summary>Gets the immutable set of allowed canonical server SHA-256 thumbprints.</summary>
    public IReadOnlySet<string> TrustedServerThumbprints { get; }

    /// <summary>Gets the TLS SNI hostname sent during handshake.</summary>
    public string ServerNameIndication { get; }

    /// <summary>Gets the deadline for connect, TLS handshake, request send, and reply EOF.</summary>
    public TimeSpan ExchangeTimeout { get; }

    /// <summary>Gets the UTC clock source used for server certificate validity checks.</summary>
    public TimeProvider TimeProvider { get; }
}

/// <summary>Fail-closed TLS 1.3 pinned mutual-authentication client for typed agent control requests.</summary>
public static class TlsControlClient
{
    /// <summary>Sends one framed control request over TLS 1.3 mTLS to a pinned agent certificate.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> or <paramref name="request"/> is null.</exception>
    /// <exception cref="RemoteTransportException">Connect, TLS 1.3 handshake, pin verification, or framing fails.</exception>
    public static async Task<AgentControlReply> SendAsync(
        TlsControlClientOptions options,
        AgentControlRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(request);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(options.ExchangeTimeout);

        using var tcp = new TcpClient();
        try
        {
            await tcp.ConnectAsync(options.TargetHost, options.Port, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new RemoteTransportException("exchange.timeout");
        }
        catch (SocketException ex)
        {
            throw new RemoteTransportException("tcp.connect", ex);
        }

        tcp.NoDelay = true;
        using var network = tcp.GetStream();
        using var ssl = new SslStream(
            network,
            leaveInnerStreamOpen: false,
            (_, certificate, _, _) => TlsThumbprintPolicy.ValidatePeerCertificate(
                certificate,
                options.PinnedServerDigests,
                TlsThumbprintPolicy.ServerAuthenticationOid,
                options.TimeProvider.GetUtcNow()));

        var authOptions = new SslClientAuthenticationOptions
        {
            TargetHost = options.ServerNameIndication,
            ClientCertificates = [options.ClientCertificate],
            LocalCertificateSelectionCallback = (_, _, _, _, _) => options.ClientCertificate,
            EnabledSslProtocols = SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        };

        try
        {
            await ssl.AuthenticateAsClientAsync(authOptions, cts.Token).ConfigureAwait(false);

            if (ssl.SslProtocol != SslProtocols.Tls13 ||
                !ssl.IsAuthenticated ||
                !ssl.IsMutuallyAuthenticated ||
                !TlsThumbprintPolicy.ValidatePeerCertificate(
                    ssl.RemoteCertificate,
                    options.PinnedServerDigests,
                    TlsThumbprintPolicy.ServerAuthenticationOid,
                    options.TimeProvider.GetUtcNow()))
            {
                throw new RemoteTransportException("tls.authentication");
            }

            var requestFrame = AgentControlFrame.Encode(AgentControlCodec.EncodeRequest(request));
            await ssl.WriteAsync(requestFrame, cts.Token).ConfigureAwait(false);
            await ssl.FlushAsync(cts.Token).ConfigureAwait(false);

            var header = await ReadExactAsync(ssl, AgentControlFrame.HeaderLength, cts.Token).ConfigureAwait(false);
            int length;
            try
            {
                length = AgentControlFrame.ReadPayloadLength(header);
            }
            catch (StatusFrameException ex)
            {
                throw new RemoteTransportException("reply.frame", ex);
            }

            var payload = await ReadExactAsync(ssl, length, cts.Token).ConfigureAwait(false);
            var extra = new byte[1];
            if (await ssl.ReadAsync(extra, cts.Token).ConfigureAwait(false) != 0)
            {
                throw new RemoteTransportException("reply.trailing");
            }

            var decoded = AgentControlCodec.DecodeReply(payload);
            if (!decoded.IsValid)
            {
                throw new RemoteTransportException("reply.invalid");
            }

            return decoded.Reply!;
        }
        catch (RemoteTransportException)
        {
            throw;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new RemoteTransportException("exchange.timeout");
        }
        catch (AuthenticationException ex)
        {
            throw new RemoteTransportException("tls.authentication", ex);
        }
        catch (IOException ex)
        {
            throw new RemoteTransportException("exchange.io", ex);
        }
        catch (SocketException ex)
        {
            throw new RemoteTransportException("exchange.socket", ex);
        }
    }

    private static async Task<byte[]> ReadExactAsync(Stream stream, int length, CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        var offset = 0;
        while (offset < length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, length - offset), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new RemoteTransportException("reply.truncated");
            }

            offset += read;
        }

        return buffer;
    }
}
