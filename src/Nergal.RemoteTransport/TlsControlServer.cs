using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Nergal.Core.Agent;

namespace Nergal.RemoteTransport;

/// <summary>TLS 1.3 pinned mutual-authentication listener for typed agent control exchanges.</summary>
public sealed class TlsControlServer : IDisposable
{
    private const int MaximumConcurrentExchanges = 4;

    private readonly TlsControlServerOptions _options;
    private readonly TcpListener _listener;
    private int _disposed;

    private TlsControlServer(TlsControlServerOptions options, TcpListener listener)
    {
        _options = options;
        _listener = listener;
        BoundEndPoint = (IPEndPoint)listener.LocalEndpoint;
    }

    /// <summary>Gets the actual bound TCP endpoint (with resolved port when port 0 was configured).</summary>
    public IPEndPoint BoundEndPoint { get; }

    /// <summary>Binds a TLS 1.3 mTLS control listener on the configured endpoint.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="RemoteTransportException">Socket binding fails.</exception>
    public static TlsControlServer Bind(TlsControlServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var listener = new TcpListener(options.ListenEndPoint);
        try
        {
            if (options.ListenEndPoint.Address.Equals(IPAddress.IPv6Any))
            {
                listener.Server.DualMode = true;
            }

            listener.Start(16);
            return new TlsControlServer(options, listener);
        }
        catch (SocketException ex)
        {
            listener.Dispose();
            throw new RemoteTransportException("tcp.bind", ex);
        }
    }

    /// <summary>Accepts and serves authenticated TLS 1.3 control requests until cancelled.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="handler"/> is null.</exception>
    /// <exception cref="ObjectDisposedException">Listener has already been disposed.</exception>
    public async Task ServeAsync(
        Func<AgentControlRequest, CancellationToken, Task<AgentControlReply>> handler,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(handler);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        using var gate = new SemaphoreSlim(MaximumConcurrentExchanges, MaximumConcurrentExchanges);
        var inFlight = new ConcurrentDictionary<Task, byte>();

        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException)
            {
                continue;
            }

            if (!gate.Wait(0))
            {
                client.Dispose();
                continue;
            }

            Task? tracked = null;
            tracked = Task.Run(async () =>
            {
                try
                {
                    await HandleClientAsync(client, handler, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    gate.Release();
                    client.Dispose();
                    if (tracked is not null)
                    {
                        inFlight.TryRemove(tracked, out _);
                    }
                }
            }, CancellationToken.None);

            inFlight[tracked] = 0;
        }

        await Task.WhenAll(inFlight.Keys).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _listener.Dispose();
    }

    private async Task HandleClientAsync(
        TcpClient client,
        Func<AgentControlRequest, CancellationToken, Task<AgentControlReply>> handler,
        CancellationToken serverCancellation)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(serverCancellation);
        cts.CancelAfter(_options.ExchangeTimeout);

        try
        {
            client.NoDelay = true;
            using var network = client.GetStream();
            using var ssl = new SslStream(
                network,
                leaveInnerStreamOpen: false,
                (_, certificate, _, _) => TlsThumbprintPolicy.ValidatePeerCertificate(
                    certificate,
                    _options.PinnedClientDigests,
                    TlsThumbprintPolicy.ClientAuthenticationOid,
                    _options.TimeProvider.GetUtcNow()));

            var authOptions = new SslServerAuthenticationOptions
            {
                ServerCertificate = _options.ServerCertificate,
                ClientCertificateRequired = true,
                EnabledSslProtocols = SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            };

            await ssl.AuthenticateAsServerAsync(authOptions, cts.Token).ConfigureAwait(false);

            if (ssl.SslProtocol != SslProtocols.Tls13 ||
                !ssl.IsAuthenticated ||
                !ssl.IsMutuallyAuthenticated ||
                !TlsThumbprintPolicy.ValidatePeerCertificate(
                    ssl.RemoteCertificate,
                    _options.PinnedClientDigests,
                    TlsThumbprintPolicy.ClientAuthenticationOid,
                    _options.TimeProvider.GetUtcNow()))
            {
                return;
            }

            var header = await ReadExactAsync(ssl, AgentControlFrame.HeaderLength, cts.Token).ConfigureAwait(false);
            if (header is null)
            {
                return;
            }

            int length;
            try
            {
                length = AgentControlFrame.ReadPayloadLength(header);
            }
            catch (StatusFrameException)
            {
                await WriteReplyAsync(ssl, new AgentControlReply(AgentControlOutcome.InvalidRequest), cts.Token).ConfigureAwait(false);
                await ssl.ShutdownAsync().ConfigureAwait(false);
                return;
            }

            var payload = await ReadExactAsync(ssl, length, cts.Token).ConfigureAwait(false);
            if (payload is null)
            {
                return;
            }

            var decoded = AgentControlCodec.DecodeRequest(payload);
            if (!decoded.IsValid)
            {
                await WriteReplyAsync(ssl, new AgentControlReply(AgentControlOutcome.InvalidRequest), cts.Token).ConfigureAwait(false);
                await ssl.ShutdownAsync().ConfigureAwait(false);
                return;
            }

            AgentControlReply reply;
            try
            {
                reply = await handler(decoded.Request!, cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (serverCancellation.IsCancellationRequested)
            {
                return;
            }
            catch (OperationCanceledException)
            {
                reply = new AgentControlReply(AgentControlOutcome.Unavailable, errorCode: "agent.timeout");
            }
            catch (Exception)
            {
                reply = new AgentControlReply(AgentControlOutcome.Unavailable, errorCode: "agent.error");
            }

            await WriteReplyAsync(ssl, reply, cts.Token).ConfigureAwait(false);
            await ssl.ShutdownAsync().ConfigureAwait(false);
        }
        catch (AuthenticationException)
        {
        }
        catch (OperationCanceledException)
        {
        }
        catch (IOException)
        {
        }
        catch (SocketException)
        {
        }
    }

    private static async Task WriteReplyAsync(SslStream ssl, AgentControlReply reply, CancellationToken cancellationToken)
    {
        var frame = AgentControlFrame.Encode(AgentControlCodec.EncodeReply(reply));
        await ssl.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        await ssl.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadExactAsync(Stream stream, int length, CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        var offset = 0;
        while (offset < length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, length - offset), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return null;
            }

            offset += read;
        }

        return buffer;
    }
}
