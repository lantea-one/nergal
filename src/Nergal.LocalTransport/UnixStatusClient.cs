using System.Net.Sockets;
using System.Runtime.Versioning;
using Nergal.Core.Agent;
using Nergal.Linux;

namespace Nergal.LocalTransport;

/// <summary>Unprivileged status-only client that authenticates kernel server identity before sending intent.</summary>
/// <remarks>Trusted parent paths and nondelegation of authenticated descriptors are prerequisites. No retries, state writes or mutation commands exist.</remarks>
public sealed class UnixStatusClient
{
    private readonly UnixStatusClientOptions options;

    /// <summary>Creates a reusable client policy; each query opens a new bounded connection.</summary>
    /// <exception cref="ArgumentNullException">Options are null.</exception>
    public UnixStatusClient(UnixStatusClientOptions options)
        => this.options = options ?? throw new ArgumentNullException(nameof(options));

    /// <summary>Returns only a complete typed reply from the explicitly authenticated server.</summary>
    /// <exception cref="LocalTransportException">Peer/path identity, transport, deadline or complete reply validation fails. No partial status is returned.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation interrupts the exchange.</exception>
    /// <exception cref="PlatformNotSupportedException">The native platform is unsupported.</exception>
    [SupportedOSPlatform("linux")]
    public async Task<AgentStatusReply> QueryAsync(CancellationToken cancellationToken = default)
    {
        UnixSocketPathPolicy.RequireSupportedPlatform();
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(options.ExchangeTimeout);
        try
        {
            RequireUnambiguousServer();
            UnixSocketPathPolicy.RequireParent(options.SocketPath, options.ExpectedServerUserId, options.SocketGroupId);
            var expected = UnixSocketPathPolicy.RequireSocket(options.SocketPath, options.ExpectedServerUserId, options.SocketGroupId);
            using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(options.SocketPath), deadline.Token);
            var peer = UnixPeerCredentials.ReadUserId(socket);
            RequireUnambiguousServer();
            if (peer != options.ExpectedServerUserId)
            {
                throw new LocalTransportException("server.denied");
            }

            UnixSocketPathPolicy.RequireParent(options.SocketPath, options.ExpectedServerUserId, options.SocketGroupId);
            if (UnixSocketPathPolicy.RequireSocket(options.SocketPath, options.ExpectedServerUserId, options.SocketGroupId) != expected)
            {
                throw new LocalTransportException("socket.pathChanged");
            }

            using var stream = new NetworkStream(socket, ownsSocket: false);
            await stream.WriteAsync(AgentStatusFrame.Encode(AgentStatusCodec.EncodeRequest()), deadline.Token);
            socket.Shutdown(SocketShutdown.Send);
            var header = new byte[AgentStatusFrame.HeaderLength];
            await stream.ReadExactlyAsync(header, deadline.Token);
            var payload = new byte[AgentStatusFrame.ReadPayloadLength(header)];
            await stream.ReadExactlyAsync(payload, deadline.Token);
            if (await stream.ReadAsync(new byte[1], deadline.Token) != 0)
            {
                throw new LocalTransportException("reply.invalid");
            }

            var decoded = AgentStatusCodec.DecodeReply(payload);
            deadline.Token.ThrowIfCancellationRequested();
            return decoded.Reply ?? throw new LocalTransportException("reply.invalid");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { throw new LocalTransportException("exchange.timeout"); }
        catch (Exception error) when (error is EndOfStreamException or StatusFrameException)
        { throw new LocalTransportException("reply.invalid"); }
        catch (Exception error) when (error is IOException or SocketException or UnauthorizedAccessException)
        { throw new LocalTransportException("exchange.unavailable"); }
    }

    [SupportedOSPlatform("linux")]
    private void RequireUnambiguousServer()
    {
        if (options.ExpectedServerUserId == LinuxProcessIdentity.ReadOverflowUserId())
        {
            throw new LocalTransportException("peer.overflowUid");
        }
    }
}
