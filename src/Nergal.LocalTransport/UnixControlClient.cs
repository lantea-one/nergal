using System.Net.Sockets;
using System.Runtime.Versioning;
using Nergal.Core.Agent;
using Nergal.Linux;

namespace Nergal.LocalTransport;

/// <summary>Fail-closed Unix domain socket client for authenticated typed agent control requests.</summary>
[SupportedOSPlatform("linux")]
public static class UnixControlClient
{
    /// <summary>Sends one framed control request to an expected local agent UID and verifies the reply.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> or <paramref name="request"/> is null.</exception>
    /// <exception cref="PlatformNotSupportedException">Host is not Linux x64 or arm64.</exception>
    /// <exception cref="LocalTransportException">Path policy, kernel peer UID, framing, or reply validation fails.</exception>
    public static async Task<AgentControlReply> SendAsync(
        UnixControlClientOptions options,
        AgentControlRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(request);
        UnixSocketPathPolicy.RequireSupportedPlatform();

        if (options.ExpectedServerUserId == LinuxProcessIdentity.ReadOverflowUserId())
        {
            throw new LocalTransportException("policy.overflowUid");
        }

        UnixSocketPathPolicy.RequireParent(options.SocketPath, options.ExpectedServerUserId, options.SocketGroupId);
        var initialNode = UnixSocketPathPolicy.RequireSocket(options.SocketPath, options.ExpectedServerUserId, options.SocketGroupId);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(options.ExchangeTimeout);

        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(options.SocketPath), cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new LocalTransportException("exchange.timeout");
        }
        catch (SocketException)
        {
            throw new LocalTransportException("socket.connect");
        }

        var connectedNode = UnixSocketPathPolicy.RequireSocket(options.SocketPath, options.ExpectedServerUserId, options.SocketGroupId);
        if (connectedNode.Inode != initialNode.Inode ||
            connectedNode.DeviceMajor != initialNode.DeviceMajor ||
            connectedNode.DeviceMinor != initialNode.DeviceMinor)
        {
            throw new LocalTransportException("socket.replaced");
        }

        var peerUid = UnixPeerCredentials.ReadUserId(socket);
        if (peerUid != options.ExpectedServerUserId)
        {
            throw new LocalTransportException("peer.unexpected");
        }

        try
        {
            using var stream = new NetworkStream(socket, ownsSocket: false);
            var requestFrame = AgentControlFrame.Encode(AgentControlCodec.EncodeRequest(request));
            try
            {
                await stream.WriteAsync(requestFrame, cts.Token).ConfigureAwait(false);
                socket.Shutdown(SocketShutdown.Send);
            }
            catch (Exception ex) when (ex is IOException or SocketException)
            {
                // Server may immediately enqueue a Denied/Busy frame and close before draining client bytes.
            }

            var header = await ReadExactAsync(stream, AgentControlFrame.HeaderLength, cts.Token).ConfigureAwait(false);
            int length;
            try
            {
                length = AgentControlFrame.ReadPayloadLength(header);
            }
            catch (StatusFrameException)
            {
                throw new LocalTransportException("reply.frame");
            }

            var payload = await ReadExactAsync(stream, length, cts.Token).ConfigureAwait(false);
            var decoded = AgentControlCodec.DecodeReply(payload);
            if (!decoded.IsValid)
            {
                throw new LocalTransportException("reply.invalid");
            }

            var extra = new byte[1];
            try
            {
                if (await stream.ReadAsync(extra, cts.Token).ConfigureAwait(false) != 0)
                {
                    throw new LocalTransportException("reply.trailing");
                }
            }
            catch (Exception ex) when (ex is IOException or SocketException)
            {
                // Server may reset/close the stream immediately after sending a complete reply frame.
            }

            return decoded.Reply!;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new LocalTransportException("exchange.timeout");
        }
        catch (LocalTransportException)
        {
            throw;
        }
        catch (IOException)
        {
            throw new LocalTransportException("exchange.io");
        }
        catch (SocketException)
        {
            throw new LocalTransportException("exchange.socket");
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
                throw new LocalTransportException("reply.truncated");
            }

            offset += read;
        }

        return buffer;
    }
}
