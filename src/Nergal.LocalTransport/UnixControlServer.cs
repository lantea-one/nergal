using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Runtime.Versioning;
using Nergal.Core.Agent;
using Nergal.Linux;

namespace Nergal.LocalTransport;

/// <summary>Kernel-authenticated local Unix domain socket listener for typed agent control exchanges.</summary>
[SupportedOSPlatform("linux")]
public sealed class UnixControlServer : IDisposable
{
    private const int MaximumConcurrentExchanges = 4;

    private readonly UnixControlOptions _options;
    private readonly Socket _listener;
    private readonly uint _ownerUid;
    private readonly LinuxNodeMetadata _boundNode;
    private int _disposed;

    private UnixControlServer(UnixControlOptions options, Socket listener, uint ownerUid, LinuxNodeMetadata boundNode)
    {
        _options = options;
        _listener = listener;
        _ownerUid = ownerUid;
        _boundNode = boundNode;
    }

    /// <summary>Gets the canonical absolute bound socket path.</summary>
    public string SocketPath => _options.SocketPath;

    /// <summary>Binds a fail-closed local control listener on an explicit socket path.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="PlatformNotSupportedException">Host is not Linux x64 or arm64.</exception>
    /// <exception cref="LocalTransportException">Parent directory policy, overflow UID check, or socket binding fails.</exception>
    public static UnixControlServer Bind(UnixControlOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        UnixSocketPathPolicy.RequireSupportedPlatform();

        if (options.TrustedUserIds.Contains(LinuxProcessIdentity.ReadOverflowUserId()))
        {
            throw new LocalTransportException("policy.overflowUid");
        }

        var owner = LinuxProcessIdentity.EffectiveUserId;
        UnixSocketPathPolicy.RequireParent(options.SocketPath, owner, options.SocketGroupId);

        if (LinuxFileSystem.Read(options.SocketPath) is not null)
        {
            throw new LocalTransportException("socket.exists");
        }

        var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        var bound = false;
        try
        {
            listener.Bind(new UnixDomainSocketEndPoint(options.SocketPath));
            bound = true;

            var mode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            if (options.SocketGroupId.HasValue)
            {
                mode |= UnixFileMode.GroupRead | UnixFileMode.GroupWrite;
            }

            File.SetUnixFileMode(options.SocketPath, mode);
            listener.Listen(16);

            var node = UnixSocketPathPolicy.RequireSocket(options.SocketPath, owner, options.SocketGroupId);
            return new UnixControlServer(options, listener, owner, node);
        }
        catch (LocalTransportException)
        {
            CleanupFailedBind(listener, options.SocketPath, bound, owner);
            throw;
        }
        catch (SocketException)
        {
            CleanupFailedBind(listener, options.SocketPath, bound, owner);
            throw new LocalTransportException("socket.bind");
        }
        catch (UnauthorizedAccessException)
        {
            CleanupFailedBind(listener, options.SocketPath, bound, owner);
            throw new LocalTransportException("socket.access");
        }
    }

    /// <summary>Serves authenticated typed control requests until <paramref name="cancellationToken"/> is cancelled.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="handler"/> is null.</exception>
    /// <exception cref="ObjectDisposedException">Server has already been disposed.</exception>
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
            Socket client;
            try
            {
                client = await _listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
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

            uint peerUid;
            try
            {
                peerUid = UnixPeerCredentials.ReadUserId(client);
            }
            catch (LocalTransportException)
            {
                client.Dispose();
                continue;
            }

            if (!_options.TrustedUserIds.Contains(peerUid))
            {
                await TrySendBestEffortReplyAsync(client, new AgentControlReply(AgentControlOutcome.Denied)).ConfigureAwait(false);
                client.Dispose();
                continue;
            }

            if (!gate.Wait(0))
            {
                await TrySendBestEffortReplyAsync(client, new AgentControlReply(AgentControlOutcome.Busy, errorCode: "server.busy")).ConfigureAwait(false);
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
        try
        {
            var current = LinuxFileSystem.Read(_options.SocketPath);
            if (current is { Type: LinuxNodeType.Socket } node &&
                node.OwnerUserId == _ownerUid &&
                node.Inode == _boundNode.Inode &&
                node.DeviceMajor == _boundNode.DeviceMajor &&
                node.DeviceMinor == _boundNode.DeviceMinor)
            {
                File.Delete(_options.SocketPath);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private async Task HandleClientAsync(
        Socket client,
        Func<AgentControlRequest, CancellationToken, Task<AgentControlReply>> handler,
        CancellationToken serverCancellation)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(serverCancellation);
        cts.CancelAfter(_options.ExchangeTimeout);

        try
        {
            using var stream = new NetworkStream(client, ownsSocket: false);
            var header = await ReadExactAsync(stream, AgentControlFrame.HeaderLength, cts.Token).ConfigureAwait(false);
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
                await WriteReplyAsync(stream, new AgentControlReply(AgentControlOutcome.InvalidRequest), cts.Token).ConfigureAwait(false);
                return;
            }

            var payload = await ReadExactAsync(stream, length, cts.Token).ConfigureAwait(false);
            if (payload is null)
            {
                return;
            }

            var decoded = AgentControlCodec.DecodeRequest(payload);
            if (!decoded.IsValid)
            {
                await WriteReplyAsync(stream, new AgentControlReply(AgentControlOutcome.InvalidRequest), cts.Token).ConfigureAwait(false);
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

            await WriteReplyAsync(stream, reply, cts.Token).ConfigureAwait(false);
            try
            {
                client.Shutdown(SocketShutdown.Send);
            }
            catch (SocketException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
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

    private static async Task TrySendBestEffortReplyAsync(Socket client, AgentControlReply reply)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
        try
        {
            using var stream = new NetworkStream(client, ownsSocket: false);
            await WriteReplyAsync(stream, reply, cts.Token).ConfigureAwait(false);
            client.Shutdown(SocketShutdown.Send);
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
        catch (ObjectDisposedException)
        {
        }
    }

    private static Task WriteReplyAsync(Stream stream, AgentControlReply reply, CancellationToken cancellationToken)
    {
        var frame = AgentControlFrame.Encode(AgentControlCodec.EncodeReply(reply));
        return stream.WriteAsync(frame, cancellationToken).AsTask();
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

    private static void CleanupFailedBind(Socket listener, string socketPath, bool bound, uint ownerUid)
    {
        listener.Dispose();
        if (!bound)
        {
            return;
        }

        try
        {
            if (LinuxFileSystem.Read(socketPath) is { Type: LinuxNodeType.Socket } node && node.OwnerUserId == ownerUid)
            {
                File.Delete(socketPath);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
