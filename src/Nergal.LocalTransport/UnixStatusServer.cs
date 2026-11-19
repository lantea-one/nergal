using System.Net.Sockets;
using System.Runtime.Versioning;
using Nergal.Core.Agent;
using Nergal.Linux;

namespace Nergal.LocalTransport;

/// <summary>Linux peer-authorized status-only listener. Has no database, firewall, shell or arbitrary-command functionality.</summary>
/// <remarks>Caller provisions a trusted service-owned parent and must cancel/await serving before disposal. Providers must be read-only, asynchronous and honor cancellation.</remarks>
[SupportedOSPlatform("linux")]
public sealed class UnixStatusServer : IDisposable
{
    private readonly Socket listener;
    private readonly UnixStatusOptions options;
    private readonly LinuxNodeMetadata created;
    private int disposed;
    private int serving;

    private UnixStatusServer(Socket listener, UnixStatusOptions options, LinuxNodeMetadata created)
    {
        this.listener = listener;
        this.options = options;
        this.created = created;
    }

    /// <summary>Binds a new pathname socket after protection checks; never deletes/adopts an existing path.</summary>
    /// <exception cref="LocalTransportException">Identity, path, mode, overflow-UID policy or native binding cannot be established.</exception>
    /// <exception cref="ArgumentNullException">Options are null.</exception>
    public static UnixStatusServer Bind(UnixStatusOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!OperatingSystem.IsLinux() || System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture is not
            (System.Runtime.InteropServices.Architecture.X64 or System.Runtime.InteropServices.Architecture.Arm64))
        {
            throw new PlatformNotSupportedException("Local peer status requires Linux x64 or arm64.");
        }

        if (options.TrustedUserIds.Contains(LinuxProcessIdentity.ReadOverflowUserId()))
        {
            throw new LocalTransportException("peer.overflowUid");
        }

        var parent = Path.GetDirectoryName(options.SocketPath) ?? throw new LocalTransportException("socket.parent");
        for (DirectoryInfo? part = new(parent); part is not null; part = part.Parent)
        {
            if (part.LinkTarget is not null)
            {
                throw new LocalTransportException("socket.symlink");
            }
        }

        var directory = LinuxFileSystem.Read(parent) ?? throw new LocalTransportException("socket.parentMissing");
        var expectedDirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        if (options.SocketGroupId.HasValue)
        {
            expectedDirectoryMode |= UnixFileMode.GroupExecute | UnixFileMode.SetGroup;
        }

        if (directory.Type != LinuxNodeType.Directory || directory.OwnerUserId != LinuxProcessIdentity.EffectiveUserId ||
            directory.Permissions != expectedDirectoryMode || (options.SocketGroupId is { } group && directory.OwnerGroupId != group))
        {
            throw new LocalTransportException("socket.parentPolicy");
        }

        if (LinuxFileSystem.Read(options.SocketPath) is not null)
        {
            throw new LocalTransportException("socket.exists");
        }

        var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        LinuxNodeMetadata? created = null;
        try
        {
            listener.Bind(new ExplicitCleanupEndPoint(options.SocketPath));
            created = LinuxFileSystem.Read(options.SocketPath) ?? throw new LocalTransportException("socket.metadata");
            var expectedGroup = options.SocketGroupId ?? LinuxProcessIdentity.EffectiveGroupId;
            if (created.Value.Type != LinuxNodeType.Socket || created.Value.OwnerUserId != LinuxProcessIdentity.EffectiveUserId ||
                created.Value.OwnerGroupId != expectedGroup || created.Value.LinkCount != 1 || created.Value.Inode == 0)
            {
                throw new LocalTransportException("socket.metadata");
            }

            var mode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            if (options.SocketGroupId.HasValue)
            {
                mode |= UnixFileMode.GroupRead | UnixFileMode.GroupWrite;
            }

            File.SetUnixFileMode(options.SocketPath, mode);
            var verified = LinuxFileSystem.Read(options.SocketPath) ?? throw new LocalTransportException("socket.metadata");
            if (!SameNode(created.Value, verified) || verified.Permissions != mode)
            {
                throw new LocalTransportException("socket.metadata");
            }

            listener.Listen(16);
            return new(listener, options, created.Value);
        }
        catch
        {
            listener.Dispose();
            if (created is { } own)
            {
                RemoveOwnSocket(options.SocketPath, own);
            }

            throw;
        }
    }

    /// <summary>Serves one bounded request per connection; authenticates kernel peer UID before reading bytes or invoking the provider.</summary>
    /// <param name="provider">Trusted read-only asynchronous status source; receives no client-supplied fields.</param>
    /// <param name="cancellationToken">Listener lifetime cancellation.</param>
    /// <exception cref="InvalidOperationException">A serve loop is already active.</exception>
    /// <exception cref="ArgumentNullException">Provider is null.</exception>
    public async Task ServeAsync(Func<CancellationToken, ValueTask<AgentStatusReply>> provider, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(provider);
        if (Interlocked.Exchange(ref serving, 1) != 0)
        {
            throw new InvalidOperationException("A serve loop is already active.");
        }

        try
        {
            while (!cancellationToken.IsCancellationRequested && Volatile.Read(ref disposed) == 0)
            {
                Socket client;
                try { client = await listener.AcceptAsync(cancellationToken); }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
                catch (ObjectDisposedException) when (Volatile.Read(ref disposed) != 0) { break; }
                using (client)
                {
                    await Exchange(client, provider, cancellationToken);
                }
            }
        }
        finally { Volatile.Write(ref serving, 0); }
    }

    private async Task Exchange(Socket client, Func<CancellationToken, ValueTask<AgentStatusReply>> provider, CancellationToken lifetime)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(lifetime);
        deadline.CancelAfter(options.ExchangeTimeout);
        using var stream = new NetworkStream(client, ownsSocket: false);
        try
        {
            uint peer;
            try { peer = UnixPeerCredentials.ReadUserId(client); }
            catch (LocalTransportException) { await Send(stream, new(AgentStatusOutcome.Denied), deadline.Token); return; }
            if (peer == LinuxProcessIdentity.ReadOverflowUserId() || !options.TrustedUserIds.Contains(peer))
            { await Send(stream, new(AgentStatusOutcome.Denied), deadline.Token); return; }
            AgentStatusReply reply;
            try
            {
                var header = new byte[AgentStatusFrame.HeaderLength];
                await stream.ReadExactlyAsync(header, deadline.Token);
                var payload = new byte[AgentStatusFrame.ReadPayloadLength(header)];
                await stream.ReadExactlyAsync(payload, deadline.Token);
                var extra = new byte[1];
                if (await stream.ReadAsync(extra, deadline.Token) != 0 || !AgentStatusCodec.DecodeRequest(payload).IsValid)
                {
                    reply = new(AgentStatusOutcome.InvalidRequest);
                }
                else
                {
                    try { reply = await provider(deadline.Token).AsTask().WaitAsync(deadline.Token); }
                    catch (Exception error) when (error is IOException or OperationCanceledException or InvalidOperationException)
                    { reply = new(AgentStatusOutcome.Unavailable); }
                }
            }
            catch (Exception error) when (error is EndOfStreamException or StatusFrameException or OperationCanceledException)
            { reply = new(AgentStatusOutcome.InvalidRequest); }
            // A timed-out exchange receives no extension; close rather than create an unbounded error write.
            if (!deadline.IsCancellationRequested)
            {
                await Send(stream, reply, deadline.Token);
            }
        }
        catch (Exception error) when (error is IOException or SocketException or OperationCanceledException) { }
    }

    private static async Task Send(NetworkStream stream, AgentStatusReply reply, CancellationToken cancellation)
        => await stream.WriteAsync(AgentStatusFrame.Encode(AgentStatusCodec.EncodeReply(reply)), cancellation);

    /// <summary>Closes the listener and removes only the matching created socket inode; never unlinks a replacement path.</summary>
    /// <exception cref="LocalTransportException">A different inode now occupies the path.</exception>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        listener.Dispose();
        RemoveOwnSocket(options.SocketPath, created);
    }
    private static void RemoveOwnSocket(string path, LinuxNodeMetadata created)
    {
        var current = LinuxFileSystem.Read(path);
        if (current is null)
        {
            return;
        }

        if (!SameNode(created, current.Value))
        {
            throw new LocalTransportException("socket.pathChanged");
        }

        File.Delete(path);
    }
    private static bool SameNode(LinuxNodeMetadata expected, LinuxNodeMetadata actual) => actual.Type == LinuxNodeType.Socket &&
        actual.OwnerUserId == expected.OwnerUserId && actual.Inode == expected.Inode &&
        actual.DeviceMajor == expected.DeviceMajor && actual.DeviceMinor == expected.DeviceMinor && actual.LinkCount == 1;

    // Socket.Bind special-cases UnixDomainSocketEndPoint and later unlinks its pathname
    // unconditionally on Dispose. Delegate only its public address codec, retaining
    // cleanup here so a replacement pathname is never deleted by the runtime.
    private sealed class ExplicitCleanupEndPoint : System.Net.EndPoint
    {
        private readonly System.Net.EndPoint address;
        internal ExplicitCleanupEndPoint(string path) => address = new UnixDomainSocketEndPoint(path);
        private ExplicitCleanupEndPoint(System.Net.EndPoint address) => this.address = address;
        public override AddressFamily AddressFamily => address.AddressFamily;
        public override System.Net.SocketAddress Serialize() => address.Serialize();
        public override System.Net.EndPoint Create(System.Net.SocketAddress socketAddress) => new ExplicitCleanupEndPoint(address.Create(socketAddress));
    }
}
