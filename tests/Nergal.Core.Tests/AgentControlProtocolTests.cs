using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Nergal.Core.Agent;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;
using Nergal.LocalTransport;
using Nergal.RemoteTransport;

namespace Nergal.Core.Tests;

/// <summary>Verifies typed control framing, JSON codec bounds, Unix peer-UID control transport, and TLS 1.3 pinned mTLS transport.</summary>
public sealed class AgentControlProtocolTests
{
    private const string SampleDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// <summary>Frame encoding copies payloads into network byte order and rejects empty, short, or oversized extents.</summary>
    [Fact]
    public void Frame_ValidatesLengthsAndSnapshotIsolation()
    {
        var payload = Encoding.UTF8.GetBytes("{\"schemaVersion\":1,\"command\":\"status\"}");
        var frame = AgentControlFrame.Encode(payload);
        Assert.Equal(payload.Length, AgentControlFrame.ReadPayloadLength(frame.AsSpan(0, AgentControlFrame.HeaderLength)));
        Assert.Equal((uint)payload.Length, BinaryPrimitives.ReadUInt32BigEndian(frame));

        payload[0] = 0;
        var decoded = AgentControlFrame.Decode(frame);
        frame[4] = 0;
        Assert.Equal((byte)'{', decoded[0]);

        Assert.Equal("frame.length", Assert.Throws<StatusFrameException>(() => AgentControlFrame.Encode([])).Code);
        Assert.Equal("frame.length", Assert.Throws<StatusFrameException>(() => AgentControlFrame.Encode(new byte[AgentControlCodec.MaximumPayloadLength + 1])).Code);
        Assert.Equal("frame.header", Assert.Throws<StatusFrameException>(() => AgentControlFrame.ReadPayloadLength([0, 1, 2])).Code);

        var badHeader = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(badHeader, (uint)AgentControlCodec.MaximumPayloadLength + 1);
        Assert.Equal("frame.length", Assert.Throws<StatusFrameException>(() => AgentControlFrame.ReadPayloadLength(badHeader)).Code);
        Assert.Equal("frame.extent", Assert.Throws<StatusFrameException>(() => AgentControlFrame.Decode(frame.AsSpan(0, 8))).Code);
    }

    /// <summary>Schema 1 and Schema 2 FilterPolicy control requests and structured replies round-trip with strict fidelity.</summary>
    [Fact]
    public void Codec_RoundTripsSchema1Schema2AndAllControlCommands()
    {
        var opId = Guid.Parse("11111111-2222-3333-4444-555555555555");
        var wdId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

        var schema1 = new FilterPolicy(
            1,
            FilterVerdict.Drop,
            [new FilterRule(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, new NetworkPrefix("192.0.2.0/24"), DestinationPort: 443)]);
        var schema2 = new FilterPolicy(
            2,
            FilterVerdict.Drop,
            FilterVerdict.Drop,
            FilterVerdict.Accept,
            [
                new FilterRule(
                    IpFamily.IPv4,
                    FilterProtocol.Any,
                    FilterVerdict.Accept,
                    Chain: FilterChainKind.Forward,
                    InputInterface: "eth0",
                    OutputInterface: "eth1",
                    ConnectionStates: ConnectionStateFlags.Established | ConnectionStateFlags.Related),
                new FilterRule(
                    IpFamily.IPv6,
                    FilterProtocol.Tcp,
                    FilterVerdict.Accept,
                    new NetworkPrefix("2001:db8:1::/48"),
                    new NetworkPrefix("2001:db8:2::/48"),
                    DestinationPort: 8443,
                    Chain: FilterChainKind.Forward,
                    ConnectionStates: ConnectionStateFlags.New,
                    RateLimit: new PerSourceRateLimit(25, RateLimitTimeUnit.Second, 10, 120),
                    MatchOriginalDestinationDnat: true),
                new FilterRule(
                    IpFamily.IPv6,
                    FilterProtocol.IcmpV6,
                    FilterVerdict.Accept,
                    Chain: FilterChainKind.Input,
                    IcmpType: "nd-neighbor-solicit"),
            ]);

        foreach (var req in new[]
        {
            new AgentControlRequest(AgentControlCommand.Status),
            new AgentControlRequest(AgentControlCommand.PrepareApply, opId, wdId, 30, schema1),
            new AgentControlRequest(AgentControlCommand.PrepareApply, opId, null, 45, schema2),
            new AgentControlRequest(AgentControlCommand.Confirm, opId, wdId),
            new AgentControlRequest(AgentControlCommand.Rollback, opId, wdId),
        })
        {
            var encoded = AgentControlCodec.EncodeRequest(req);
            var decoded = AgentControlCodec.DecodeRequest(encoded);
            Assert.True(decoded.IsValid, decoded.ErrorCode);
            Assert.Equal(req.Command, decoded.Request!.Command);
            Assert.Equal(req.OperationId, decoded.Request.OperationId);
            Assert.Equal(req.WatchdogId, decoded.Request.WatchdogId);
            Assert.Equal(req.ConfirmationTimeoutSeconds, decoded.Request.ConfirmationTimeoutSeconds);
            if (req.Policy is not null)
            {
                Assert.NotNull(decoded.Request.Policy);
                Assert.Equal(req.Policy.SchemaVersion, decoded.Request.Policy!.SchemaVersion);
                Assert.Equal(req.Policy.InputDefaultVerdict, decoded.Request.Policy.InputDefaultVerdict);
                Assert.Equal(req.Policy.ForwardDefaultVerdict, decoded.Request.Policy.ForwardDefaultVerdict);
                Assert.Equal(req.Policy.OutputDefaultVerdict, decoded.Request.Policy.OutputDefaultVerdict);
                Assert.Equal(req.Policy.Rules.Count, decoded.Request.Policy.Rules.Count);
                for (var i = 0; i < req.Policy.Rules.Count; i++)
                {
                    Assert.Equal(req.Policy.Rules[i], decoded.Request.Policy.Rules[i]);
                }
            }
        }

        foreach (var reply in new[]
        {
            new AgentControlReply(AgentControlOutcome.Matched, revision: 9),
            new AgentControlReply(AgentControlOutcome.AppliedPendingConfirmation, revision: 9, operationId: opId, watchdogId: wdId, activePhase: ApplyPhase.AwaitingConfirmation, remainingSeconds: 29, candidateDigest: SampleDigest),
            new AgentControlReply(AgentControlOutcome.Confirmed, revision: 10, operationId: opId, watchdogId: wdId, activePhase: ApplyPhase.Confirmed, candidateDigest: SampleDigest),
            new AgentControlReply(AgentControlOutcome.RolledBack, revision: 9, operationId: opId, watchdogId: wdId, activePhase: ApplyPhase.RolledBack),
            new AgentControlReply(AgentControlOutcome.Rejected, revision: 9, errorCode: "candidate.invalid"),
            new AgentControlReply(AgentControlOutcome.Denied),
            new AgentControlReply(AgentControlOutcome.InvalidRequest),
        })
        {
            var encoded = AgentControlCodec.EncodeReply(reply);
            var decoded = AgentControlCodec.DecodeReply(encoded);
            Assert.True(decoded.IsValid, decoded.ErrorCode);
            Assert.Equal(reply, decoded.Reply);
        }
    }

    /// <summary>Constructor and JSON decoder reject duplicate keys, unsupported commands/versions, out-of-range numbers, and oversized frames.</summary>
    [Fact]
    public void RequestsAndReplies_RejectMalformedOrAmbiguousInputs()
    {
        var opId = Guid.Parse("11111111-2222-3333-4444-555555555555");
        var wdId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        var policy = new FilterPolicy(1, FilterVerdict.Drop, []);

        Assert.Throws<ArgumentException>(() => new AgentControlRequest(AgentControlCommand.Status, operationId: opId));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgentControlRequest(AgentControlCommand.PrepareApply, opId, wdId, 0, policy));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgentControlRequest(AgentControlCommand.PrepareApply, opId, wdId, 3601, policy));
        Assert.Throws<ArgumentException>(() => new AgentControlRequest(AgentControlCommand.Confirm, opId, null));
        Assert.Throws<ArgumentException>(() => new AgentControlRequest(AgentControlCommand.Rollback, opId, wdId, policy: policy));

        Assert.Throws<ArgumentException>(() => new AgentControlReply(AgentControlOutcome.Denied, revision: 1));
        Assert.Throws<ArgumentException>(() => new AgentControlReply(AgentControlOutcome.InvalidRequest, errorCode: "x"));
        Assert.Throws<ArgumentException>(() => new AgentControlReply(AgentControlOutcome.Rejected, candidateDigest: "not-hex"));
        Assert.Throws<ArgumentException>(() => new AgentControlReply(AgentControlOutcome.Rejected, errorCode: "bad space"));

        Assert.Equal("payload.tooLarge", AgentControlCodec.DecodeRequest(new byte[AgentControlCodec.MaximumPayloadLength + 1]).ErrorCode);
        Assert.Equal("request.duplicateProperty", AgentControlCodec.DecodeRequest("{\"schemaVersion\":1,\"command\":\"status\",\"command\":\"status\"}"u8).ErrorCode);
        Assert.Equal("request.fields", AgentControlCodec.DecodeRequest("{\"schemaVersion\":2,\"command\":\"status\"}"u8).ErrorCode);
        Assert.Equal("request.command", AgentControlCodec.DecodeRequest("{\"schemaVersion\":1,\"command\":\"exec\"}"u8).ErrorCode);
        Assert.Equal("request.fields", AgentControlCodec.DecodeRequest("{\"schemaVersion\":1,\"command\":\"status\",\"extra\":1}"u8).ErrorCode);
        Assert.Equal("reply.duplicateProperty", AgentControlCodec.DecodeReply("{\"schemaVersion\":1,\"outcome\":\"denied\",\"outcome\":\"denied\"}"u8).ErrorCode);
        Assert.Equal("reply.fields", AgentControlCodec.DecodeReply("{\"schemaVersion\":1,\"outcome\":\"denied\",\"errorCode\":\"leak\"}"u8).ErrorCode);
    }

    /// <summary>Unix control transport authenticates explicit peer UIDs and denies untrusted peers fail-closed.</summary>
    [Fact]
    public Task UnixControl_AuthenticatesPeerUidAndDeniesUntrustedPeers()
    {
        return OperatingSystem.IsLinux()
            ? RunUnixControlPeerUidCheckAsync()
            : Task.CompletedTask;
    }

    [SupportedOSPlatform("linux")]
    private static async Task RunUnixControlPeerUidCheckAsync()
    {
        var tempDir = CreateOwnerOnlyTempDirectory();
        var socketPath = Path.Combine(tempDir, "ctrl.sock");
        var uid = GetEffectiveUid();

        try
        {
            using var server = UnixControlServer.Bind(new UnixControlOptions(socketPath, [uid]));
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var serverTask = server.ServeAsync((req, _) =>
                Task.FromResult(req.Command == AgentControlCommand.Status
                    ? new AgentControlReply(AgentControlOutcome.Matched, revision: 4)
                    : new AgentControlReply(AgentControlOutcome.Rejected, errorCode: "unexpected")),
                cts.Token);

            var reply = await UnixControlClient.SendAsync(
                new UnixControlClientOptions(socketPath, uid),
                new AgentControlRequest(AgentControlCommand.Status),
                cts.Token);

            Assert.Equal(AgentControlOutcome.Matched, reply.Outcome);
            Assert.Equal(4UL, reply.Revision);

            // Client expecting a different server UID fails closed before sending a request.
            var wrongServer = await Assert.ThrowsAsync<LocalTransportException>(() =>
                UnixControlClient.SendAsync(
                    new UnixControlClientOptions(socketPath, uid + 1),
                    new AgentControlRequest(AgentControlCommand.Status),
                    cts.Token));
            Assert.StartsWith("socket.", wrongServer.Code, StringComparison.Ordinal);

            await cts.CancelAsync();
            await serverTask;
        }
        finally
        {
            DeleteTempDirectory(tempDir);
        }
    }

    /// <summary>Unix control server denies connections from unallowlisted peer UIDs without invoking its handler.</summary>
    [Fact]
    public async Task UnixControl_DeniesUnallowlistedPeerUidWithoutInvokingHandler()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var tempDir = CreateOwnerOnlyTempDirectory();
        var socketPath = Path.Combine(tempDir, "ctrl-deny.sock");
        var uid = GetEffectiveUid();
        var handlerCalled = 0;

        try
        {
            using var server = UnixControlServer.Bind(new UnixControlOptions(socketPath, [uid + 1]));
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var serverTask = server.ServeAsync((_, _) =>
            {
                Interlocked.Increment(ref handlerCalled);
                return Task.FromResult(new AgentControlReply(AgentControlOutcome.Matched, revision: 1));
            }, cts.Token);

            var reply = await UnixControlClient.SendAsync(
                new UnixControlClientOptions(socketPath, uid),
                new AgentControlRequest(AgentControlCommand.Status),
                cts.Token);

            Assert.Equal(AgentControlOutcome.Denied, reply.Outcome);
            Assert.Equal(0, Volatile.Read(ref handlerCalled));

            await cts.CancelAsync();
            await serverTask;
        }
        finally
        {
            DeleteTempDirectory(tempDir);
        }
    }

    /// <summary>TLS 1.3 pinned mTLS authenticates pinned leaf certificates and rejects unpinned, expired, CA, or wrong-EKU certificates.</summary>
    [Fact]
    public async Task TlsControl_EnforcesPinnedTls13MtlsAndCertificateConstraints()
    {
        var now = DateTimeOffset.UtcNow;
        using var serverCert = CreateLeafCert("CN=nergal-agent", TlsThumbprintPolicy.ServerAuthenticationOid, now.AddHours(-1), now.AddHours(2));
        using var clientCert = CreateLeafCert("CN=nergal-controller", TlsThumbprintPolicy.ClientAuthenticationOid, now.AddHours(-1), now.AddHours(2));
        using var rogueClientCert = CreateLeafCert("CN=rogue-controller", TlsThumbprintPolicy.ClientAuthenticationOid, now.AddHours(-1), now.AddHours(2));
        using var wrongEkuClientCert = CreateLeafCert("CN=wrong-eku-client", TlsThumbprintPolicy.ServerAuthenticationOid, now.AddHours(-1), now.AddHours(2));
        using var wrongEkuServerCert = CreateLeafCert("CN=wrong-eku-server", TlsThumbprintPolicy.ClientAuthenticationOid, now.AddHours(-1), now.AddHours(2));
        using var expiredClientCert = CreateLeafCert("CN=expired-client", TlsThumbprintPolicy.ClientAuthenticationOid, now.AddHours(-4), now.AddHours(-1));
        using var caCert = CreateCaCert("CN=nergal-ca", now.AddHours(-1), now.AddHours(2));

        var serverPin = TlsThumbprintPolicy.ComputeSha256Thumbprint(serverCert);
        var clientPin = TlsThumbprintPolicy.ComputeSha256Thumbprint(clientCert);
        var roguePin = TlsThumbprintPolicy.ComputeSha256Thumbprint(rogueClientCert);
        var expiredPin = TlsThumbprintPolicy.ComputeSha256Thumbprint(expiredClientCert);

        // Options reject CA certificates or wrong EKUs deterministically.
        Assert.Throws<ArgumentException>(() => new TlsControlServerOptions(new IPEndPoint(IPAddress.Loopback, 0), caCert, [clientPin]));
        Assert.Throws<ArgumentException>(() => new TlsControlServerOptions(new IPEndPoint(IPAddress.Loopback, 0), wrongEkuServerCert, [clientPin]));
        Assert.Throws<ArgumentException>(() => new TlsControlClientOptions("127.0.0.1", 8443, caCert, [serverPin]));
        Assert.Throws<ArgumentException>(() => new TlsControlClientOptions("127.0.0.1", 8443, wrongEkuClientCert, [serverPin]));

        var fixedClock = new FixedTimeProvider(now);
        var handlerInvocations = 0;

        using var server = TlsControlServer.Bind(new TlsControlServerOptions(
            new IPEndPoint(IPAddress.Loopback, 0),
            serverCert,
            [clientPin, expiredPin],
            timeProvider: fixedClock));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var serverTask = server.ServeAsync((req, _) =>
        {
            Interlocked.Increment(ref handlerInvocations);
            return Task.FromResult(new AgentControlReply(AgentControlOutcome.Matched, revision: 12));
        }, cts.Token);

        var port = server.BoundEndPoint.Port;

        // 1. Valid pinned mTLS succeeds.
        var okReply = await TlsControlClient.SendAsync(
            new TlsControlClientOptions("127.0.0.1", port, clientCert, [serverPin], serverNameIndication: "nergal-agent", timeProvider: fixedClock),
            new AgentControlRequest(AgentControlCommand.Status),
            cts.Token);
        Assert.Equal(AgentControlOutcome.Matched, okReply.Outcome);
        Assert.Equal(12UL, okReply.Revision);
        Assert.Equal(1, Volatile.Read(ref handlerInvocations));

        // 2. Client rejects unpinned server certificate.
        await Assert.ThrowsAsync<RemoteTransportException>(() =>
            TlsControlClient.SendAsync(
                new TlsControlClientOptions("127.0.0.1", port, clientCert, [roguePin], serverNameIndication: "nergal-agent", timeProvider: fixedClock),
                new AgentControlRequest(AgentControlCommand.Status),
                cts.Token));
        Assert.Equal(1, Volatile.Read(ref handlerInvocations));

        // 3. Server rejects unpinned client certificate before running handler.
        await Assert.ThrowsAsync<RemoteTransportException>(() =>
            TlsControlClient.SendAsync(
                new TlsControlClientOptions("127.0.0.1", port, rogueClientCert, [serverPin], serverNameIndication: "nergal-agent", timeProvider: fixedClock),
                new AgentControlRequest(AgentControlCommand.Status),
                cts.Token));
        Assert.Equal(1, Volatile.Read(ref handlerInvocations));

        // 4. Server rejects expired client certificate even when thumbprint is pinned.
        await Assert.ThrowsAsync<RemoteTransportException>(() =>
            TlsControlClient.SendAsync(
                new TlsControlClientOptions("127.0.0.1", port, expiredClientCert, [serverPin], serverNameIndication: "nergal-agent", timeProvider: fixedClock),
                new AgentControlRequest(AgentControlCommand.Status),
                cts.Token));
        Assert.Equal(1, Volatile.Read(ref handlerInvocations));

        // 5. Client clock past server expiry rejects handshake even with valid pin.
        var futureClock = new FixedTimeProvider(now.AddHours(3));
        await Assert.ThrowsAsync<RemoteTransportException>(() =>
            TlsControlClient.SendAsync(
                new TlsControlClientOptions("127.0.0.1", port, clientCert, [serverPin], serverNameIndication: "nergal-agent", timeProvider: futureClock),
                new AgentControlRequest(AgentControlCommand.Status),
                cts.Token));
        Assert.Equal(1, Volatile.Read(ref handlerInvocations));

        await cts.CancelAsync();
        await serverTask;
    }

    private static X509Certificate2 CreateLeafCert(string subject, string ekuOid, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(ekuOid)], true));
        return request.CreateSelfSigned(notBefore, notAfter);
    }

    private static X509Certificate2 CreateCaCert(string subject, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return request.CreateSelfSigned(notBefore, notAfter);
    }

    [SupportedOSPlatform("linux")]
    private static string CreateOwnerOnlyTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "ng-ctrl-" + Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return path;
    }

    private static void DeleteTempDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    [SupportedOSPlatform("linux")]
    private static uint GetEffectiveUid() => geteuid();

    [DllImport("libc")]
    private static extern uint geteuid();

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }
}
