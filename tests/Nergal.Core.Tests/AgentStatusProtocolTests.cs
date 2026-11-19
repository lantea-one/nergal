using System.Buffers.Binary;
using System.Text;
using Nergal.Core.Agent;
using Nergal.LocalTransport;

namespace Nergal.Core.Tests;

/// <summary>Verifies bounded status-only intent, exact revisions and metadata-free denial/error replies without I/O.</summary>
public sealed class AgentStatusProtocolTests
{
    /// <summary>The only encoded request contains no identity/policy/native extension fields.</summary>
    [Fact]
    public void Request_OnlyStatusIntentIsSupported()
    {
        var payload = AgentStatusCodec.EncodeRequest();
        Assert.Equal("{\"schemaVersion\":1,\"command\":\"status\"}", Encoding.UTF8.GetString(payload));
        Assert.True(AgentStatusCodec.DecodeRequest(payload).IsValid);
        Assert.Null(AgentStatusCodec.DecodeRequest(payload).ErrorCode);
    }

    /// <summary>Mutating caller-owned buffers cannot alter an already encoded/decoded frame snapshot.</summary>
    [Fact]
    public void Frame_PreservesSnapshotsAndNetworkByteOrder()
    {
        var payload = AgentStatusCodec.EncodeRequest();
        var frame = AgentStatusFrame.Encode(payload);
        Assert.Equal(payload.Length, AgentStatusFrame.ReadPayloadLength(frame.AsSpan(0, 4)));
        Assert.Equal((uint)payload.Length, BinaryPrimitives.ReadUInt32BigEndian(frame));
        payload[0] = 0;
        var decoded = AgentStatusFrame.Decode(frame);
        frame[4] = 0;
        Assert.True(AgentStatusCodec.DecodeRequest(decoded).IsValid);
    }

    /// <summary>Unknown versions, commands, fields and duplicate keys cannot become status authority.</summary>
    [Theory]
    [InlineData("{\"schemaVersion\":2,\"command\":\"status\"}", "request.version")]
    [InlineData("{\"schemaVersion\":\"1\",\"command\":\"status\"}", "request.version")]
    [InlineData("{\"schemaVersion\":1,\"command\":\"apply\"}", "request.command")]
    [InlineData("{\"schemaVersion\":1,\"command\":\"Status\"}", "request.command")]
    [InlineData("{\"schemaVersion\":1,\"command\":\"status\",\"uid\":0}", "request.fields")]
    [InlineData("{\"schemaVersion\":1,\"command\":\"status\",\"policy\":{}}", "request.fields")]
    [InlineData("{\"schemaVersion\":1,\"command\":\"status\",\"command\":\"apply\"}", "request.duplicateProperty")]
    [InlineData("{}", "request.fields")]
    [InlineData("null", "request.fields")]
    [InlineData("{", "request.invalidJson")]
    [InlineData("{\"schemaVersion\":1,\"command\":\"status\",}", "request.invalidJson")]
    public void Request_RejectsUnsupportedInput(string input, string code)
    {
        var result = AgentStatusCodec.DecodeRequest(Encoding.UTF8.GetBytes(input));
        Assert.False(result.IsValid);
        Assert.Equal(code, result.ErrorCode);
    }

    /// <summary>JSON resource bounds and malformed UTF-8 are checked before any provider could be selected.</summary>
    [Fact]
    public void Request_BoundsSizeDepthAndEncoding()
    {
        Assert.Equal("payload.tooLarge", AgentStatusCodec.DecodeRequest(new byte[4097]).ErrorCode);
        Assert.Equal("request.invalidJson", AgentStatusCodec.DecodeRequest(Encoding.UTF8.GetBytes(new string('[', 20) + new string(']', 20))).ErrorCode);
        Assert.Equal("request.invalidJson", AgentStatusCodec.DecodeRequest([0xff]).ErrorCode);
    }

    /// <summary>Every classification round-trips without granting extra metadata to denial/error replies.</summary>
    [Theory]
    [InlineData(AgentStatusOutcome.Matched, 1UL)]
    [InlineData(AgentStatusOutcome.Drift, ulong.MaxValue)]
    [InlineData(AgentStatusOutcome.Unbound, 7UL)]
    [InlineData(AgentStatusOutcome.Unavailable, null)]
    [InlineData(AgentStatusOutcome.Denied, null)]
    [InlineData(AgentStatusOutcome.InvalidRequest, null)]
    public void Reply_RoundTripsTypedContract(AgentStatusOutcome outcome, ulong? revision)
    {
        var original = new AgentStatusReply(outcome, revision);
        var payload = AgentStatusCodec.EncodeReply(original);
        var parsed = AgentStatusCodec.DecodeReply(AgentStatusFrame.Decode(AgentStatusFrame.Encode(payload)));
        Assert.True(parsed.IsValid, parsed.ErrorCode);
        Assert.Equal(original, parsed.Reply);
        if (revision is null)
        {
            Assert.DoesNotContain("revision", Encoding.UTF8.GetString(payload));
        }
        else
        {
            Assert.Contains("\"revision\":\"" + revision.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\"", Encoding.UTF8.GetString(payload));
        }
    }

    /// <summary>Unknown outcomes and incorrect revision presence cannot enter a typed reply.</summary>
    [Fact]
    public void Reply_ConstructorEnforcesMetadataBoundary()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgentStatusReply((AgentStatusOutcome)99));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgentStatusReply(AgentStatusOutcome.Matched));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgentStatusReply(AgentStatusOutcome.Drift, 0));
        Assert.Throws<ArgumentException>(() => new AgentStatusReply(AgentStatusOutcome.Denied, 1));
        Assert.Throws<ArgumentException>(() => new AgentStatusReply(AgentStatusOutcome.Unavailable, 1));
        Assert.Throws<ArgumentNullException>(() => AgentStatusCodec.EncodeReply(null!));
    }

    /// <summary>Revisions stay canonical and exact; error metadata and unsupported replies fail closed.</summary>
    [Theory]
    [InlineData("{\"schemaVersion\":1,\"outcome\":\"denied\",\"revision\":\"1\"}", "reply.fields")]
    [InlineData("{\"schemaVersion\":1,\"outcome\":\"matched\"}", "reply.fields")]
    [InlineData("{\"schemaVersion\":1,\"outcome\":\"matched\",\"revision\":1}", "reply.revision")]
    [InlineData("{\"schemaVersion\":1,\"outcome\":\"matched\",\"revision\":\"01\"}", "reply.revision")]
    [InlineData("{\"schemaVersion\":1,\"outcome\":\"matched\",\"revision\":\"0\"}", "reply.revision")]
    [InlineData("{\"schemaVersion\":1,\"outcome\":\"matched\",\"revision\":\"18446744073709551616\"}", "reply.revision")]
    [InlineData("{\"schemaVersion\":2,\"outcome\":\"denied\"}", "reply.version")]
    [InlineData("{\"schemaVersion\":1,\"outcome\":\"applied\"}", "reply.outcome")]
    [InlineData("{\"schemaVersion\":1,\"outcome\":\"denied\",\"outcome\":\"matched\"}", "reply.duplicateProperty")]
    [InlineData("{", "reply.invalidJson")]
    public void Reply_RejectsAmbiguousOrUnsupportedMetadata(string input, string code)
    {
        var result = AgentStatusCodec.DecodeReply(Encoding.UTF8.GetBytes(input));
        Assert.False(result.IsValid);
        Assert.Null(result.Reply);
        Assert.Equal(code, result.ErrorCode);
    }

    /// <summary>Untrusted declared lengths cannot trigger large allocations, and extra/truncated bytes are rejected.</summary>
    [Fact]
    public void Frame_RejectsInvalidExtentBeforePayloadAllocation()
    {
        Assert.Equal("frame.header", Assert.Throws<StatusFrameException>(() => AgentStatusFrame.ReadPayloadLength([0, 0, 1])).Code);
        foreach (var length in new[] { 0U, 4097U, uint.MaxValue })
        {
            var header = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(header, length);
            Assert.Equal("frame.length", Assert.Throws<StatusFrameException>(() => AgentStatusFrame.ReadPayloadLength(header)).Code);
        }
        Assert.Equal("frame.length", Assert.Throws<StatusFrameException>(() => AgentStatusFrame.Encode([])).Code);
        Assert.Equal("frame.length", Assert.Throws<StatusFrameException>(() => AgentStatusFrame.Encode(new byte[4097])).Code);
        var frame = AgentStatusFrame.Encode([1]);
        Assert.Equal("frame.extent", Assert.Throws<StatusFrameException>(() => AgentStatusFrame.Decode(frame.AsSpan(0, 4))).Code);
        Assert.Equal("frame.extent", Assert.Throws<StatusFrameException>(() => AgentStatusFrame.Decode([.. frame, 2])).Code);
        Assert.Equal(4096, AgentStatusFrame.Decode(AgentStatusFrame.Encode(new byte[4096])).Length);
    }

    /// <summary>Local peer configuration cannot be silently expanded through caller mutation or missing defaults.</summary>
    [Fact]
    public void Options_SnapshotExplicitPeersAndRejectInvalidConfiguration()
    {
        var peers = new HashSet<uint> { 1 };
        var options = new UnixStatusOptions("/tmp/nergal-test.sock", peers, 1);
        peers.Add(2);
        peers.Clear();
        Assert.Contains(1U, options.TrustedUserIds);
        Assert.DoesNotContain(2U, options.TrustedUserIds);
        Assert.DoesNotContain(0U, options.TrustedUserIds);
        Assert.Throws<ArgumentException>(() => new UnixStatusOptions("/tmp/nergal-test.sock", []));
        Assert.Throws<ArgumentException>(() => new UnixStatusOptions("relative.sock", [1]));
        Assert.Throws<ArgumentException>(() => new UnixStatusOptions("/tmp/" + new string('x', 108), [1]));
        Assert.Throws<ArgumentOutOfRangeException>(() => new UnixStatusOptions("/tmp/test.sock", [uint.MaxValue]));
        Assert.Throws<ArgumentOutOfRangeException>(() => new UnixStatusOptions("/tmp/test.sock", [1], uint.MaxValue));
        Assert.Throws<ArgumentOutOfRangeException>(() => new UnixStatusOptions("/tmp/test.sock", [1], exchangeTimeout: TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => new UnixStatusOptions("/tmp/test.sock", [1], exchangeTimeout: TimeSpan.FromSeconds(31)));
    }

    /// <summary>Client authority is explicit and shares the same strict pathname/group/deadline contract.</summary>
    [Fact]
    public void ClientOptions_RequireValidExplicitServerPolicy()
    {
        var policy = new UnixStatusClientOptions("/tmp/nergal-client.sock", 7, 3, TimeSpan.FromSeconds(1));
        Assert.Equal(7U, policy.ExpectedServerUserId);
        Assert.Equal(3U, policy.SocketGroupId);
        Assert.Equal(TimeSpan.FromSeconds(1), policy.ExchangeTimeout);
        Assert.Equal("/tmp/nergal-client.sock", policy.SocketPath);
        Assert.Equal(0U, new UnixStatusClientOptions("/tmp/test.sock", 0).ExpectedServerUserId);
        Assert.Throws<ArgumentOutOfRangeException>(() => new UnixStatusClientOptions("/tmp/test.sock", uint.MaxValue));
        Assert.Throws<ArgumentOutOfRangeException>(() => new UnixStatusClientOptions("/tmp/test.sock", 1, uint.MaxValue));
        Assert.Throws<ArgumentException>(() => new UnixStatusClientOptions("relative.sock", 1));
        Assert.Throws<ArgumentException>(() => new UnixStatusClientOptions("/tmp/invalid\0.sock", 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new UnixStatusClientOptions("/tmp/test.sock", 1, exchangeTimeout: TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => new UnixStatusClientOptions("/tmp/test.sock", 1, exchangeTimeout: TimeSpan.FromSeconds(31)));
        Assert.Throws<ArgumentNullException>(() => new UnixStatusClient(null!));
    }

    /// <summary>Caller cancellation is preserved before any filesystem or socket access, including nonexistent endpoints.</summary>
    [Fact]
    public async Task Client_PreCanceledQueryDoesNotInspectEndpoint()
    {
        if (!OperatingSystem.IsLinux()) { return; }
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        var client = new UnixStatusClient(new("/missing/nergal-test/status.sock", 7));
        var querying = client.QueryAsync(canceled.Token);
        var failure = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => querying);
        Assert.Equal(canceled.Token, failure.CancellationToken);
    }
}
