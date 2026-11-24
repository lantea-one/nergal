using System.Buffers.Binary;
using System.Text.Json.Nodes;
using Nergal.Agent;
using Nergal.Linux;
using Nergal.Nftables;

namespace Nergal.LocalState.Tests;

/// <summary>Untrusted wire replies and concurrent configuration changes must never authorize a mixed snapshot.</summary>
public sealed class NftGenerationTests
{
    /// <summary>Complete correlated replies retain the full 32-bit sequence, including its wrap boundary.</summary>
    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(0x12345678u)]
    [InlineData(uint.MaxValue)]
    public void CompleteCorrelatedReplyRetainsAllGenerationBits(uint generation)
    {
        Assert.Equal(generation, NftGenerationMessage.Decode(Reply(generation), 7, 42));
    }

    /// <summary>Malformed or uncorrelated replies cannot establish a configuration generation.</summary>
    [Theory]
    [InlineData("short")]
    [InlineData("length")]
    [InlineData("event")]
    [InlineData("multipart")]
    [InlineData("sequence")]
    [InlineData("port")]
    [InlineData("family")]
    [InlineData("version")]
    [InlineData("resource")]
    [InlineData("attribute-size")]
    [InlineData("attribute-overflow")]
    [InlineData("attribute-type")]
    [InlineData("nested")]
    [InlineData("duplicate")]
    [InlineData("trailing")]
    [InlineData("missing")]
    [InlineData("error")]
    public void IncompleteUnknownOrUncorrelatedReplyIsDenied(string corruption)
    {
        var bytes = Reply(0x12345678);
        switch (corruption)
        {
            case "short": bytes = bytes[..19]; break;
            case "length": Put32(bytes, 0, 100); break;
            case "event": Put16(bytes, 4, 0x0a10); break;
            case "multipart": Put16(bytes, 6, 2); break;
            case "sequence": Put32(bytes, 8, 8); break;
            case "port": Put32(bytes, 12, 43); break;
            case "family": bytes[16] = 2; break;
            case "version": bytes[17] = 1; break;
            case "resource": bytes[18] ^= 1; break;
            case "attribute-size": Put16(bytes, 20, 7); break;
            case "attribute-overflow": Put16(bytes, 20, 100); break;
            case "attribute-type": Put16(bytes, 22, 4); break;
            case "nested": Put16(bytes, 22, 0x8001); break;
            case "duplicate": bytes = [.. bytes, .. bytes[20..]]; Put32(bytes, 0, (uint)bytes.Length); break;
            case "trailing": bytes = [.. bytes, 0]; Put32(bytes, 0, (uint)bytes.Length); break;
            case "missing": Put16(bytes, 22, 2); break;
            case "error": Put16(bytes, 4, 2); break;
        }
        Assert.Throws<IOException>(() => NftGenerationMessage.Decode(bytes, 7, 42));
    }

    /// <summary>Optional kernel diagnostics are bounded and validated without becoming authorization.</summary>
    [Fact]
    public void OptionalKernelDiagnosticsDoNotBecomeAuthority()
    {
        var bytes = Reply(3);
        // Network-order flag is permitted on numeric attributes, not arbitrary nested data.
        Put16(bytes, 22, 0x4001);
        bytes = [.. bytes, 8, 0, 2, 0x40, 0, 0, 0, 99, 6, 0, 3, 0, (byte)'x', 0, 0, 0];
        if (!BitConverter.IsLittleEndian)
        {
            Put16(bytes, 28, 8); Put16(bytes, 30, 0x4002);
            Put16(bytes, 36, 6); Put16(bytes, 38, 3);
        }
        Put32(bytes, 0, (uint)bytes.Length);
        Assert.Equal(3u, NftGenerationMessage.Decode(bytes, 7, 42));
        bytes[41] = 1; // Unterminated process name is malformed even though not used for authorization.
        Assert.Throws<IOException>(() => NftGenerationMessage.Decode(bytes, 7, 42));
    }

    /// <summary>Different transaction generations cannot authorize a combined observation.</summary>
    [Theory]
    [InlineData(5u, 5u, true)]
    [InlineData(5u, 6u, false)]
    [InlineData(uint.MaxValue, 0u, false)]
    public async Task OnlyOneTransactionGenerationCanBackACompleteObservation(uint before, uint after, bool accepted)
    {
        var observation = Observation();
        var generations = new Queue<uint>([before, after]);
        var result = await NativeNft.CollectConsistentAsync(generations.Dequeue, () => Task.FromResult<NftTableObservation?>(observation), TestContext.Current.CancellationToken);
        Assert.Equal(accepted, ReferenceEquals(observation, result));
        Assert.Empty(generations);
    }

    /// <summary>A failed final query cannot publish a previously collected snapshot.</summary>
    [Fact]
    public async Task FailedGenerationReadCannotReturnPreviouslyCollectedState()
    {
        var reads = 0;
        await Assert.ThrowsAsync<IOException>(() => NativeNft.CollectConsistentAsync(
            () => ++reads == 1 ? 5u : throw new IOException("denied"),
            () => Task.FromResult<NftTableObservation?>(Observation()), TestContext.Current.CancellationToken));
    }

    /// <summary>Cancellation after collection discards the snapshot.</summary>
    [Fact]
    public async Task CancellationAfterCollectionCannotPublishAnObservation()
    {
        using var cancellation = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => NativeNft.CollectConsistentAsync(
            () => 5, () => { cancellation.Cancel(); return Task.FromResult<NftTableObservation?>(Observation()); }, cancellation.Token));
    }

    /// <summary>No table collection may run when the initial consistency query fails.</summary>
    [Fact]
    public async Task InitialQueryFailureDoesNotCollectTables()
    {
        var collected = false;
        await Assert.ThrowsAsync<IOException>(() => NativeNft.CollectConsistentAsync(
            () => throw new IOException("denied"),
            () => { collected = true; return Task.FromResult<NftTableObservation?>(Observation()); }, TestContext.Current.CancellationToken));
        Assert.False(collected);
    }

    /// <summary>An invalid table snapshot cannot become usable even with a stable generation.</summary>
    [Fact]
    public async Task InvalidCollectionRemainsUnavailable()
    {
        var result = await NativeNft.CollectConsistentAsync(() => 5,
            () => Task.FromResult<NftTableObservation?>(null), TestContext.Current.CancellationToken);
        Assert.Null(result);
    }

    private static NftTableObservation Observation()
    {
        var assembly = typeof(NftGenerationTests).Assembly;
        using var stream = assembly.GetManifestResourceStream(assembly.GetManifestResourceNames().Single(n => n.EndsWith("bundle-echo.json", StringComparison.Ordinal)))!;
        var root = JsonNode.Parse(stream)!;
        // Reuse the complete synthetic native fixture and its actual parser; no production host input.
        return NftTableObservation.ParseBundleReplacementEcho(root.ToJsonString(), new(
            Guid.Parse("00000000-0000-0000-0000-000000000010"),
            Guid.Parse("00000000-0000-0000-0000-000000000020")), true, true, true).Observation
            ?? throw new InvalidOperationException("Synthetic observation fixture is invalid.");
    }

    private static byte[] Reply(uint generation)
    {
        var bytes = new byte[28];
        Put32(bytes, 0, 28); Put16(bytes, 4, 0x0a0f);
        Put32(bytes, 8, 7); Put32(bytes, 12, 42);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(18), (ushort)generation);
        Put16(bytes, 20, 8); Put16(bytes, 22, 1);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(24), generation);
        return bytes;
    }
    private static void Put16(byte[] bytes, int offset, ushort value) => BitConverter.GetBytes(value).CopyTo(bytes, offset);
    private static void Put32(byte[] bytes, int offset, uint value) => BitConverter.GetBytes(value).CopyTo(bytes, offset);
}
