using System.Text;
using Nergal.Agent;
using Nergal.Nftables;

namespace Nergal.LocalState.Tests;

/// <summary>The agent consumes complete bounded UTF-8 evidence without truncation.</summary>
public sealed class NativeOutputBoundsTests
{
    /// <summary>The capture boundary is measured in bytes, and bytes beyond that boundary fail the read.</summary>
    [Theory]
    [InlineData(NftObservationLimits.MaximumInventoryBytes)]
    [InlineData(NftObservationLimits.MaximumDocumentBytes)]
    public async Task CapturesExactBoundAndRejectsOneMoreByte(int bound)
    {
        var text = new string(' ', bound - 2) + "é";
        using var complete = new MemoryStream(Encoding.UTF8.GetBytes(text));
        Assert.Equal(text, await NativeNft.ReadOutput(complete, bound, TestContext.Current.CancellationToken));

        using var oversized = new MemoryStream(Encoding.UTF8.GetBytes(text + " "));
        await Assert.ThrowsAsync<IOException>(() => NativeNft.ReadOutput(oversized, bound, TestContext.Current.CancellationToken));
    }

    /// <summary>A malformed UTF-8 sequence cannot produce a receipt payload.</summary>
    [Fact]
    public async Task InvalidUtf8IsNotReplaced()
    {
        using var invalid = new MemoryStream([0xc3, 0x20]);
        await Assert.ThrowsAsync<DecoderFallbackException>(
            () => NativeNft.ReadOutput(invalid, NftObservationLimits.MaximumDocumentBytes, TestContext.Current.CancellationToken));
    }
}
