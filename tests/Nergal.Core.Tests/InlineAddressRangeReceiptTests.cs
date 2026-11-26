using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Anonymous range receipts retain the exact bounded address union.</summary>
public sealed class InlineAddressRangeReceiptTests
{
    /// <summary>A native range round trips as disjoint canonical CIDRs and binds its endpoint.</summary>
    [Fact]
    public void Range_ReconstructsExactCoverAndBindsEndpoint()
    {
        var first = NftTableObservation.Parse(Listing("""{"range":["192.0.2.1","192.0.2.2"]}"""));
        Assert.True(first.IsSuccess, first.ErrorCode);
        var rule = Assert.Single(first.Observation!.Policy.Rules)!;
        Assert.Equal([new NetworkPrefix("192.0.2.1/32"), new NetworkPrefix("192.0.2.2/32")], rule.SourcePrefixes);
        Assert.True(NftFilterCompiler.Compile(first.Observation.Policy).IsSuccess);

        var second = NftTableObservation.Parse(Listing("""{"range":["192.0.2.1","192.0.2.3"]}"""));
        Assert.True(second.IsSuccess, second.ErrorCode);
        Assert.NotEqual(first.Observation.StateDigest, second.Observation!.StateDigest);
    }

    /// <summary>Reversed, mixed-family or overlapping intervals invalidate the complete evidence.</summary>
    [Theory]
    [InlineData("""{"range":["192.0.2.2","192.0.2.1"]}""")]
    [InlineData("""{"range":["192.0.2.1","2001:db8::2"]}""")]
    [InlineData("""{"range":["192.0.2.1","192.0.2.2"]},"192.0.2.2" """)]
    public void InvalidRanges_AreDenied(string members)
    {
        var result = NftTableObservation.Parse(Listing(members));
        Assert.False(result.IsSuccess);
        Assert.Null(result.Observation);
    }

    private static string Listing(string members)
    {
        var identity = new NftTableIdentity(Guid.Parse("00000000-0000-0000-0000-000000000001"), Guid.Parse("00000000-0000-0000-0000-000000000002"));
        return """
            {"nftables":[
              {"metainfo":{"version":"1.1.7","release_name":"fixture","json_schema_version":1}},
              {"table":{"family":"inet","name":"nergal_filter","handle":7,"comment":"__COMMENT__"}},
              {"chain":{"family":"inet","table":"nergal_filter","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"drop"}},
              {"chain":{"family":"inet","table":"nergal_filter","name":"forward","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
              {"chain":{"family":"inet","table":"nergal_filter","name":"output","handle":3,"type":"filter","hook":"output","prio":0,"policy":"accept"}},
              {"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":10,"expr":[
                {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"set":[__MEMBERS__]}}},
                {"accept":null}
              ]}}
            ]}
            """
            .Replace("__COMMENT__", identity.Comment, StringComparison.Ordinal)
            .Replace("__MEMBERS__", members, StringComparison.Ordinal);
    }
}
