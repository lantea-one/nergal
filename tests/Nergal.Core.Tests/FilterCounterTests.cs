using System.Text.Json.Nodes;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Managed counters record only packets reaching a schema-2 filter verdict.</summary>
public sealed class FilterCounterTests
{
    private static readonly FilterRule Rule = new(IpFamily.IPv4, FilterProtocol.Udp, FilterVerdict.Drop, DestinationPort: 53);

    /// <summary>The counter is part of immutable rule identity and survives encoding and compilation.</summary>
    [Fact]
    public void FilterCounter_RoundTripsAtVerdict()
    {
        var counted = Rule with { CountPackets = true };
        var filter = new FilterPolicy(2, FilterVerdict.Drop, [counted, Rule]);
        var json = PolicyBundleJsonCodec.EncodeBundle(new(1, filter));
        var encoded = JsonNode.Parse(json)!["filter"]!["rules"]!;
        Assert.True((bool)encoded[0]!["countPackets"]!);
        Assert.Null(encoded[1]!["countPackets"]);
        var decoded = PolicyBundleJsonCodec.DecodeBundle(json).Value!.Filter;
        Assert.Equal(counted, decoded.Rules[0]);
        Assert.Equal(Rule, decoded.Rules[1]);
        Assert.NotEqual(decoded.Rules[0], decoded.Rules[1]);
        Assert.Equal(counted.GetHashCode(), decoded.Rules[0]!.GetHashCode());
        Assert.Contains(FirewallFeature.InlineFilterCounters, decoded.GetRequiredFeatures());
        var compiled = NftFilterCompiler.Compile(decoded);
        Assert.Contains("udp dport 53 counter drop\n", compiled.Candidate);
        Assert.Contains("udp dport 53 drop\n", compiled.Candidate);
    }

    /// <summary>Only a boolean in the schema-2 JSON contract can request counting.</summary>
    [Theory]
    [InlineData(1, "true")]
    [InlineData(1, "false")]
    [InlineData(2, "null")]
    [InlineData(2, "1")]
    [InlineData(2, "\"true\"")]
    [InlineData(2, """{"packets":0,"bytes":0}""")]
    public void FilterCounter_RejectsInvalidIntent(int version, string value)
    {
        var encoded = PolicyBundleJsonCodec.EncodeBundle(new(1, new(version, FilterVerdict.Drop, [Rule])));
        var json = JsonNode.Parse(encoded)!;
        json["filter"]!["rules"]![0]!["countPackets"] = JsonNode.Parse(value);
        var decoded = PolicyBundleJsonCodec.DecodeBundle(json.ToJsonString());
        Assert.Null(decoded.Value);
        Assert.Equal(new("filter.countPackets", "filter.rules[0].countPackets"), Assert.Single(decoded.Diagnostics));
    }

    /// <summary>Disabling a rule cannot bypass the schema gate on a retained counter.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void FilterCounter_BlocksSchema1Compilation(bool enabled)
    {
        var filter = new FilterPolicy(1, FilterVerdict.Drop, [Rule with { CountPackets = true, Enabled = enabled }]);
        var compiled = NftFilterCompiler.Compile(filter);
        Assert.Null(compiled.Candidate);
        Assert.Equal(new("counter.requiresSchema2", "rules[0].countPackets"), Assert.Single(compiled.Diagnostics));
    }
}
