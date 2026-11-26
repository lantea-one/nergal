using System.Text.Json.Nodes;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Selectors bind the whole match to a single rule and preserve its immutable semantics.</summary>
public sealed class FilterSelectorTests
{
    /// <summary>Reordering or changing caller-owned data cannot alter a saved selector.</summary>
    [Fact]
    public void Selector_SnapshotsAndCanonicallyOrdersItsPatterns()
    {
        var names = new[] { "wan*", "uplink" };
        var selector = InterfaceNameSelector.Create(names)!;
        names[0] = "other";
        Assert.Equal([("uplink", false), ("wan", true)], selector.Patterns.Select(p => (p.Name, p.IsPrefix)));
        var rule = new FilterRule(IpFamily.DualStack, FilterProtocol.TcpOrUdp, FilterVerdict.Continue,
            Chain: FilterChainKind.Output, OutputInterfaceSelector: selector, NegateOutputInterface: true,
            DestinationPorts: [53, 443], CountPackets: true);
        var filter = new FilterPolicy(2, FilterVerdict.Drop, [rule]);
        var json = PolicyBundleJsonCodec.EncodeBundle(new(1, filter));
        var decoded = PolicyBundleJsonCodec.DecodeBundle(json).Value!.Filter;
        Assert.Equal(rule, Assert.Single(decoded.Rules));
        Assert.Contains(FirewallFeature.FilterSelectorSets, decoded.GetRequiredFeatures());
        var result = NftFilterCompiler.Compile(decoded);
        Assert.Contains("oifname != { \"uplink\", \"wan*\" } meta l4proto { tcp, udp } th dport { 53, 443 } counter\n", result.Candidate);
        var oversized = new FilterPolicy(2, FilterVerdict.Accept, Enumerable.Repeat(rule, 600));
        Assert.Contains(NftFilterCompiler.Compile(oversized).Diagnostics, issue => issue.Code == "selector.nativeObservationTooLarge");
    }

    /// <summary>Never turn an invalid or overlapping match into a subset or a wildcard.</summary>
    [Theory]
    [InlineData("[]")]
    [InlineData("""["*"]""")]
    [InlineData("""["eth*0"]""")]
    [InlineData("""["eth**"]""")]
    [InlineData("""["eth?"]""")]
    [InlineData("""["a\\*"]""")]
    [InlineData("""["bad\"name"]""")]
    [InlineData("""["abcdefghijklmno*"]""")]
    [InlineData("""["a","a"]""")]
    [InlineData("""["eth*","eth","wg0"]""")]
    [InlineData("""["ok",null]""")]
    public void Codec_RejectsWholeSelector(string invalid)
    {
        var rule = new FilterRule(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Drop);
        var json = JsonNode.Parse(PolicyBundleJsonCodec.EncodeBundle(new(1, new(2, FilterVerdict.Accept, [rule]))))!;
        json["filter"]!["rules"]![0]!["inputInterfaceSelector"] = JsonNode.Parse(invalid);
        Assert.Null(PolicyBundleJsonCodec.DecodeBundle(json.ToJsonString()).Value);
    }

    /// <summary>Selectors cannot bypass the hook, index-binding, or schema boundary, even when disabled.</summary>
    [Fact]
    public void Compile_RejectsConflictingOrMisplacedSelectors()
    {
        var selector = InterfaceNameSelector.Create(["a*", "b0"]);
        var rule = new FilterRule(IpFamily.IPv4, FilterProtocol.TcpOrUdp, FilterVerdict.Drop,
            InputInterfaceSelector: selector, Enabled: false);
        Assert.Null(NftFilterCompiler.Compile(new(1, FilterVerdict.Accept, [rule])).Candidate);
        foreach (var invalid in new[] { rule with { InputInterface = "a" }, rule with { BindInputInterfaceIndex = true },
            rule with { Chain = FilterChainKind.Output }, rule with { OutputInterfaceSelector = selector } })
        {
            Assert.Null(NftFilterCompiler.Compile(new(2, FilterVerdict.Accept, [invalid])).Candidate);
        }
        Assert.Null(InterfaceNameSelector.Create(Enumerable.Range(0, 65).Select(i => $"p{i}")));
    }
}
