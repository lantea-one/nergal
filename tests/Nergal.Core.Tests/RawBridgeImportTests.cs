using System.Text.Json.Nodes;
using Nergal.Core;
using Nergal.Core.Controller;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Raw and bridge conversions preserve native interface binding, counter position and family guards.</summary>
public sealed class RawBridgeImportTests
{
    private static NativeImportPlan Plan(string raw, string bridge)
    {
        var content = new NativeSourceContent("synthetic", $$"""
            table inet early { chain incoming { type filter hook prerouting priority raw; policy accept; {{raw}}; } }
            table bridge switching { chain transit { type filter hook forward priority -200; policy drop; {{bridge}}; } }
            """);
        var snapshot = new NativeSourceSnapshot(new(Guid.NewGuid(), content.Name, content.Digest, content.ByteLength, "fixture", DateTimeOffset.UnixEpoch), content);
        return NativeImportPlanner.Plan(new(snapshot.Summary.Id,
            [new("inet", "early", NativeImportTableRole.Filter), new("bridge", "switching", NativeImportTableRole.Bridge)], []), [snapshot]);
    }

    /// <summary>One snapshot retains both types of interface match and exactly one counter per counted rule.</summary>
    [Fact]
    public void CompleteSourcePreservesGuardedMatchesAndCounters()
    {
        const string rules = """
            iif edge0 accept;
            iifname edge1 ip saddr { 192.0.2.0/26, 198.51.100.0/24 } counter drop;
            iifname edge1 ip6 saddr { 2001:db8:1::/64, 2001:db8:3::/64 } counter drop;
            ip6 daddr { 2001:db8:2::/64, 2001:db8:4::/64 } accept;
            counter drop
            """;
        var plan = Plan(rules, rules);
        Assert.True(plan.CanCreateRevision, string.Join(", ", plan.Gaps.Select(g => g.Code)));
        var policy = PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!;
        var raw = policy.Filter.RpFilter!.Rules;
        var bridge = policy.Bridge!.Rules;
        Assert.Equal(5, raw.Count);
        Assert.Equal(5, bridge.Count);
        Assert.True(raw[0]!.BindInputInterfaceIndex);
        Assert.True(bridge[0]!.BindInputInterfaceIndex);
        Assert.Equal(new[] { false, true, true, false, true }, raw.Select(r => r!.CountPackets));
        Assert.Equal(raw.Select(r => r!.CountPackets), bridge.Select(r => r!.CountPackets));
        Assert.Equal(raw[3]!.DestinationPrefixes, bridge[3]!.DestinationPrefixes);
        foreach (var features in new[] { policy.Filter.GetRequiredFeatures(), policy.Bridge.GetRequiredFeatures() })
        {
            Assert.Contains(FirewallFeature.InputInterfaceIndexBinding, features);
            Assert.Contains(FirewallFeature.InlineFilterCounters, features);
        }
        var compiled = NftPolicyBundleCompiler.Compile(policy);
        Assert.Equal(plan.CandidateDigest, compiled.Digest!.Value);
        Assert.Contains("edge1\" ether type ip6 ip6 saddr { 2001:db8:1::/64, 2001:db8:3::/64 } counter drop", compiled.Candidate);
    }

    /// <summary>A gap in either table denies revision creation for the entire snapshot.</summary>
    [Theory]
    [InlineData("counter ip saddr 192.0.2.1 drop", "counter drop")]
    [InlineData("counter drop", "iif 4 counter accept")]
    [InlineData("iif 4 accept", "drop")]
    [InlineData("counter drop", "counter counter drop")]
    [InlineData("counter drop", "meta nfproto ipv6 accept")]
    [InlineData("counter drop", "ether type arp ip saddr 192.0.2.1 drop")]
    [InlineData("ip daddr != 192.0.2.1 drop", "accept")]
    public void UnsupportedNeighborBlocksCompleteCandidate(string raw, string bridge)
    {
        var plan = Plan(raw, bridge);
        Assert.False(plan.CanCreateRevision);
        Assert.Null(plan.CandidateDigest);
        Assert.Null(plan.PolicyJson);
    }

    /// <summary>Invalid dormant rules still block compilation, and caller mutation cannot change frozen raw sets.</summary>
    [Fact]
    public void DormantRawRulesValidateSnapshotsAndRejectConflictingMatchers()
    {
        NetworkPrefix[] prefixes = [new("192.0.2.0/25"), new("198.51.100.0/24")];
        var rule = new RpFilterRule(FilterVerdict.Drop, IpFamily.IPv4, SourcePrefixes: prefixes, DestinationPrefixes: prefixes, Enabled: false);
        var raw = new RpFilterPolicy(FilterVerdict.Accept, [rule]);
        prefixes[1] = new("0.0.0.0/0");
        Assert.Equal("198.51.100.0/24", raw.Rules[0]!.SourcePrefixes![1].Value);
        Assert.Equal("198.51.100.0/24", raw.Rules[0]!.DestinationPrefixes![1].Value);
        rule = raw.Rules[0]!;
        foreach (var invalid in new[] { rule with { Source = prefixes[0] }, rule with { Destination = prefixes[0] },
            rule with { Family = null }, rule with { BindInputInterfaceIndex = true }, rule with { BindInputInterfaceIndex = true, InputInterface = "2" } })
        {
            var policy = new FilterPolicy(2, FilterVerdict.Accept, FilterVerdict.Accept, FilterVerdict.Accept, [], new(FilterVerdict.Accept, [invalid]));
            Assert.Null(NftFilterCompiler.Compile(policy).Candidate);
        }
    }

    /// <summary>Observation binds the exact counter placement and index-vs-name semantics while ignoring live totals.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ObservationRejectsMalformedCountersAndDetectsSemanticDrift(bool bridge)
    {
        var assembly = typeof(RawBridgeImportTests).Assembly;
        var suffix = bridge ? ".bridge-list.json" : ".filter-list.json";
        using var input = assembly.GetManifestResourceStream(assembly.GetManifestResourceNames().Single(n => n.EndsWith(suffix, StringComparison.Ordinal)))!;
        var document = JsonNode.Parse(input)!;
        var rule = document["nftables"]!.AsArray().Select(n => n!["rule"]).First(n => n?["chain"]?.GetValue<string>() == (bridge ? "forward" : "rpfilter"))!;
        const string index = """{"match":{"op":"==","left":{"meta":{"key":"iif"}},"right":"edge0"}}""";
        const string counter = """{"counter":{"packets":1,"bytes":64}}""";
        const string drop = """{"drop":null}""";
        string? Digest(params string[] expressions)
        {
            rule["expr"] = new JsonArray(expressions.Select(e => JsonNode.Parse(e)).ToArray());
            var listing = document.ToJsonString();
            return bridge ? NftBridgeTableObservation.Parse(listing).Observation?.StateDigest.Value :
                NftTableObservation.Parse(listing).Observation?.StateDigest.Value;
        }
        var digest = Digest(index, counter, drop);
        Assert.NotNull(digest);
        Assert.Equal(digest, Digest(index, counter.Replace("64", "200", StringComparison.Ordinal), drop));
        var noCounter = Digest(index, drop);
        var byName = Digest(index.Replace("\"iif\"", "\"iifname\"", StringComparison.Ordinal), counter, drop);
        Assert.NotNull(noCounter);
        Assert.NotNull(byName);
        Assert.NotEqual(digest, noCounter);
        Assert.NotEqual(digest, byName);
        Assert.Null(Digest(counter, index, drop));
        Assert.Null(Digest(index, counter, counter, drop));
        Assert.Null(Digest(index.Replace("\"edge0\"", "2", StringComparison.Ordinal), counter, drop));
        Assert.Null(Digest(index, """{"counter":{"packets":-1,"bytes":64}}""", drop));
        Assert.Null(Digest(index, """{"counter":{"packets":1,"bytes":64,"name":"other"}}""", drop));
    }
}
