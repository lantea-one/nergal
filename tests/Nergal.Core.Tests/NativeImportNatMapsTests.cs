using Nergal.Core.Controller;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Static map projections preserve lookup scope, ordering and decline unsafe shortcuts.</summary>
public sealed class NativeImportNatMapsTests
{
    /// <summary>An absent map key returns to the next base-chain rule.</summary>
    [Fact]
    public void DnatJump_ProjectsOnlyMatchingPortsBeforeBaseFallback()
    {
        var plan = Plan("""
            map ports { type inet_service : ipv4_addr; elements = { 443 : 192.0.2.2, 8443 : 192.0.2.4 }; }
            chain translate {
              type nat hook output priority dstnat; policy accept;
              ip daddr 198.51.100.1 jump lookup;
              ip daddr 198.51.100.1 tcp dport 444 dnat ip to 192.0.2.8;
            }
            chain lookup { tcp dport { 443, 444 } dnat ip to tcp dport map @ports; return; }
            """);
        Assert.True(plan.CanCreateRevision, string.Join(", ", plan.Gaps.Select(gap => gap.Code)));
        var rules = PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!.Nat!.DnatRules;
        Assert.Equal([(443, "192.0.2.2"), (444, "192.0.2.8")],
            rules.Select(rule => (rule!.OriginalPort!.Value, rule.TranslatedAddress)));
        Assert.All(rules, rule => Assert.Equal(DnatHook.Output, rule!.Hook));
    }

    /// <summary>An address-keyed projection retains unrelated output-interface scope.</summary>
    [Fact]
    public void SnatMap_ProjectsExactSourceAndPreservesOtherMatches()
    {
        var plan = Plan("""
            map hosts { type ipv6_addr : ipv6_addr; elements = { 2001:db8::2 : 2001:db8::4 }; }
            chain translate { type nat hook postrouting priority srcnat; policy accept; oifname "edge0" snat to ip6 saddr map @hosts; }
            """);
        Assert.True(plan.CanCreateRevision, string.Join(", ", plan.Gaps.Select(gap => gap.Code)));
        var rule = Assert.Single(PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!.Nat!.SnatRules)!;
        Assert.Equal("2001:db8::2/128", rule.Source!.Value);
        Assert.Equal("2001:db8::4", rule.TranslatedAddress);
        Assert.Equal("edge0", rule.OutputInterface);
    }

    /// <summary>Declines calls and projections whose effects cannot be represented.</summary>
    [Theory]
    [InlineData("ip daddr 198.51.100.1 counter dnat ip to tcp dport map @ports", "import.mapScopeUnsupported")]
    [InlineData("ip daddr 198.51.100.1 jump translate", "import.natJumpTargetUnsupported")]
    [InlineData("ip daddr 198.51.100.1 dnat ip to tcp sport map @ports", "import.mapSelectorUnsupported")]
    public void UnsupportedLookupOrCall_DeniesWholeCandidate(string rule, string diagnostic)
    {
        var plan = Plan("map ports { type inet_service : ipv4_addr; elements = { 443 : 192.0.2.2 }; } " +
            "chain translate { type nat hook output priority dstnat; policy accept; " + rule + "; }");
        Assert.Contains(plan.Gaps, gap => gap.Code == diagnostic);
        Assert.Null(plan.PolicyJson);
    }

    private static NativeImportPlan Plan(string natBody)
    {
        var content = new NativeSourceContent("synthetic-nat-maps",
            "table inet sample { chain input { type filter hook input priority filter; policy drop; } }\n" +
            "table inet translate { " + natBody + " }");
        var id = Guid.NewGuid();
        var source = new NativeSourceSnapshot(new(id, content.Name, content.Digest, content.ByteLength, "test", DateTimeOffset.UnixEpoch), content);
        return NativeImportPlanner.Plan(new(id, [new("inet", "sample", NativeImportTableRole.Filter), new("inet", "translate", NativeImportTableRole.Nat)], []), [source]);
    }
}
