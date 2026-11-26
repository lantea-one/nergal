using Nergal.Core.Controller;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Native literal expansion preserves nft semantics without changing authored policy validation.</summary>
public sealed class NativeImportLiteralTests
{
    /// <summary>Lexical groups become one predicate, and nft CIDR masking retains the actual network.</summary>
    [Fact]
    public void NestedDefinitionsAndHostBits_PreserveSingleCountedRule()
    {
        var plan = Plan("""
            define devices = { "lo", "lab-*" }
            define input_devices = { $devices }
            define sites = { 2001:db8::1234/64, 2001:db8:2::23/64 }
            table inet sample {
              chain input {
                type filter hook input priority filter; policy drop;
                iifname { $input_devices } ip6 saddr { $sites, 2001:db8:4::/64 } counter accept;
              }
            }
            """);
        Assert.True(plan.CanCreateRevision, string.Join(", ", plan.Gaps.Select(gap => gap.Code)));
        var bundle = PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!;
        var rule = Assert.Single(bundle.Filter.Rules)!;
        Assert.True(rule.CountPackets);
        Assert.Equal(["lab-*", "lo"], rule.InputInterfaceSelector!.Patterns.Select(pattern => pattern.Value));
        Assert.Equal(["2001:db8::/64", "2001:db8:2::/64", "2001:db8:4::/64"], rule.SourcePrefixes!.Select(prefix => prefix.Value));
        Assert.Throws<ArgumentException>(() => new NetworkPrefix("2001:db8::1234/64"));
    }

    /// <summary>Nested collections retain the limit on the final number of entries.</summary>
    [Fact]
    public void NestedLiteralCollections_RejectMoreThanSixtyFourEntries()
    {
        var terms = string.Join(", ", Enumerable.Repeat("{ 192.0.2.1, 192.0.2.2 }", 33));
        var plan = Plan("table inet sample { chain input { type filter hook input priority 0; ip saddr { " +
            terms + " } accept; } }");
        Assert.Contains(plan.Gaps, gap => gap.Code == "import.listLimit");
        Assert.Null(plan.PolicyJson);
    }

    private static NativeImportPlan Plan(string text)
    {
        var content = new NativeSourceContent("synthetic-literals", text);
        var id = Guid.NewGuid();
        var source = new NativeSourceSnapshot(new(id, content.Name, content.Digest, content.ByteLength, "test", DateTimeOffset.UnixEpoch), content);
        return NativeImportPlanner.Plan(new(id, [new("inet", "sample", NativeImportTableRole.Filter)], []), [source]);
    }
}
