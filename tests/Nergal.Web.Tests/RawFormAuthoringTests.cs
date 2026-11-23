using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web.Tests;

/// <summary>Raw/MSS/DNAT guided edits never activate dormant intent or silently discard invalid matchers.</summary>
public sealed class RawFormAuthoringTests
{
    private static VisualRawRuleInput Rule() => new("ipv4", "accept", "udp", null, false, "lan0", false, 68, null, false, "DHCP exception");
    private static string Bundle() => PolicyBundleJsonCodec.EncodeBundle(new(1,
        new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, [], new(FilterVerdict.Accept,
            [new(FilterVerdict.Drop, MatchFibUnreachable: true, Description: "Reverse path", Enabled: false)]), 1360, false),
        new(1, [new(IpFamily.IPv4, FilterProtocol.Tcp, new("192.0.2.1/32"), "198.51.100.1", 443, 8443, "wan0", new("203.0.113.0/24"), Enabled: false)], [])));

    /// <summary>Exceptions can precede the FIB drop, keep independent state and be removed without resetting chain defaults.</summary>
    [Fact]
    public void RawRule_AddMoveEditRemoveRetainsDormantContentsAndOrder()
    {
        Assert.True(PolicyAuthoringService.TrySetRawRule(Bundle(), null, "add", Rule(), out var added, out _));
        Assert.True(PolicyAuthoringService.TrySetRawRule(added!, 1, "up", Rule(), out var moved, out _));
        var b = PolicyBundleJsonCodec.DecodeBundle(moved!).Value!;
        Assert.Equal(68, b.Filter.RpFilter!.Rules[0]!.SourcePort);
        Assert.False(b.Filter.RpFilter.Rules[1]!.Enabled); Assert.True(b.Filter.RpFilter.Rules[1]!.MatchFibUnreachable);
        Assert.Equal(1360, b.Filter.ForwardTcpMssClamp); Assert.False(b.Filter.ForwardTcpMssClampEnabled);
        Assert.True(PolicyAuthoringService.TrySetRawRule(moved!, 1, "edit", Rule() with { Verdict = "drop", SourcePort = null, MatchFibUnreachable = true }, out var edited, out _));
        Assert.False(PolicyBundleJsonCodec.DecodeBundle(edited!).Value!.Filter.RpFilter!.Rules[1]!.Enabled);
        Assert.True(PolicyAuthoringService.TrySetRawRule(moved!, 0, "remove", Rule(), out var removed, out _));
        Assert.Equal(Bundle(), removed);
        var candidate = NftPolicyBundleCompiler.Compile(b).Candidate!;
        Assert.Contains("hook prerouting priority raw", candidate); Assert.Contains("udp sport 68 accept", candidate);
        Assert.DoesNotContain("fib saddr", candidate);
    }

    /// <summary>Unknown form enums, unbound negation and incompatible source/port/family combinations fail before draft replacement.</summary>
    [Fact]
    public void RawRule_RejectUnknownOrIncompatibleInputAndInvalidLocations()
    {
        foreach (var input in new[] { Rule() with { Family = "unknown" }, Rule() with { Verdict = "reject" }, Rule() with { Protocol = "icmp" },
            Rule() with { Protocol = "any" }, Rule() with { SourcePort = 0 }, Rule() with { Source = "garbage" },
            Rule() with { NegateSource = true }, Rule() with { Family = "any", Source = "192.0.2.0/24" },
            Rule() with { InputInterface = "", NegateInputInterface = true }, Rule() with { Family = "ipv6", Source = "192.0.2.0/24" } })
        {
            Assert.False(PolicyAuthoringService.TrySetRawRule(Bundle(), null, "add", input, out var updated, out var errors));
            Assert.Null(updated); Assert.NotEmpty(errors);
        }
        foreach (var (index, operation) in new (int?, string)[] { (0, "add"), (null, "edit"), (-1, "remove"), (1, "edit"), (0, "up"), (0, "down"), (0, "unknown") })
        { Assert.False(PolicyAuthoringService.TrySetRawRule(Bundle(), index, operation, Rule(), out _, out _)); }
    }

    /// <summary>Changing the raw default retains all ordered rules, including dormant entries.</summary>
    [Fact]
    public void RawDefault_ChangesOnlyChainDefault()
    {
        Assert.True(PolicyAuthoringService.TrySetRawDefault(Bundle(), "drop", out var updated, out _));
        var b = PolicyBundleJsonCodec.DecodeBundle(updated!).Value!;
        Assert.Equal(FilterVerdict.Drop, b.Filter.RpFilter!.DefaultVerdict);
        Assert.False(b.Filter.RpFilter.Rules[0]!.Enabled); Assert.True(b.Filter.RpFilter.Rules[0]!.MatchFibUnreachable);
        Assert.False(PolicyAuthoringService.TrySetRawDefault(Bundle(), "reject", out _, out _));
        Assert.False(PolicyAuthoringService.TrySetRawDefault(Bundle(), "remove", out _, out _));
        var empty = PolicyBundleJsonCodec.EncodeBundle(new(1,
            new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, [], new(FilterVerdict.Drop, []))));
        Assert.True(PolicyAuthoringService.TrySetRawDefault(empty, "remove", out var removed, out _));
        Assert.Null(PolicyBundleJsonCodec.DecodeBundle(removed!).Value!.Filter.RpFilter);
        Assert.True(PolicyAuthoringService.TrySetRawDefault(removed!, "accept", out var created, out _));
        Assert.Empty(PolicyBundleJsonCodec.DecodeBundle(created!).Value!.Filter.RpFilter!.Rules);

    }

    /// <summary>Resizing a disabled clamp cannot activate it; remove is explicit and invalid sizes are rejected while dormant.</summary>
    [Fact]
    public void Mss_ResizePreservesStateAndRemovalClearsConfiguration()
    {
        Assert.True(PolicyAuthoringService.TrySetMss(Bundle(), "set", 1400, out var updated, out _));
        var b = PolicyBundleJsonCodec.DecodeBundle(updated!).Value!;
        Assert.Equal(1400, b.Filter.ForwardTcpMssClamp); Assert.False(b.Filter.ForwardTcpMssClampEnabled);
        foreach (var size in new[] { 0, 535, 1461, 65535 })
        { Assert.False(PolicyAuthoringService.TrySetMss(Bundle(), "set", size, out _, out _)); }
        Assert.False(PolicyAuthoringService.TrySetMss(Bundle(), "set", null, out _, out _));
        Assert.False(PolicyAuthoringService.TrySetMss(Bundle(), "remove", 1360, out _, out _));
        Assert.False(PolicyAuthoringService.TrySetMss(Bundle(), "unknown", 1360, out _, out _));
        Assert.True(PolicyAuthoringService.TrySetMss(updated!, "remove", null, out var removed, out _));
        var cleared = PolicyBundleJsonCodec.DecodeBundle(removed!).Value!;
        Assert.Null(cleared.Filter.ForwardTcpMssClamp); Assert.True(cleared.Filter.ForwardTcpMssClampEnabled);
        Assert.True(PolicyAuthoringService.TrySetMss(removed!, "set", 1360, out var added, out _));
        Assert.Contains("tcp flags syn tcp option maxseg size set 1360", NftPolicyBundleCompiler.Compile(PolicyBundleJsonCodec.DecodeBundle(added!).Value!).Candidate);
    }

    /// <summary>DNAT negations retain ports, translation and lifecycle state; missing matchers cannot be negated.</summary>
    [Fact]
    public void DnatConditions_PreserveFullRuleAndDenyInvalidReferences()
    {
        Assert.True(PolicyAuthoringService.TrySetDnatConditions(Bundle(), 0, true, true, true, out var updated, out _));
        var b = PolicyBundleJsonCodec.DecodeBundle(updated!).Value!;
        var rule = b.Nat!.DnatRules[0]!;
        Assert.False(rule.Enabled); Assert.Equal(443, rule.OriginalPort); Assert.Equal(8443, rule.TranslatedPort);
        Assert.True(rule.NegateSource); Assert.True(rule.NegateDestination); Assert.True(rule.NegateInputInterface);
        Assert.True(PolicyAuthoringService.TrySetDnatConditions(updated!, 0, false, false, false, out var reverted, out _));
        Assert.Equal(Bundle(), reverted);
        Assert.False(PolicyAuthoringService.TrySetDnatConditions(Bundle(), 1, true, true, true, out _, out _));
        var missing = PolicyBundleJsonCodec.EncodeBundle(new(1, b.Filter, new(1, [rule with { Source = null, NegateSource = false }], [])));
        Assert.False(PolicyAuthoringService.TrySetDnatConditions(missing, 0, true, false, false, out _, out _));
    }
    /// <summary>NAT exemptions can move ahead of translations while preserving dormant state and every matcher.</summary>
    [Theory]
    [InlineData("dnat")]
    [InlineData("postrouting")]
    public void NatMovement_RetainsOrderedContentsAndRejectsOutOfRange(string kind)
    {
        var bundle = PolicyBundleJsonCodec.DecodeBundle(Bundle()).Value!;
        var dnat = bundle.Nat!.DnatRules[0]!;
        var json = PolicyBundleJsonCodec.EncodeBundle(new(1, bundle.Filter,
            new(1, [dnat, dnat with { Description = "Second" }],
                [new(IpFamily.IPv4, null, null, Action: NatPostroutingAction.Masquerade),
                 new(IpFamily.IPv4, new("192.0.2.0/24"), null, Action: NatPostroutingAction.Return, Enabled: false)])), indented: true);
        Assert.True(PolicyAuthoringService.TryMoveNatRule(json, kind, 1, -1, out var moved, out _));
        var changed = PolicyBundleJsonCodec.DecodeBundle(moved!).Value!;
        if (kind == "postrouting") { Assert.Equal(NatPostroutingAction.Return, changed.Nat!.SnatRules[0]!.Action); Assert.False(changed.Nat.SnatRules[0]!.Enabled); }
        else { Assert.Equal("Second", changed.Nat!.DnatRules[0]!.Description); Assert.False(changed.Nat.DnatRules[0]!.Enabled); }
        Assert.True(PolicyAuthoringService.TryMoveNatRule(moved!, kind, 0, 1, out var restored, out _));
        Assert.Equal(json, restored);
        foreach (var (index, direction) in new[] { (-1, 1), (0, -1), (1, 1), (int.MaxValue, 1), (0, 2) })
        { Assert.False(PolicyAuthoringService.TryMoveNatRule(json, kind, index, direction, out _, out _)); }
        Assert.False(PolicyAuthoringService.TryMoveNatRule(json, "unknown", 0, 1, out _, out _));
    }
    /// <summary>Adding schema-2 constructs upgrades only known schema 1; unknown schemas remain denied.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(99)]
    public void Forms_DoNotNormalizeUnknownPolicySchemas(int schema)
    {
        var json = PolicyBundleJsonCodec.EncodeBundle(new(1, new(schema, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept,
            [new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept)])));
        Assert.False(PolicyAuthoringService.TrySetMss(json, "set", 1360, out _, out _));
        Assert.False(PolicyAuthoringService.TrySetRawDefault(json, "accept", out _, out _));
        Assert.False(PolicyAuthoringService.TryUpdateFilterConditions(json, 0, new(null, false, false, false, false, false, "sourceAddress"), out _, out _));
    }
}
