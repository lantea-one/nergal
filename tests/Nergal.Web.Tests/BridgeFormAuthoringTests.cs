using System.Text.Json;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web.Tests;

/// <summary>Complete bridge authoring preserves scope/state and rejects unsupported graph or matcher semantics.</summary>
public sealed class BridgeFormAuthoringTests
{
    private static VisualExtendedBridgeInput Rule(string action = "accept") => new("ipv4", action, "lan0", "lan1", "br0",
        "02:00:00:00:00:01", "02:00:00:00:00:02", false, true, "ipv4", "192.0.2.0/24", "198.51.100.0/24", "tcp", "80,443", null, "Synthetic bridge rule");
    private static string Bundle() => PolicyBundleJsonCodec.EncodeBundle(new(1,
        new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, [], forwardTcpMssClamp: 1360, forwardTcpMssClampEnabled: false),
        new(1, [], [new(IpFamily.IPv4, null, null, Action: NatPostroutingAction.Masquerade, Enabled: false)]),
        auxiliaryFilter: new(-5, new(2, FilterVerdict.Accept, FilterVerdict.Accept, FilterVerdict.Accept, []))), indented: true);
    private static string Configured()
    {
        Assert.True(PolicyAuthoringService.TrySetBridgeSettings(Bundle(), "set", -5, "drop", out var json, out _));
        Assert.True(PolicyAuthoringService.TrySetBridgeChain(json!, "add", "mail", out var chain, out _));
        return chain!;
    }

    /// <summary>Bridge L2/L3/L4 restrictions and local control flow compile explicitly while other policy sections remain unchanged.</summary>
    [Fact]
    public void BridgeForms_CompleteMatchersAndJumpReturnPreserveOtherSections()
    {
        Assert.True(PolicyAuthoringService.TrySetExtendedBridgeRule(Configured(), "add", "mail", null, Rule(), out var matched, out _));
        Assert.True(PolicyAuthoringService.TrySetExtendedBridgeRule(matched!, "add", "mail", null, Rule("return"), out var returned, out _));
        Assert.True(PolicyAuthoringService.TrySetExtendedBridgeRule(returned!, "add", null, null, Rule("jump") with { JumpTarget = "mail" }, out var jumped, out _));
        var b = PolicyBundleJsonCodec.DecodeBundle(jumped!).Value!;
        Assert.Equal(-5, b.Bridge!.Priority); Assert.Equal("mail", b.Bridge.Rules[0]!.JumpTarget); Assert.True(b.Bridge.SubChains[0].Rules[1]!.Return);
        var candidate = NftPolicyBundleCompiler.Compile(b).Candidate!;
        foreach (var fragment in new[] { "priority -5;", "meta ibrname \"br0\"", "ether daddr != 02:00:00:00:00:02", "ip saddr 192.0.2.0/24", "tcp dport { 80, 443 }", "jump mail", "return" })
        { Assert.Contains(fragment, candidate); }
        using var a = JsonDocument.Parse(Bundle()); using var after = JsonDocument.Parse(jumped!);
        foreach (var name in new[] { "filter", "nat", "auxiliaryFilter" })
        { Assert.Equal(a.RootElement.GetProperty(name).GetRawText(), after.RootElement.GetProperty(name).GetRawText()); }
    }

    /// <summary>Disabled rules stay disabled during edits/reorders and deletion requires explicit emptying and no remaining jump references.</summary>
    [Fact]
    public void BridgeLifecycle_PreservesDormantStateAndProtectsJumpReferences()
    {
        Assert.True(PolicyAuthoringService.TrySetExtendedBridgeRule(Configured(), "add", "mail", null, Rule("return"), out var first, out _));
        var disabled = PolicyAuthoringService.EncodeBundle(PolicyRuleStates.SetEnabled(PolicyBundleJsonCodec.DecodeBundle(first!).Value!, PolicyRuleScope.BridgeChain, 0, "mail", false));
        Assert.True(PolicyAuthoringService.TrySetExtendedBridgeRule(disabled, "edit", "mail", 0, Rule("return") with { Description = "Dormant" }, out var edited, out _));
        Assert.False(PolicyBundleJsonCodec.DecodeBundle(edited!).Value!.Bridge!.SubChains[0].Rules[0]!.Enabled);
        Assert.True(PolicyAuthoringService.TrySetExtendedBridgeRule(edited!, "add", "mail", null, Rule(), out var second, out _));
        Assert.True(PolicyAuthoringService.TrySetExtendedBridgeRule(second!, "up", "mail", 1, Rule(), out var moved, out _));
        Assert.True(PolicyAuthoringService.TrySetExtendedBridgeRule(moved!, "down", "mail", 0, Rule(), out var restored, out _));
        Assert.Equal(second, restored);
        Assert.False(PolicyAuthoringService.TrySetBridgeChain(restored!, "remove", "mail", out _, out _));
        Assert.True(PolicyAuthoringService.TrySetExtendedBridgeRule(restored!, "remove", "mail", 1, Rule(), out var one, out _));
        Assert.True(PolicyAuthoringService.TrySetExtendedBridgeRule(one!, "remove", "mail", 0, Rule(), out var empty, out _));
        Assert.True(PolicyAuthoringService.TrySetExtendedBridgeRule(empty!, "add", null, null, Rule("jump") with { JumpTarget = "mail" }, out var jump, out _));
        Assert.False(PolicyAuthoringService.TrySetBridgeChain(jump!, "remove", "mail", out _, out _));
        Assert.True(PolicyAuthoringService.TrySetExtendedBridgeRule(jump!, "remove", null, 0, Rule(), out var noJump, out _));
        Assert.True(PolicyAuthoringService.TrySetBridgeChain(noJump!, "remove", "mail", out var noChain, out _));
        Assert.True(PolicyAuthoringService.TrySetBridgeSettings(noChain!, "remove", null, null, out var noTable, out _));
        Assert.Equal(Bundle(), noTable);
    }

    /// <summary>Missing/cyclic targets, base-chain returns and incompatible or unknown form semantics never produce an updated draft.</summary>
    [Fact]
    public void BridgeForms_RejectInvalidGraphMatchersAndLocations()
    {
        foreach (var input in new[] { Rule("unknown"), Rule("return"), Rule("jump"), Rule("jump") with { JumpTarget = "missing" },
            Rule() with { JumpTarget = "mail" }, Rule() with { EtherType = "arp" }, Rule() with { Family = "none" },
            Rule() with { Protocol = "any" }, Rule() with { Protocol = "icmp" }, Rule() with { SourceMac = "invalid" },
            Rule() with { DestinationMac = null }, Rule() with { DestinationPorts = "0" }, Rule() with { Source = "garbage" } })
        { Assert.False(PolicyAuthoringService.TrySetExtendedBridgeRule(Configured(), "add", null, null, input, out _, out _)); }
        Assert.False(PolicyAuthoringService.TrySetExtendedBridgeRule(Configured(), "add", "mail", null, Rule("jump") with { JumpTarget = "mail" }, out _, out _));
        Assert.False(PolicyAuthoringService.TrySetExtendedBridgeRule(Configured(), "add", "unknown", null, Rule(), out _, out _));
        Assert.False(PolicyAuthoringService.TrySetExtendedBridgeRule(Configured(), "edit", "mail", int.MaxValue, Rule(), out _, out _));
        foreach (var name in new[] { "forward", "mail", "bad;command", "123", "" })
        { Assert.False(PolicyAuthoringService.TrySetBridgeChain(Configured(), "add", name, out _, out _)); }
        Assert.False(PolicyAuthoringService.TrySetBridgeSettings(Configured(), "set", -301, "drop", out _, out _));
        Assert.False(PolicyAuthoringService.TrySetBridgeSettings(Configured(), "set", -5, "reject", out _, out _));
        Assert.False(PolicyAuthoringService.TrySetBridgeSettings(Configured(), "remove", null, null, out _, out _));
    }
}
