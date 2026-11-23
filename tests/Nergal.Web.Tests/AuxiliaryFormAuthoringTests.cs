using System.Text.Json;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web.Tests;

/// <summary>Auxiliary forms operate on one owned draft table without changing independently authored policy sections.</summary>
public sealed class AuxiliaryFormAuthoringTests
{
    private static string Bundle() => PolicyBundleJsonCodec.EncodeBundle(new(1,
        new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, [],
            new(FilterVerdict.Accept, [new(FilterVerdict.Drop, MatchFibUnreachable: true, Enabled: false)]), 1360, false),
        new(1, [], [new(IpFamily.IPv4, new("192.0.2.0/24"), null, Action: NatPostroutingAction.Masquerade, Enabled: false)]),
        new(1, FilterVerdict.Drop, [], -5)), indented: true);
    private static VisualFilterRuleInput Rule() => new("input", "ipv4", "tcp", "reject", "192.0.2.0/24", null, "443", null, "lan0", null, "new",
        RateLimitPackets: 10, RateLimitUnit: "second", RateLimitBurst: 20, RateLimitTimeout: 60, Description: "Restricted service");
    private static VisualFilterConditionsInput Conditions() => new("02:00:00:00:00:01", true, true, false, true, false, "destinationAddress");
    private static string Configured()
    {
        Assert.True(PolicyAuthoringService.TrySetAuxiliaryDefaults(Bundle(), "set", -5, "accept", "drop", "accept", out var json, out _));
        return json!;
    }

    private static void AssertOtherSectionsUnchanged(string before, string after)
    {
        using var a = JsonDocument.Parse(before); using var b = JsonDocument.Parse(after);
        foreach (var name in new[] { "filter", "nat", "bridge" })
        { Assert.Equal(a.RootElement.GetProperty(name).GetRawText(), b.RootElement.GetProperty(name).GetRawText()); }
    }

    /// <summary>Complete matchers compile in the auxiliary table while original primary/NAT/bridge settings remain byte-identical.</summary>
    [Fact]
    public void AuxiliaryRule_CompleteMatchersRetainOtherPolicySections()
    {
        var configured = Configured();
        Assert.True(PolicyAuthoringService.TrySetAuxiliaryRule(configured, "add", null, Rule(), Conditions(), out var json, out var errors), string.Join(",", errors));
        AssertOtherSectionsUnchanged(configured, json!);
        var bundle = PolicyBundleJsonCodec.DecodeBundle(json!).Value!;
        Assert.Equal(-5, bundle.AuxiliaryFilter!.Priority); Assert.Equal(FilterVerdict.Drop, bundle.AuxiliaryFilter.Filter.ForwardDefaultVerdict);
        var candidate = NftPolicyBundleCompiler.Compile(bundle).Candidate!;
        Assert.Contains("inet nergal_aux", candidate); Assert.Contains("priority -5;", candidate);
        Assert.Contains("ether saddr != 02:00:00:00:00:01", candidate); Assert.Contains("ip saddr != 192.0.2.0/24", candidate);
        Assert.Contains("ip daddr timeout", candidate); Assert.Contains("reject with icmpx type admin-prohibited", candidate);
    }

    /// <summary>Editing and moving dormant auxiliary rules retains their state; removal requires an explicitly empty table.</summary>
    [Fact]
    public void AuxiliaryLifecycle_PreservesDormantStateOrderAndDefaults()
    {
        Assert.True(PolicyAuthoringService.TrySetAuxiliaryRule(Configured(), "add", null, Rule(), Conditions(), out var first, out _));
        var disabled = PolicyAuthoringService.EncodeBundle(PolicyRuleStates.SetEnabled(PolicyBundleJsonCodec.DecodeBundle(first!).Value!, PolicyRuleScope.Auxiliary, 0, null, false));
        Assert.True(PolicyAuthoringService.TrySetAuxiliaryRule(disabled, "edit", 0, Rule() with { Description = "Dormant rule" }, Conditions(), out var edited, out _));
        Assert.False(PolicyBundleJsonCodec.DecodeBundle(edited!).Value!.AuxiliaryFilter!.Filter.Rules[0]!.Enabled);
        Assert.True(PolicyAuthoringService.TrySetAuxiliaryRule(edited!, "add", null, Rule(), Conditions(), out var second, out _));
        Assert.True(PolicyAuthoringService.TrySetAuxiliaryRule(second!, "up", 1, Rule(), Conditions(), out var moved, out _));
        Assert.True(PolicyAuthoringService.TrySetAuxiliaryRule(moved!, "down", 0, Rule(), Conditions(), out var restored, out _));
        Assert.Equal(second, restored);
        Assert.False(PolicyAuthoringService.TrySetAuxiliaryDefaults(restored!, "remove", null, null, null, null, out _, out _));
        Assert.True(PolicyAuthoringService.TrySetAuxiliaryRule(restored!, "remove", 1, Rule(), Conditions(), out var one, out _));
        Assert.True(PolicyAuthoringService.TrySetAuxiliaryRule(one!, "remove", 0, Rule(), Conditions(), out var empty, out _));
        Assert.True(PolicyAuthoringService.TrySetAuxiliaryDefaults(empty!, "remove", null, null, null, null, out var removed, out _));
        Assert.Equal(Bundle(), removed);
    }

    /// <summary>Invalid defaults, unknown enums, malformed MACs, unbound negation and incompatible protocols remain denied.</summary>
    [Fact]
    public void AuxiliaryForms_RejectUnsupportedOrIncompatibleInput()
    {
        foreach (var priority in new[] { -301, 301 })
        { Assert.False(PolicyAuthoringService.TrySetAuxiliaryDefaults(Bundle(), "set", priority, "accept", "accept", "accept", out _, out _)); }
        Assert.False(PolicyAuthoringService.TrySetAuxiliaryDefaults(Bundle(), "set", -5, "reject", "accept", "accept", out _, out _));
        Assert.False(PolicyAuthoringService.TrySetAuxiliaryDefaults(Bundle(), "set", null, "accept", "accept", "accept", out _, out _));
        Assert.False(PolicyAuthoringService.TrySetAuxiliaryDefaults(Bundle(), "unknown", -5, "accept", "accept", "accept", out _, out _));
        Assert.False(PolicyAuthoringService.TrySetAuxiliaryRule(Bundle(), "add", null, Rule(), Conditions(), out _, out _));
        foreach (var rule in new[] { Rule() with { Family = "ipv6" }, Rule() with { Protocol = "any" }, Rule() with { Chain = "output" },
            Rule() with { Verdict = "unknown" }, Rule() with { Sources = "garbage" }, Rule() with { RateLimitBurst = null } })
        { Assert.False(PolicyAuthoringService.TrySetAuxiliaryRule(Configured(), "add", null, rule, Conditions(), out _, out _)); }
        foreach (var conditions in new[] { Conditions() with { SourceMacs = "invalid" }, Conditions() with { NegateDestination = true }, Conditions() with { RateLimitKey = "unknown" } })
        { Assert.False(PolicyAuthoringService.TrySetAuxiliaryRule(Configured(), "add", null, Rule(), conditions, out _, out _)); }
        foreach (var (op, index) in new (string, int?)[] { ("edit", null), ("remove", 0), ("up", -1), ("add", 0), ("unknown", null) })
        { Assert.False(PolicyAuthoringService.TrySetAuxiliaryRule(Configured(), op, index, Rule(), Conditions(), out _, out _)); }
    }
}
