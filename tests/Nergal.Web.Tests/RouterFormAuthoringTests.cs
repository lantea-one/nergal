using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web.Tests;

/// <summary>Guided router forms preserve unrelated intent and reject edits that would weaken or misrepresent policy.</summary>
public sealed class RouterFormAuthoringTests
{
    private static string Bundle() => PolicyBundleJsonCodec.EncodeBundle(new(1,
        new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept,
            [new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, Source: new("192.0.2.0/24"), DestinationPort: 443,
                InputInterface: "lan0", RateLimit: new(10, RateLimitTimeUnit.Second, 20, 60), Enabled: false)]),
        new(1, [], [new(IpFamily.IPv4, new("192.0.2.0/24"), "198.51.100.1", Enabled: false)])));

    private static VisualFilterConditionsInput Conditions() => new("02:00:00:00:00:01", true, true, false, true, false, "destinationAddress");
    private static VisualPostroutingInput Postrouting(string action = "masquerade") => new("ipv4", action,
        "192.0.2.0/24", "203.0.113.0/24", null, "lan0", "wan0", "tcp", "443, 9001", false, true, false, false, "Egress");

    /// <summary>MAC/IP pinning and meter keys are changed explicitly without activating dormant rules or losing rate settings.</summary>
    [Fact]
    public void FilterConditions_PreserveUnrelatedStateAndGenerateDestinationMeter()
    {
        Assert.True(PolicyAuthoringService.TryUpdateFilterConditions(Bundle(), 0, Conditions(), out var json, out var errors), string.Join(",", errors));
        var bundle = PolicyBundleJsonCodec.DecodeBundle(json!).Value!;
        var r = bundle.Filter.Rules[0]!;
        Assert.False(r.Enabled); Assert.Equal(443, r.DestinationPort); Assert.Equal("192.0.2.0/24", r.Source!.Value);
        Assert.Equal(10, r.RateLimit!.PacketsPerWindow); Assert.Equal(RateLimitKeyKind.DestinationAddress, r.RateLimit.KeyKind);
        Assert.Equal("02:00:00:00:00:01", r.SourceMac!.Value); Assert.True(r.NegateSourceMac); Assert.True(r.NegateSource); Assert.True(r.NegateInputInterface);
        var active = PolicyRuleStates.SetEnabled(bundle, PolicyRuleScope.Filter, 0, null, true);
        var candidate = NftPolicyBundleCompiler.Compile(active).Candidate!;
        Assert.Contains("ether saddr != 02:00:00:00:00:01", candidate); Assert.Contains("ip saddr != 192.0.2.0/24", candidate);
        Assert.Contains("ip daddr timeout", candidate);
    }

    /// <summary>Unknown keys, invalid MACs and unbound negation fail even for disabled rules.</summary>
    [Fact]
    public void FilterConditions_RejectInvalidEditsWithoutProducingDraft()
    {
        foreach (var input in new[] { Conditions() with { SourceMacs = "broken" }, Conditions() with { RateLimitKey = "unknown" },
            Conditions() with { NegateDestination = true }, Conditions() with { SourceMacs = "" }, Conditions() with { SourceMacs = "02:00:00:00:00:01,02:00:00:00:00:01" } })
        {
            Assert.False(PolicyAuthoringService.TryUpdateFilterConditions(Bundle(), 0, input, out var json, out var errors));
            Assert.Null(json); Assert.NotEmpty(errors);
        }
        Assert.False(PolicyAuthoringService.TryUpdateFilterConditions(Bundle(), -1, Conditions(), out _, out _));
    }

    /// <summary>Complete postrouting edits retain disabled state; new rules append and preserve existing rule order.</summary>
    [Theory]
    [InlineData("masquerade")]
    [InlineData("return")]
    [InlineData("snat")]
    public void Postrouting_EditAndAppendCompleteRule(string action)
    {
        var input = Postrouting(action) with { TranslatedAddress = action == "snat" ? "198.51.100.2" : null };
        Assert.True(PolicyAuthoringService.TrySetPostrouting(Bundle(), 0, input, out var edited, out var errors), string.Join(",", errors));
        var r = PolicyBundleJsonCodec.DecodeBundle(edited!).Value!.Nat!.SnatRules[0]!;
        Assert.False(r.Enabled); Assert.Equal("lan0", r.InputInterface); Assert.True(r.NegateDestination);
        Assert.Equal(new[] { 443, 9001 }, r.DestinationPorts); Assert.Equal(action, r.Action.ToString().ToLowerInvariant());
        Assert.True(PolicyAuthoringService.TrySetPostrouting(edited!, null, input, out var appended, out _));
        var rules = PolicyBundleJsonCodec.DecodeBundle(appended!).Value!.Nat!.SnatRules;
        Assert.Equal(2, rules.Count); Assert.False(rules[0]!.Enabled); Assert.True(rules[1]!.Enabled);
        var firstOnly = new FirewallPolicyBundle(1, PolicyBundleJsonCodec.DecodeBundle(edited!).Value!.Filter,
            new NatPolicy(1, [], [rules[0]]));
        Assert.Equal(edited, PolicyBundleJsonCodec.EncodeBundle(firstOnly, indented: true));
    }

    /// <summary>No ignored translation targets, invalid protocol/port pairs or negations without matchers enter the draft.</summary>
    [Fact]
    public void Postrouting_RejectIncompatibleFields()
    {
        foreach (var input in new[] { Postrouting() with { TranslatedAddress = "198.51.100.1" }, Postrouting("snat"),
            Postrouting() with { Action = "unknown" }, Postrouting() with { Protocol = "icmp" },
            Postrouting() with { Protocol = "any" }, Postrouting() with { Destination = "" },
            Postrouting() with { Source = "garbage" }, Postrouting() with { Family = "ipv6" },
            Postrouting() with { DestinationPorts = "0" } })
        {
            Assert.False(PolicyAuthoringService.TrySetPostrouting(Bundle(), null, input, out var json, out var errors));
            Assert.Null(json); Assert.NotEmpty(errors);
        }
        Assert.False(PolicyAuthoringService.TrySetPostrouting(Bundle(), -1, Postrouting(), out _, out _));
    }

    /// <summary>Reject is a deliberate guided verdict and is upgraded to the schema that supports it.</summary>
    [Fact]
    public void FilterBuilder_RejectProducesExplicitIcmpx()
    {
        Assert.True(PolicyAuthoringService.TryAppendFilterRule(PolicyAuthoringService.DefaultStarterBundleJson,
            new("input", "ipv4", "tcp", "reject", "", "", "443", "", "", "", ""), out var updated, out _));
        Assert.Contains("reject with icmpx type admin-prohibited", NftPolicyBundleCompiler.Compile(PolicyBundleJsonCodec.DecodeBundle(updated!).Value!).Candidate);
    }
}
