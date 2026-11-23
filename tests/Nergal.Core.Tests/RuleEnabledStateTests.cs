using System.Text.Json.Nodes;
using Nergal.Core.Controller;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Dormant intent remains valid, immutable and recoverable while native projection contains active rules only.</summary>
public sealed class RuleEnabledStateTests
{
    private static FirewallPolicyBundle Sample()
    {
        var reference = new PolicyObjectReference(Guid.Parse("11111111-1111-4111-8111-111111111111"), 1, new("clients", ReusableObjectKind.Ipv4, "", ["192.0.2.10"]));
        return new(1, new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept,
            [new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, SourceObject: reference, DestinationPort: 443, Description: "Retain pin"),
             new(IpFamily.IPv6, FilterProtocol.Udp, FilterVerdict.Drop, RateLimit: new(3, RateLimitTimeUnit.Second, 2, 30))],
            new(FilterVerdict.Accept, [new(FilterVerdict.Drop, MatchFibUnreachable: true)]), 1360),
            new(1, [new(IpFamily.IPv4, FilterProtocol.Tcp, new("192.0.2.1/32"), "198.51.100.1", 443, 8443)],
                [new(IpFamily.IPv4, new("192.0.2.0/24"), "203.0.113.1")]),
            new(1, FilterVerdict.Accept, [new(BridgeEtherType.IPv4, FilterVerdict.Drop, JumpTarget: "transit")], -5,
                [new("transit", [new(BridgeEtherType.Any, FilterVerdict.Drop, Return: true)])]),
            new(-5, new(2, FilterVerdict.Accept, FilterVerdict.Drop, FilterVerdict.Accept, [new(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Drop)])));
    }

    /// <summary>Every state location restores byte-identical intent and native output, without mutating its caller.</summary>
    [Fact]
    public void State_AllScopesPreserveSettingsOrderAndReferences()
    {
        var original = Sample(); var json = PolicyBundleJsonCodec.EncodeBundle(original);
        var compiled = NftPolicyBundleCompiler.Compile(original); Assert.True(compiled.IsSuccess);
        var states = PolicyRuleStates.Enumerate(original); Assert.Equal(9, states.Count);
        foreach (var state in states)
        {
            var disabled = PolicyRuleStates.SetEnabled(original, state.Scope, state.Index, state.Chain, false);
            Assert.False(PolicyRuleStates.Enumerate(disabled).Single(s => s.Scope == state.Scope && s.Index == state.Index && s.Chain == state.Chain).Enabled);
            var stored = PolicyBundleJsonCodec.EncodeBundle(disabled); var decoded = PolicyBundleJsonCodec.DecodeBundle(stored);
            Assert.True(decoded.IsSuccess); Assert.True(NftPolicyBundleCompiler.Compile(decoded.Value!).IsSuccess);
            var restored = PolicyRuleStates.SetEnabled(decoded.Value!, state.Scope, state.Index, state.Chain, true);
            Assert.Equal(json, PolicyBundleJsonCodec.EncodeBundle(restored));
            Assert.Equal(compiled.Candidate, NftPolicyBundleCompiler.Compile(restored).Candidate);
            Assert.Equal(json, PolicyBundleJsonCodec.EncodeBundle(original));
        }
    }

    /// <summary>All-disabled intent emits no rule or dynamic meter, retaining explicit chains/tables and defaults.</summary>
    [Fact]
    public void State_DisabledProjectionOmitsRulesAndMetersWithoutChangingDefaults()
    {
        var original = Sample(); var disabled = original;
        foreach (var state in PolicyRuleStates.Enumerate(original)) { disabled = PolicyRuleStates.SetEnabled(disabled, state.Scope, state.Index, state.Chain, false); }
        var result = NftPolicyBundleCompiler.Compile(disabled); Assert.True(result.IsSuccess);
        Assert.DoesNotContain("add rule", result.Candidate); Assert.DoesNotContain("add set", result.Candidate);
        Assert.Contains("priority raw; policy accept", result.Candidate);
        Assert.Contains("add chain bridge nergal_bridge transit", result.Candidate);
        Assert.Contains("policy drop", result.Candidate);
        Assert.Equal(9, PolicyRuleStates.Enumerate(disabled).Count);
        Assert.NotNull(disabled.Filter.Rules[0]!.SourceObject);
    }

    /// <summary>Disabled rules do not bypass family, NAT target, raw port, jump or MSS validation.</summary>
    [Fact]
    public void State_DisablingInvalidIntentCannotProduceCandidate()
    {
        Assert.False(NftFilterCompiler.Compile(new(2, FilterVerdict.Drop, [new((IpFamily)99, FilterProtocol.Any, FilterVerdict.Accept, Enabled: false)])).IsSuccess);
        Assert.False(NftNatCompiler.Compile(new(1, [new(IpFamily.IPv4, FilterProtocol.Tcp, new("192.0.2.1/32"), "bad", Enabled: false)], [])).IsSuccess);
        Assert.False(NftBridgeCompiler.Compile(new(1, FilterVerdict.Drop, [new(BridgeEtherType.Any, FilterVerdict.Drop, JumpTarget: "missing", Enabled: false)])).IsSuccess);
        Assert.False(NftFilterCompiler.Compile(new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, [], new(FilterVerdict.Accept, [new(FilterVerdict.Drop, Protocol: FilterProtocol.Udp, SourcePort: 65536, Enabled: false)]))).IsSuccess);
        Assert.False(NftFilterCompiler.Compile(new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, [], forwardTcpMssClamp: 100, forwardTcpMssClampEnabled: false)).IsSuccess);
        Assert.False(NftFilterCompiler.Compile(new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, [], forwardTcpMssClampEnabled: false)).IsSuccess);
    }

    /// <summary>Old documents default to enabled; malformed/null/string state never becomes a truthy boolean.</summary>
    [Theory]
    [InlineData("null")]
    [InlineData("0")]
    [InlineData("\"false\"")]
    public void State_CodecRejectsNonBooleanEveryScope(string value)
    {
        foreach (var path in new[] { "filter", "raw", "mss", "aux", "dnat", "snat", "bridge", "chain" })
        {
            var json = JsonNode.Parse(PolicyBundleJsonCodec.EncodeBundle(Sample()))!;
            var node = path switch
            {
                "raw" => json["filter"]!["rpFilter"]!["rules"]![0]!,
                "mss" => json["filter"]!,
                "aux" => json["auxiliaryFilter"]!["filter"]!["rules"]![0]!,
                "dnat" => json["nat"]!["dnatRules"]![0]!,
                "snat" => json["nat"]!["snatRules"]![0]!,
                "bridge" => json["bridge"]!["rules"]![0]!,
                "chain" => json["bridge"]!["subChains"]![0]!["rules"]![0]!,
                _ => json["filter"]!["rules"]![0]!
            };
            node[path == "mss" ? "forwardTcpMssClampEnabled" : "enabled"] = JsonNode.Parse(value);
            Assert.False(PolicyBundleJsonCodec.DecodeBundle(json.ToJsonString()).IsSuccess);
        }
        Assert.All(PolicyRuleStates.Enumerate(PolicyBundleJsonCodec.DecodeBundle(PolicyBundleJsonCodec.EncodeBundle(Sample())).Value!), s => Assert.True(s.Enabled));
    }

    /// <summary>Untrusted locations cannot change another rule, scope or chain.</summary>
    [Fact]
    public void State_RejectsUnknownLocations()
    {
        var bundle = Sample();
        Assert.Throws<ArgumentException>(() => PolicyRuleStates.SetEnabled(bundle, (PolicyRuleScope)99, 0, null, false));
        Assert.Throws<ArgumentException>(() => PolicyRuleStates.SetEnabled(bundle, PolicyRuleScope.Filter, -1, null, false));
        Assert.Throws<ArgumentException>(() => PolicyRuleStates.SetEnabled(bundle, PolicyRuleScope.BridgeChain, 0, "missing", false));
        Assert.Throws<ArgumentException>(() => PolicyRuleStates.SetEnabled(bundle, PolicyRuleScope.Filter, 0, "unexpected", false));
    }
}
