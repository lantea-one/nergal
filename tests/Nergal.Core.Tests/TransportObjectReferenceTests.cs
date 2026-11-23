using System.Text.Json.Nodes;
using Nergal.Core.Controller;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Embedded transport-list identity survives serialization while native enforcement remains exactly equivalent to explicit literal matching.</summary>
public sealed class TransportObjectReferenceTests
{
    private static PolicyObjectReference Reference(params string[] ports) => new(Guid.Parse("11111111-1111-4111-8111-111111111111"), 1, new("services", ReusableObjectKind.Port, "Synthetic", ports));
    private static FirewallPolicyBundle Bundle(PolicyObjectReference? reference, bool enabled = true, bool singleton = false) => new(1,
        new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, [], forwardTcpMssClamp: 1360, forwardTcpMssClampEnabled: false),
        new(1, [], [new(IpFamily.IPv6, new("2001:db8:1::/64"), null, Action: NatPostroutingAction.Masquerade,
            InputInterface: "lan0", OutputInterface: "wan0", Protocol: FilterProtocol.Tcp, Enabled: enabled, DestinationPortObject: reference, DestinationPort: reference is null && singleton ? 443 : null, DestinationPorts: reference is null && !singleton ? new[] { 443, 9001 } : null)]),
        new(1, FilterVerdict.Drop, [new(BridgeEtherType.Any, FilterVerdict.Drop, BridgeName: "br0", SourceMac: new("02:00:00:00:00:01"), Protocol: FilterProtocol.Tcp,
            JumpTarget: "service", DestinationPortObject: reference, Enabled: enabled, DestinationPort: reference is null && singleton ? 443 : null, DestinationPorts: reference is null && !singleton ? new[] { 443, 9001 } : null)], -5,
            [new("service", [new(BridgeEtherType.IPv4, FilterVerdict.Drop, Family: IpFamily.IPv4, Source: new("192.0.2.0/24"), Protocol: FilterProtocol.Tcp,
                Return: true, Enabled: enabled, DestinationPortObject: reference, DestinationPort: reference is null && singleton ? 443 : null, DestinationPorts: reference is null && !singleton ? new[] { 443, 9001 } : null)])]));

    /// <summary>Singleton and multi-port references round-trip, preserve dormant state and produce byte-identical native transactions to literals.</summary>
    [Theory]
    [InlineData(true, true)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(false, false)]
    public void RoundTripAndProjection_PreserveIntentAndLiteralEnforcement(bool singleton, bool enabled)
    {
        var reference = singleton ? Reference("443") : Reference("443", "9001");
        var original = Bundle(reference, enabled);
        var json = PolicyBundleJsonCodec.EncodeBundle(original);
        var decoded = PolicyBundleJsonCodec.DecodeBundle(json);
        Assert.True(decoded.IsSuccess); Assert.Equal(json, PolicyBundleJsonCodec.EncodeBundle(decoded.Value!));
        var bindings = PolicyObjectReferences.Enumerate(decoded.Value!);
        Assert.Equal(new[] { "nat.snatRules[0].destinationPortObject", "bridge.rules[0].destinationPortObject", "bridge.subChains[0].rules[0].destinationPortObject" }, bindings.Select(b => b.Path));
        Assert.All(bindings, b => Assert.Equal(reference, b.Reference));
        var errors = new List<PolicyObjectDiagnostic>();
        var nat = TransportObjectResolver.Resolve(original.Nat!, errors); var bridge = TransportObjectResolver.Resolve(original.Bridge!, errors);
        Assert.Empty(errors); Assert.Null(nat.SnatRules[0]!.DestinationPortObject); Assert.Null(bridge.SubChains[0].Rules[0]!.DestinationPortObject);
        var literals = Bundle(null, enabled, singleton);
        Assert.Equal(NftPolicyBundleCompiler.Compile(literals).Candidate, NftPolicyBundleCompiler.Compile(decoded.Value!).Candidate);
        Assert.True(NftPolicyBundleCompiler.Compile(decoded.Value!).IsSuccess);
        Assert.Equal(enabled, nat.SnatRules[0]!.Enabled); Assert.Equal("service", bridge.Rules[0]!.JumpTarget);
        Assert.Equal(reference, original.Nat!.SnatRules[0]!.DestinationPortObject);
        Assert.Equal("wan0", nat.SnatRules[0]!.OutputInterface); Assert.True(bridge.SubChains[0].Rules[0]!.Return);
        Assert.False(decoded.Value!.Filter.ForwardTcpMssClampEnabled);
    }

    /// <summary>Type conflicts and incompatible protocols fail even for dormant policies; no partial candidate can be emitted.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Validation_RejectInvalidReferenceMatchers(bool enabled)
    {
        var valid = Bundle(Reference("443", "9001"), enabled);
        var wrong = new PolicyObjectReference(Guid.NewGuid(), 1, new("clients", ReusableObjectKind.Ipv4, "", ["192.0.2.10"]));
        foreach (var rule in new[] { valid.Nat!.SnatRules[0]! with { DestinationPortObject = wrong }, valid.Nat.SnatRules[0]! with { DestinationPort = 443 },
            valid.Nat.SnatRules[0]! with { DestinationPorts = new[] { 443, 9001 } }, valid.Nat.SnatRules[0]! with { Protocol = FilterProtocol.Any } })
        { var result = NftNatCompiler.Compile(new(1, [], [rule])); Assert.False(result.IsSuccess); Assert.Null(result.Candidate); }
        foreach (var rule in new[] { valid.Bridge!.Rules[0]! with { DestinationPortObject = wrong }, valid.Bridge.Rules[0]! with { DestinationPort = 443 },
            valid.Bridge.Rules[0]! with { Protocol = FilterProtocol.Any }, valid.Bridge.Rules[0]! with { DestinationPorts = new[] { 443, 9001 } } })
        { var result = NftBridgeCompiler.Compile(new(1, FilterVerdict.Drop, [rule], -5, valid.Bridge.SubChains)); Assert.False(result.IsSuccess); Assert.Null(result.Candidate); }
        var nullChain = new BridgePolicy(1, FilterVerdict.Drop, valid.Bridge!.Rules, -5, [null!]);
        Assert.False(NftBridgeCompiler.Compile(nullChain).IsSuccess);
        Assert.Single(PolicyObjectReferences.Enumerate(new(1, valid.Filter, bridge: nullChain)));
    }

    /// <summary>Strict decoding rejects null, forged, unknown or mistyped embedded references at every newly supported scope.</summary>
    [Theory]
    [InlineData("nat")]
    [InlineData("bridge")]
    [InlineData("regular")]
    public void Codec_RejectMalformedReferences(string scope)
    {
        foreach (var mutation in new Action<JsonObject>[] { r => r["destinationPortObject"] = null,
            r => r["destinationPortObject"]!["digest"] = new string('a', 64), r => r["destinationPortObject"]!["version"] = 0,
            r => r["destinationPortObject"]!["unexpected"] = true, r => r["destinationPortObject"]!["kind"] = "unknown" })
        {
            var root = JsonNode.Parse(PolicyBundleJsonCodec.EncodeBundle(Bundle(Reference("443"))))!;
            var rule = scope switch { "nat" => root["nat"]!["snatRules"]![0]!, "bridge" => root["bridge"]!["rules"]![0]!, _ => root["bridge"]!["subChains"]![0]!["rules"]![0]! };
            mutation(rule.AsObject()); Assert.False(PolicyBundleJsonCodec.DecodeBundle(root.ToJsonString()).IsSuccess);
        }
    }
}
