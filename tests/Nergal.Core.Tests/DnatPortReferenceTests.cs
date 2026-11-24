using System.Text.Json.Nodes;
using Nergal.Core.Controller;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Original destination-port lists preserve one DNAT target, immutable intent and complete native evidence.</summary>
public sealed class DnatPortReferenceTests
{
    private static readonly NftTableIdentity Identity = new(Guid.Parse("11111111-1111-4111-8111-111111111111"), Guid.Parse("22222222-2222-4222-8222-222222222222"));
    private static DnatRule Rule(IpFamily family = IpFamily.IPv4) => new(family, FilterProtocol.Tcp,
        new(family == IpFamily.IPv4 ? "198.51.100.10/32" : "2001:db8:2::10/128"), family == IpFamily.IPv4 ? "192.0.2.2" : "2001:db8:1::2", TranslatedPort: 8080);
    private static FirewallPolicyBundle Bundle(DnatRule rule) => new(1, new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, []), new(1, [rule], []));
    private static PolicyObjectReference Reference(bool singleton = false) => new(Identity.OwnerId, 1, new("web_ports", ReusableObjectKind.Port, "Synthetic", singleton ? ["443"] : ["443", "8443"]));

    /// <summary>Both families, singleton/set lists and dormant rules round-trip intent and match independent literal candidates.</summary>
    [Theory]
    [InlineData(IpFamily.IPv4, true, true)]
    [InlineData(IpFamily.IPv4, false, true)]
    [InlineData(IpFamily.IPv6, true, true)]
    [InlineData(IpFamily.IPv6, false, true)]
    [InlineData(IpFamily.IPv4, false, false)]
    [InlineData(IpFamily.IPv6, false, false)]
    public void Reference_RetainsIntentAndCompilesExactLiteral(IpFamily family, bool singleton, bool enabled)
    {
        var rule = Rule(family) with { OriginalPortObject = Reference(singleton), Enabled = enabled, NegateDestination = true };
        var json = PolicyBundleJsonCodec.EncodeBundle(Bundle(rule));
        var decoded = PolicyBundleJsonCodec.DecodeBundle(json); Assert.True(decoded.IsSuccess);
        Assert.Equal(json, PolicyBundleJsonCodec.EncodeBundle(decoded.Value!));
        var literal = rule with { OriginalPortObject = null, OriginalPort = singleton ? 443 : null, OriginalPorts = singleton ? null : [443, 8443] };
        var compiled = NftNatCompiler.Compile(decoded.Value!.Nat!); Assert.True(compiled.IsSuccess);
        Assert.Equal(NftNatCompiler.Compile(Bundle(literal).Nat!).Candidate, compiled.Candidate);
        Assert.Equal("nat.dnatRules[0].originalPortObject", Assert.Single(PolicyObjectReferences.Enumerate(decoded.Value)).Path);
        Assert.Equal(rule.TranslatedPort, decoded.Value.Nat!.DnatRules[0]!.TranslatedPort);
    }

    /// <summary>Malformed lists, protocol/type/literal conflicts and invalid dormant entries never emit partial candidates.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Validation_RejectsUnsafeOriginalPortMatchers(bool enabled)
    {
        var valid = Rule() with { Enabled = enabled, OriginalPorts = [443, 8443] };
        foreach (var rule in new[] { valid with { OriginalPort = 443 }, valid with { OriginalPorts = [] }, valid with { OriginalPorts = [443] },
            valid with { OriginalPorts = [443, 443] }, valid with { OriginalPorts = [0, 443] }, valid with { Protocol = FilterProtocol.Any },
            valid with { OriginalPortObject = Reference() }, valid with { OriginalPorts = null, OriginalPortObject = new(Identity.OwnerId, 1, new("addresses", ReusableObjectKind.Ipv4, "", ["192.0.2.1"])) } })
        { var result = NftNatCompiler.Compile(Bundle(rule).Nat!); Assert.False(result.IsSuccess); Assert.Null(result.Candidate); }
        foreach (var (field, value) in new[] { ("originalPorts", "null"), ("originalPorts", "[null]"), ("originalPorts", "[\"443\"]"), ("originalPortObject", "{}"), ("originalPortObject", "null") })
        {
            var json = JsonNode.Parse(PolicyBundleJsonCodec.EncodeBundle(Bundle(Rule())))!;
            json["nat"]!["dnatRules"]![0]![field] = JsonNode.Parse(value);
            Assert.False(PolicyBundleJsonCodec.DecodeBundle(json.ToJsonString()).IsSuccess);
        }
    }

    /// <summary>Caller edits cannot mutate saved policy port-set contents.</summary>
    [Fact]
    public void Policy_DefensivelySnapshotsOriginalPortSets()
    {
        int[] ports = [443, 8443]; var policy = new NatPolicy(1, [Rule() with { OriginalPorts = ports }], []);
        ports[0] = 22; Assert.Equal(new[] { 443, 8443 }, policy.DnatRules[0]!.OriginalPorts);
        Assert.Throws<NotSupportedException>(() => ((IList<int>)policy.DnatRules[0]!.OriginalPorts!).Clear());
    }

    /// <summary>Complete listing/echo fingerprints include every original port; same-handle edits change evidence.</summary>
    [Theory]
    [InlineData(IpFamily.IPv4)]
    [InlineData(IpFamily.IPv6)]
    public void NativeObservation_RetainsSetsAndDetectsDrift(IpFamily family)
    {
        var proto = family == IpFamily.IPv4 ? "ip" : "ip6";
        var rule = Rule(family) with { OriginalPorts = [443, 8443] };
        var json = JsonNode.Parse("""
            {"nftables":[{"metainfo":{"version":"1.1.7","release_name":"fixture","json_schema_version":1}},
            {"table":{"family":"inet","name":"nergal_nat","handle":1,"comment":"$comment"}},
            {"chain":{"family":"inet","table":"nergal_nat","name":"prerouting","handle":1,"type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}},
            {"chain":{"family":"inet","table":"nergal_nat","name":"postrouting","handle":2,"type":"nat","hook":"postrouting","prio":100,"policy":"accept"}},
            {"rule":{"family":"inet","table":"nergal_nat","chain":"prerouting","handle":4,"expr":[
            {"match":{"op":"==","left":{"payload":{"protocol":"$proto","field":"daddr"}},"right":"$destination"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[443,8443]}}},
            {"dnat":{"family":"$proto","addr":"$target","port":8080}}]}}]}
            """.Replace("$comment", Identity.Comment, StringComparison.Ordinal).Replace("$proto", proto, StringComparison.Ordinal)
            .Replace("$destination", rule.OriginalDestination.Value.Split('/')[0], StringComparison.Ordinal).Replace("$target", rule.TranslatedAddress, StringComparison.Ordinal))!;
        var observed = NftNatTableObservation.Parse(json.ToJsonString()); Assert.True(observed.IsSuccess, observed.ErrorCode);
        Assert.Equal(NftNatCompiler.Compile(Bundle(rule).Nat!, Identity).Candidate, NftNatCompiler.Compile(observed.Observation!.Policy, Identity).Candidate);
        var echo = new JsonObject { ["nftables"] = new JsonArray(json["nftables"]!.AsArray().Skip(1).Select(n => (JsonNode)new JsonObject { [n!.AsObject().ContainsKey("table") ? "create" : "add"] = n.DeepClone() }).ToArray()) };
        Assert.Equal(observed.Observation.StateDigest, NftNatTableObservation.ParseReplacementEcho(echo.ToJsonString()).Observation!.StateDigest);
        json["nftables"]![4]!["rule"]!["expr"]![1]!["match"]!["right"]!["set"]![1] = 9443;
        var changed = NftNatTableObservation.Parse(json.ToJsonString()); Assert.True(changed.IsSuccess, changed.ErrorCode);
        Assert.NotEqual(observed.Observation.StateDigest, changed.Observation!.StateDigest);
    }
}
