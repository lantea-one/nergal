using System.Text.Json.Nodes;
using Nergal.Core.Controller;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>DNAT address restrictions remain complete, immutable and conjunctive with ports and one explicit translation.</summary>
public sealed class DnatAddressTests
{
    private static readonly NftTableIdentity Identity = new(Guid.Parse("11111111-1111-4111-8111-111111111111"), Guid.Parse("22222222-2222-4222-8222-222222222222"));
    private static NetworkPrefix[] Sources(IpFamily family) => family == IpFamily.IPv4 ? [new("192.0.2.2/32"), new("192.0.2.90/32")] : [new("2001:db8:1::2/128"), new("2001:db8:1::90/128")];
    private static NetworkPrefix[] Destinations(IpFamily family) => family == IpFamily.IPv4 ? [new("198.51.100.10/32"), new("198.51.100.90/32")] : [new("2001:db8:2::10/128"), new("2001:db8:2::90/128")];
    private static FirewallPolicyBundle Bundle(DnatRule rule) => new(1, new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, []), new(1, [rule], []));
    private static DnatRule Rule(IpFamily family) => new(family, FilterProtocol.Tcp, null, family == IpFamily.IPv4 ? "203.0.113.2" : "2001:db8:3::2", TranslatedPort: 8080, OriginalPorts: [443, 8443]);
    private static PolicyObjectReference Reference(string name, IpFamily family, IEnumerable<NetworkPrefix> prefixes) => new(name == "sources" ? Identity.OwnerId : Identity.ResourceId, 1,
        new(name, family == IpFamily.IPv4 ? ReusableObjectKind.Ipv4 : ReusableObjectKind.Ipv6, "Synthetic", prefixes.Select(p => p.Value)));

    /// <summary>Both families, single/multiple entries and disabled rules retain exact references and compile like independently authored literals.</summary>
    [Theory]
    [InlineData(IpFamily.IPv4, true, true)]
    [InlineData(IpFamily.IPv4, false, true)]
    [InlineData(IpFamily.IPv6, true, true)]
    [InlineData(IpFamily.IPv6, false, true)]
    [InlineData(IpFamily.IPv4, false, false)]
    [InlineData(IpFamily.IPv6, false, false)]
    public void References_RoundTripCompleteImmutableIntent(IpFamily family, bool singleton, bool enabled)
    {
        var sources = Sources(family).Take(singleton ? 1 : 2).ToArray(); var destinations = Destinations(family).Take(singleton ? 1 : 2).ToArray();
        var rule = Rule(family) with
        {
            Enabled = enabled,
            NegateSource = true,
            NegateDestination = true,
            SourceObject = Reference("sources", family, sources),
            DestinationObject = Reference("destinations", family, destinations)
        };
        var json = PolicyBundleJsonCodec.EncodeBundle(Bundle(rule)); var decoded = PolicyBundleJsonCodec.DecodeBundle(json); Assert.True(decoded.IsSuccess);
        Assert.Equal(json, PolicyBundleJsonCodec.EncodeBundle(decoded.Value!));
        var literal = rule with
        {
            SourceObject = null,
            DestinationObject = null,
            Source = singleton ? sources[0] : null,
            OriginalDestination = singleton ? destinations[0] : null,
            SourcePrefixes = singleton ? null : sources,
            DestinationPrefixes = singleton ? null : destinations
        };
        var result = NftNatCompiler.Compile(decoded.Value!.Nat!); Assert.True(result.IsSuccess);
        Assert.Equal(NftNatCompiler.Compile(Bundle(literal).Nat!).Candidate, result.Candidate);
        Assert.Equal(new[] { "nat.dnatRules[0].sourceObject", "nat.dnatRules[0].destinationObject" }, PolicyObjectReferences.Enumerate(decoded.Value).Select(b => b.Path));
        Assert.Equal(enabled, decoded.Value.Nat!.DnatRules[0]!.Enabled);
    }

    /// <summary>Missing original destination, conflicting/family-invalid/overlapping sets and malformed snapshots fail even when dormant.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Validation_RejectsIncompleteAndConflictingMatchers(bool enabled)
    {
        var valid = Rule(IpFamily.IPv4) with { Enabled = enabled, SourcePrefixes = Sources(IpFamily.IPv4), DestinationPrefixes = Destinations(IpFamily.IPv4) };
        foreach (var rule in new[] { valid with { DestinationPrefixes = null }, valid with { DestinationPrefixes = [] }, valid with { SourcePrefixes = [] },
            valid with { Source = new("192.0.2.2/32") }, valid with { OriginalDestination = new("198.51.100.10/32") },
            valid with { SourcePrefixes = [new("192.0.2.0/24"), new("192.0.2.2/32")] }, valid with { DestinationPrefixes = [new("198.51.100.10/32"), new("198.51.100.11/32")] },
            valid with { SourcePrefixes = Sources(IpFamily.IPv6) }, valid with { DestinationPrefixes = Destinations(IpFamily.IPv6) },
            valid with { SourceObject = Reference("sources", IpFamily.IPv4, Sources(IpFamily.IPv4)) },
            valid with { DestinationPrefixes = null, DestinationObject = Reference("destinations", IpFamily.IPv6, Destinations(IpFamily.IPv6)) } })
        { var result = NftNatCompiler.Compile(Bundle(rule).Nat!); Assert.False(result.IsSuccess); Assert.Null(result.Candidate); }
        foreach (var field in new[] { "sourcePrefixes", "destinationPrefixes", "sourceObject", "destinationObject" })
        {
            var json = JsonNode.Parse(PolicyBundleJsonCodec.EncodeBundle(Bundle(valid)))!; json["nat"]!["dnatRules"]![0]![field] = null;
            Assert.False(PolicyBundleJsonCodec.DecodeBundle(json.ToJsonString()).IsSuccess);
        }
    }

    /// <summary>Caller mutation cannot change either address set in a policy snapshot.</summary>
    [Fact]
    public void Policy_SnapshotsBothAddressCollections()
    {
        var sources = Sources(IpFamily.IPv4); var destinations = Destinations(IpFamily.IPv4);
        var policy = Bundle(Rule(IpFamily.IPv4) with { SourcePrefixes = sources, DestinationPrefixes = destinations }).Nat!;
        sources[0] = new("10.0.0.0/8"); destinations[0] = new("10.0.0.0/8");
        Assert.Equal("192.0.2.2/32", policy.DnatRules[0]!.SourcePrefixes![0].Value); Assert.Equal("198.51.100.10/32", policy.DnatRules[0]!.DestinationPrefixes![0].Value);
        Assert.Throws<NotSupportedException>(() => ((IList<NetworkPrefix>)policy.DnatRules[0]!.DestinationPrefixes!).Clear());
    }

    /// <summary>Both address sets and their negation survive native echo/list parsing; same-handle drift changes complete evidence.</summary>
    [Theory]
    [InlineData(IpFamily.IPv4, false)]
    [InlineData(IpFamily.IPv4, true)]
    [InlineData(IpFamily.IPv6, false)]
    [InlineData(IpFamily.IPv6, true)]
    public void NativeObservation_RetainsSetsAndNegation(IpFamily family, bool negate)
    {
        var rule = Rule(family) with { SourcePrefixes = Sources(family), DestinationPrefixes = Destinations(family), NegateSource = negate, NegateDestination = negate };
        var proto = family == IpFamily.IPv4 ? "ip" : "ip6";
        JsonNode Match(string protocol, string field, JsonNode right, string op = "==") => new JsonObject { ["match"] = new JsonObject { ["op"] = op, ["left"] = new JsonObject { ["payload"] = new JsonObject { ["protocol"] = protocol, ["field"] = field } }, ["right"] = right } };
        JsonNode Addresses(IEnumerable<NetworkPrefix> prefixes) => new JsonObject { ["set"] = new JsonArray(prefixes.Select(p => (JsonNode)JsonValue.Create(p.Value.Split('/')[0])!).ToArray()) };
        var json = JsonNode.Parse("""
            {"nftables":[{"metainfo":{"version":"1.1.7","release_name":"fixture","json_schema_version":1}},
            {"table":{"family":"inet","name":"nergal_nat","handle":1,"comment":"$comment"}},
            {"chain":{"family":"inet","table":"nergal_nat","name":"prerouting","handle":1,"type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}},
            {"chain":{"family":"inet","table":"nergal_nat","name":"postrouting","handle":2,"type":"nat","hook":"postrouting","prio":100,"policy":"accept"}},
            {"rule":{"family":"inet","table":"nergal_nat","chain":"prerouting","handle":4,"expr":[]}}]}
            """.Replace("$comment", Identity.Comment, StringComparison.Ordinal))!;
        var expressions = json["nftables"]![4]!["rule"]!["expr"]!.AsArray();
        expressions.Add(Match(proto, "saddr", Addresses(Sources(family)), negate ? "!=" : "=="));
        expressions.Add(Match(proto, "daddr", Addresses(Destinations(family)), negate ? "!=" : "=="));
        expressions.Add(Match("tcp", "dport", new JsonObject { ["set"] = new JsonArray(443, 8443) }));
        expressions.Add(new JsonObject { ["dnat"] = new JsonObject { ["family"] = proto, ["addr"] = rule.TranslatedAddress, ["port"] = rule.TranslatedPort } });
        var observed = NftNatTableObservation.Parse(json.ToJsonString()); Assert.True(observed.IsSuccess, observed.ErrorCode);
        Assert.Equal(NftNatCompiler.Compile(Bundle(rule).Nat!, Identity).Candidate, NftNatCompiler.Compile(observed.Observation!.Policy, Identity).Candidate);
        var echo = new JsonObject { ["nftables"] = new JsonArray(json["nftables"]!.AsArray().Skip(1).Select(n => (JsonNode)new JsonObject { [n!.AsObject().ContainsKey("table") ? "create" : "add"] = n.DeepClone() }).ToArray()) };
        Assert.Equal(observed.Observation.StateDigest, NftNatTableObservation.ParseReplacementEcho(echo.ToJsonString()).Observation!.StateDigest);
        expressions[1]!["match"]!["right"]!["set"]![1] = family == IpFamily.IPv4 ? "198.51.100.98" : "2001:db8:2::98";
        var changed = NftNatTableObservation.Parse(json.ToJsonString()); Assert.True(changed.IsSuccess, changed.ErrorCode); Assert.NotEqual(observed.Observation.StateDigest, changed.Observation!.StateDigest);
    }
}
