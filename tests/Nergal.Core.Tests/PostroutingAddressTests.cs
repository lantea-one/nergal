using System.Text.Json.Nodes;
using Nergal.Core.Controller;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Postrouting address restrictions remain complete in immutable intent, native compilation and ownership fingerprints.</summary>
public sealed class PostroutingAddressTests
{
    private static readonly NftTableIdentity Identity = new(Guid.Parse("11111111-1111-4111-8111-111111111111"), Guid.Parse("22222222-2222-4222-8222-222222222222"));
    private static NetworkPrefix[] Sources(IpFamily family) => family == IpFamily.IPv4 ? [new("192.0.2.0/24"), new("198.51.100.0/24")] : [new("2001:db8:1::/64"), new("2001:db8:3::/64")];
    private static NetworkPrefix[] Destinations(IpFamily family) => family == IpFamily.IPv4 ? [new("203.0.113.10/32"), new("203.0.113.20/32")] : [new("2001:db8:2::10/128"), new("2001:db8:2::20/128")];
    private static PolicyObjectReference Reference(string name, IpFamily family, IEnumerable<NetworkPrefix> prefixes) =>
        new(name == "sources" ? Identity.OwnerId : Identity.ResourceId, 1, new(name, family == IpFamily.IPv4 ? ReusableObjectKind.Ipv4 : ReusableObjectKind.Ipv6, "Synthetic", prefixes.Select(p => p.Value)));
    private static FirewallPolicyBundle Bundle(SnatRule rule) => new(1, new(2, FilterVerdict.Accept, FilterVerdict.Accept, FilterVerdict.Accept, []), new(1, [], [rule]));

    /// <summary>Both families, singleton/multiple entries and dormant rules retain pinned identity while compiling exactly like independent literals.</summary>
    [Theory]
    [InlineData(IpFamily.IPv4, true, true)]
    [InlineData(IpFamily.IPv4, false, true)]
    [InlineData(IpFamily.IPv6, true, true)]
    [InlineData(IpFamily.IPv6, false, true)]
    [InlineData(IpFamily.IPv4, false, false)]
    [InlineData(IpFamily.IPv6, false, false)]
    public void References_RoundTripAndProjectToExactLiteralRestrictions(IpFamily family, bool singleton, bool enabled)
    {
        var sources = Sources(family).Take(singleton ? 1 : 2).ToArray();
        var destinations = Destinations(family).Take(singleton ? 1 : 2).ToArray();
        var rule = new SnatRule(family, null, null, Action: NatPostroutingAction.Return, InputInterface: "lan0", OutputInterface: "wan0",
            Protocol: FilterProtocol.Udp, DestinationPort: 19000, NegateSource: true, NegateDestination: true, Enabled: enabled,
            SourceObject: Reference("sources", family, sources), DestinationObject: Reference("destinations", family, destinations));
        var json = PolicyBundleJsonCodec.EncodeBundle(Bundle(rule));
        var decoded = PolicyBundleJsonCodec.DecodeBundle(json); Assert.True(decoded.IsSuccess);
        Assert.Equal(json, PolicyBundleJsonCodec.EncodeBundle(decoded.Value!));
        var literal = rule with
        {
            SourceObject = null,
            DestinationObject = null,
            Source = singleton ? sources[0] : null,
            SourcePrefixes = singleton ? null : sources,
            Destination = singleton ? destinations[0] : null,
            DestinationPrefixes = singleton ? null : destinations
        };
        var compiled = NftPolicyBundleCompiler.Compile(decoded.Value!); Assert.True(compiled.IsSuccess);
        Assert.Equal(NftPolicyBundleCompiler.Compile(Bundle(literal)).Candidate, compiled.Candidate);
        Assert.Equal(new[] { "nat.snatRules[0].sourceObject", "nat.snatRules[0].destinationObject" }, PolicyObjectReferences.Enumerate(decoded.Value!).Select(b => b.Path));
        Assert.Equal(enabled, decoded.Value!.Nat!.SnatRules[0]!.Enabled);
    }

    /// <summary>Malformed sets and conflicting/wrong-family references fail even when dormant, with no partial candidate.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Validation_RejectsInvalidOrConflictingRestrictions(bool enabled)
    {
        var valid = new SnatRule(IpFamily.IPv4, null, "203.0.113.1", SourcePrefixes: Sources(IpFamily.IPv4), Enabled: enabled);
        foreach (var (rule, code) in new (SnatRule, string)[]
        {
            (valid with { SourcePrefixes = [] }, "set.minElements"),
            (valid with { SourcePrefixes = [new("192.0.2.0/24")] }, "set.minElements"),
            (valid with { SourcePrefixes = [null!, new("192.0.2.0/24")] }, "set.nullElement"),
            (valid with { SourcePrefixes = Enumerable.Repeat(new NetworkPrefix("192.0.2.0/24"), 65).ToArray() }, "set.tooManyElements"),
            (valid with { SourcePrefixes = [new("192.0.2.0/24"), new("192.0.2.0/24")] }, "set.duplicate"),
            (valid with { SourcePrefixes = [new("192.0.2.0/24"), new("192.0.3.0/24")] }, "set.overlappingOrAdjacent"),
            (valid with { SourcePrefixes = [new("192.0.2.0/24"), new("192.0.2.10/32")] }, "set.overlappingOrAdjacent"),
            (valid with { DestinationPrefixes = Sources(IpFamily.IPv6) }, "network.familyMismatch"),
            (valid with { Source = new("192.0.2.0/24") }, "set.conflictsWithScalar"),
            (valid with { SourceObject = Reference("sources", IpFamily.IPv4, Sources(IpFamily.IPv4)) }, "object.conflictsWithLiteral"),
            (valid with { SourcePrefixes = null, SourceObject = Reference("sources", IpFamily.IPv6, Sources(IpFamily.IPv6)) }, "object.kindMismatch")
        }) { var result = NftNatCompiler.Compile(new(1, [], [rule])); Assert.False(result.IsSuccess); Assert.Null(result.Candidate); Assert.Contains(result.Diagnostics, d => d.Code == code); }
    }

    /// <summary>Callers cannot mutate either source or destination arrays after policy construction.</summary>
    [Fact]
    public void Snapshot_CopiesBothAddressSets()
    {
        var source = Sources(IpFamily.IPv4); var destination = Destinations(IpFamily.IPv4);
        var policy = new NatPolicy(1, [], [new(IpFamily.IPv4, null, null, Action: NatPostroutingAction.Masquerade, SourcePrefixes: source, DestinationPrefixes: destination)]);
        source[0] = new("10.0.0.0/8"); destination[0] = new("10.0.0.0/8");
        Assert.Equal("192.0.2.0/24", policy.SnatRules[0]!.SourcePrefixes![0].Value);
        Assert.Equal("203.0.113.10/32", policy.SnatRules[0]!.DestinationPrefixes![0].Value);
        Assert.Throws<NotSupportedException>(() => ((IList<NetworkPrefix>)policy.SnatRules[0]!.SourcePrefixes!).Clear());
    }

    /// <summary>Strict fields cannot be forged, ignored in another scope, or normalized from null into a missing restriction.</summary>
    [Fact]
    public void Codec_RejectsMalformedAddressFieldsAndUnknownDnatMaps()
    {
        var rule = new SnatRule(IpFamily.IPv4, null, null, Action: NatPostroutingAction.Masquerade,
            SourceObject: Reference("sources", IpFamily.IPv4, Sources(IpFamily.IPv4)));
        var original = JsonNode.Parse(PolicyBundleJsonCodec.EncodeBundle(Bundle(rule)))!;
        foreach (var field in new[] { "sourcePrefixes", "destinationPrefixes", "sourceObject", "destinationObject" })
        {
            foreach (var invalid in new JsonNode?[] { null, JsonValue.Create("unknown"), new JsonArray(1) })
            {
                var changed = original.DeepClone(); changed["nat"]!["snatRules"]![0]![field] = invalid?.DeepClone();
                Assert.False(PolicyBundleJsonCodec.DecodeBundle(changed.ToJsonString()).IsSuccess);
            }
        }
        foreach (var field in new[] { "digest", "kind", "id", "version", "unknown" })
        {
            var changed = original.DeepClone();
            changed["nat"]!["snatRules"]![0]!["sourceObject"]![field] = JsonValue.Create("forged");
            Assert.False(PolicyBundleJsonCodec.DecodeBundle(changed.ToJsonString()).IsSuccess);
        }
        var dnat = JsonNode.Parse(PolicyBundleJsonCodec.EncodeBundle(new(1, Bundle(rule).Filter, new(1,
            [new(IpFamily.IPv4, FilterProtocol.Tcp, new("198.51.100.1/32"), "192.0.2.1")], []))))!;
        dnat["nat"]!["dnatRules"]![0]!["sourceMap"] = original["nat"]!["snatRules"]![0]!["sourceObject"]!.DeepClone();
        Assert.False(PolicyBundleJsonCodec.DecodeBundle(dnat.ToJsonString()).IsSuccess);
    }

    /// <summary>Every observed set is retained and fingerprinted; adding a restriction to an otherwise unrestricted masquerade must change its receipt.</summary>
    [Theory]
    [InlineData(IpFamily.IPv4, false)]
    [InlineData(IpFamily.IPv4, true)]
    [InlineData(IpFamily.IPv6, false)]
    [InlineData(IpFamily.IPv6, true)]
    public void Observation_RetainsCompleteSetsAndDetectsSemanticDrift(IpFamily family, bool negate)
    {
        var list = Listing(family, negate);
        var parsed = NftNatTableObservation.Parse(list.ToJsonString()); Assert.True(parsed.IsSuccess, parsed.ErrorCode);
        var rule = Assert.Single(parsed.Observation!.Policy.SnatRules)!;
        Assert.Equal(Sources(family).Select(p => p.Value), rule.SourcePrefixes!.Select(p => p.Value));
        Assert.Equal(Destinations(family).Select(p => p.Value), rule.DestinationPrefixes!.Select(p => p.Value));
        Assert.Equal(negate, rule.NegateSource); Assert.Equal(negate, rule.NegateDestination);
        var expected = new SnatRule(family, null, null, Action: NatPostroutingAction.Masquerade, SourcePrefixes: Sources(family), DestinationPrefixes: Destinations(family), NegateSource: negate, NegateDestination: negate);
        Assert.Equal(NftNatCompiler.Compile(new(1, [], [expected]), Identity).Candidate, NftNatCompiler.Compile(parsed.Observation.Policy, Identity).Candidate);
        var echo = new JsonObject { ["nftables"] = new JsonArray(list["nftables"]!.AsArray().Skip(1).Select(n => (JsonNode)new JsonObject { [n!.AsObject().ContainsKey("table") ? "create" : "add"] = n.DeepClone() }).ToArray()) };
        Assert.Equal(parsed.Observation.StateDigest, NftNatTableObservation.ParseReplacementEcho(echo.ToJsonString()).Observation!.StateDigest);
        var drift = list.DeepClone(); drift["nftables"]![4]!["rule"]!["expr"]!.AsArray().RemoveAt(1);
        var changed = NftNatTableObservation.Parse(drift.ToJsonString()); Assert.True(changed.IsSuccess, changed.ErrorCode);
        Assert.NotEqual(parsed.Observation.StateDigest, changed.Observation!.StateDigest);
        drift["nftables"]![4]!["rule"]!["expr"]!.AsArray().RemoveAt(0);
        drift["nftables"]![4]!["rule"]!["expr"]!.AsArray().Insert(0, new JsonObject { ["match"] = new JsonObject { ["op"] = "==", ["left"] = new JsonObject { ["meta"] = new JsonObject { ["key"] = "nfproto" } }, ["right"] = family == IpFamily.IPv4 ? "ipv4" : "ipv6" } });
        var unrestricted = NftNatTableObservation.Parse(drift.ToJsonString()); Assert.True(unrestricted.IsSuccess, unrestricted.ErrorCode);
        Assert.NotEqual(changed.Observation.StateDigest, unrestricted.Observation!.StateDigest);
    }

    private static JsonObject Listing(IpFamily family, bool negate)
    {
        var proto = family == IpFamily.IPv4 ? "ip" : "ip6";
        JsonNode Prefix(NetworkPrefix p) { var parts = p.Value.Split('/'); if (parts[1] == (p.Family == IpFamily.IPv4 ? "32" : "128")) { return JsonValue.Create(parts[0])!; } return new JsonObject { ["prefix"] = new JsonObject { ["addr"] = parts[0], ["len"] = int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture) } }; }
        JsonNode Match(string field, NetworkPrefix[] prefixes) => new JsonObject { ["match"] = new JsonObject { ["op"] = negate ? "!=" : "==", ["left"] = new JsonObject { ["payload"] = new JsonObject { ["protocol"] = proto, ["field"] = field } }, ["right"] = new JsonObject { ["set"] = new JsonArray(prefixes.Select(Prefix).ToArray()) } } };
        return new JsonObject
        {
            ["nftables"] = new JsonArray(
            new JsonObject { ["metainfo"] = new JsonObject { ["version"] = "1.1.7", ["release_name"] = "fixture", ["json_schema_version"] = 1 } },
            new JsonObject { ["table"] = new JsonObject { ["family"] = "inet", ["name"] = "nergal_nat", ["handle"] = 1, ["comment"] = Identity.Comment } },
            new JsonObject { ["chain"] = new JsonObject { ["family"] = "inet", ["table"] = "nergal_nat", ["name"] = "prerouting", ["handle"] = 1, ["type"] = "nat", ["hook"] = "prerouting", ["prio"] = -100, ["policy"] = "accept" } },
            new JsonObject { ["chain"] = new JsonObject { ["family"] = "inet", ["table"] = "nergal_nat", ["name"] = "postrouting", ["handle"] = 2, ["type"] = "nat", ["hook"] = "postrouting", ["prio"] = 100, ["policy"] = "accept" } },
            new JsonObject
            {
                ["rule"] = new JsonObject
                {
                    ["family"] = "inet",
                    ["table"] = "nergal_nat",
                    ["chain"] = "postrouting",
                    ["handle"] = 3,
                    ["expr"] = new JsonArray(
                Match("saddr", Sources(family)), Match("daddr", Destinations(family)), new JsonObject { ["masquerade"] = null })
                }
            })
        };
    }
}
