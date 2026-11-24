using System.Text.Json.Nodes;
using Nergal.Core.Controller;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Bridge address sets remain conjunctive with MAC matching and local control flow, including dormant rules and complete receipts.</summary>
public sealed class BridgeAddressTests
{
    private static readonly NftTableIdentity Identity = new(Guid.Parse("11111111-1111-4111-8111-111111111111"), Guid.Parse("22222222-2222-4222-8222-222222222222"));
    private static NetworkPrefix[] Sources(IpFamily family) => family == IpFamily.IPv4 ? [new("192.0.2.2/32"), new("192.0.2.90/32")] : [new("2001:db8:1::2/128"), new("2001:db8:1::90/128")];
    private static NetworkPrefix[] Destinations(IpFamily family) => family == IpFamily.IPv4 ? [new("192.0.2.3/32"), new("192.0.2.99/32")] : [new("2001:db8:1::3/128"), new("2001:db8:1::99/128")];
    private static PolicyObjectReference Reference(string name, IpFamily family, IEnumerable<NetworkPrefix> entries) => new(name == "sources" ? Identity.OwnerId : Identity.ResourceId,
        1, new(name, family == IpFamily.IPv4 ? ReusableObjectKind.Ipv4 : ReusableObjectKind.Ipv6, "Synthetic", entries.Select(p => p.Value)));
    private static BridgePolicy Policy(BridgeFilterRule rule) => new(1, FilterVerdict.Drop,
        [rule with { JumpTarget = "service", Return = false }], -5, [new("service", [rule with { JumpTarget = null, Return = true }])]);
    private static FirewallPolicyBundle Bundle(BridgePolicy bridge) => new(1, new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, []), bridge: bridge);

    /// <summary>Singleton/multiple snapshots in both chains/families preserve identity, MAC pinning and dormant intent while matching independent literals.</summary>
    [Theory]
    [InlineData(IpFamily.IPv4, true, true)]
    [InlineData(IpFamily.IPv4, false, true)]
    [InlineData(IpFamily.IPv6, true, true)]
    [InlineData(IpFamily.IPv6, false, true)]
    [InlineData(IpFamily.IPv4, false, false)]
    [InlineData(IpFamily.IPv6, false, false)]
    public void References_PreserveCompleteRulesAndExactLiteralCandidates(IpFamily family, bool singleton, bool enabled)
    {
        var source = Sources(family).Take(singleton ? 1 : 2).ToArray(); var destination = Destinations(family).Take(singleton ? 1 : 2).ToArray();
        var rule = new BridgeFilterRule(BridgeEtherType.Any, FilterVerdict.Drop, BridgeName: "br0", SourceMac: new("02:00:00:00:00:01"),
            DestinationMac: new("02:00:00:00:00:02"), Family: family, Protocol: FilterProtocol.Tcp, DestinationPort: 443, Enabled: enabled,
            SourceObject: Reference("sources", family, source), DestinationObject: Reference("destinations", family, destination));
        var json = PolicyBundleJsonCodec.EncodeBundle(Bundle(Policy(rule)));
        var decoded = PolicyBundleJsonCodec.DecodeBundle(json); Assert.True(decoded.IsSuccess);
        Assert.Equal(json, PolicyBundleJsonCodec.EncodeBundle(decoded.Value!));
        var literal = rule with
        {
            SourceObject = null,
            DestinationObject = null,
            Source = singleton ? source[0] : null,
            SourcePrefixes = singleton ? null : source,
            Destination = singleton ? destination[0] : null,
            DestinationPrefixes = singleton ? null : destination
        };
        var compiled = NftBridgeCompiler.Compile(decoded.Value!.Bridge!, Identity); Assert.True(compiled.IsSuccess);
        Assert.Equal(NftBridgeCompiler.Compile(Policy(literal), Identity).Candidate, compiled.Candidate);
        Assert.Equal(new[] { "bridge.rules[0].sourceObject", "bridge.rules[0].destinationObject", "bridge.subChains[0].rules[0].sourceObject", "bridge.subChains[0].rules[0].destinationObject" },
            PolicyObjectReferences.Enumerate(decoded.Value).Select(b => b.Path));
        Assert.Equal(enabled, decoded.Value.Bridge!.SubChains[0].Rules[0]!.Enabled);
        Assert.Equal("02:00:00:00:00:01", decoded.Value.Bridge.Rules[0]!.SourceMac!.Value);
    }

    /// <summary>Unsupported type/family, absent family and invalid/conflicting sets fail even when dormant; no candidate is emitted.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Validation_RejectsIncompleteOrConflictingAddressRestrictions(bool enabled)
    {
        var valid = new BridgeFilterRule(BridgeEtherType.Any, FilterVerdict.Drop, Family: IpFamily.IPv4, SourcePrefixes: Sources(IpFamily.IPv4), Enabled: enabled);
        foreach (var (rule, code) in new (BridgeFilterRule, string)[]
        {
            (valid with { Family = null }, "bridge.familyRequired"),
            (valid with { EtherType = BridgeEtherType.Arp }, "bridge.familyMismatch"),
            (valid with { Source = Sources(IpFamily.IPv4)[0] }, "set.conflictsWithScalar"),
            (valid with { SourcePrefixes = [] }, "set.minElements"),
            (valid with { SourcePrefixes = [null!, Sources(IpFamily.IPv4)[0]] }, "set.nullElement"),
            (valid with { SourcePrefixes = [new("192.0.2.2/32"), new("192.0.2.3/32")] }, "set.overlappingOrAdjacent"),
            (valid with { DestinationPrefixes = Sources(IpFamily.IPv6) }, "network.familyMismatch"),
            (valid with { SourceObject = Reference("sources", IpFamily.IPv4, Sources(IpFamily.IPv4)) }, "object.conflictsWithLiteral"),
            (valid with { SourcePrefixes = null, SourceObject = Reference("sources", IpFamily.IPv6, Sources(IpFamily.IPv6)) }, "object.kindMismatch"),
            (valid with { Family = null, SourcePrefixes = null, SourceObject = Reference("sources", IpFamily.IPv4, Sources(IpFamily.IPv4)) }, "object.requiresFamily")
        }) { var result = NftBridgeCompiler.Compile(Policy(rule)); Assert.False(result.IsSuccess); Assert.Null(result.Candidate); Assert.Contains(result.Diagnostics, d => d.Code == code); }
        Assert.False(NftBridgeCompiler.Compile(new(1, FilterVerdict.Drop, [valid with { Family = null }])).IsSuccess);
    }

    /// <summary>Both base and regular chains defensively snapshot caller arrays.</summary>
    [Fact]
    public void Policy_CopiesSourceAndDestinationSetsInEveryChain()
    {
        var source = Sources(IpFamily.IPv4); var destination = Destinations(IpFamily.IPv4);
        var policy = Policy(new(BridgeEtherType.IPv4, FilterVerdict.Drop, Family: IpFamily.IPv4, SourcePrefixes: source, DestinationPrefixes: destination));
        source[0] = new("10.0.0.0/8"); destination[0] = new("10.0.0.0/8");
        foreach (var rule in new[] { policy.Rules[0]!, policy.SubChains[0].Rules[0]! })
        {
            Assert.Equal("192.0.2.2/32", rule.SourcePrefixes![0].Value); Assert.Equal("192.0.2.3/32", rule.DestinationPrefixes![0].Value);
            Assert.Throws<NotSupportedException>(() => ((IList<NetworkPrefix>)rule.DestinationPrefixes).Clear());
        }
    }

    /// <summary>Actual native shapes retain every set in both chains, and a same-handle set change changes the complete receipt.</summary>
    [Theory]
    [InlineData(IpFamily.IPv4)]
    [InlineData(IpFamily.IPv6)]
    public void Observation_RoundTripsBothChainsAndDetectsSetDrift(IpFamily family)
    {
        var listing = Listing(family);
        var observed = NftBridgeTableObservation.Parse(listing.ToJsonString()); Assert.True(observed.IsSuccess, observed.ErrorCode);
        var rule = new BridgeFilterRule(BridgeEtherType.Any, FilterVerdict.Drop, Family: family, SourceMac: new("02:00:00:00:00:01"), DestinationMac: new("02:00:00:00:00:02"), SourcePrefixes: Sources(family), DestinationPrefixes: Destinations(family));
        Assert.Equal(NftBridgeCompiler.Compile(Policy(rule), Identity).Candidate, NftBridgeCompiler.Compile(observed.Observation!.Policy, Identity).Candidate);
        Assert.Equal(2, observed.Observation.Policy.Rules[0]!.SourcePrefixes!.Count);
        Assert.Equal(2, observed.Observation.Policy.SubChains[0].Rules[0]!.DestinationPrefixes!.Count);
        var echo = new JsonObject { ["nftables"] = new JsonArray(listing["nftables"]!.AsArray().Skip(1).Select(n => (JsonNode)new JsonObject { [n!.AsObject().ContainsKey("table") ? "create" : "add"] = n.DeepClone() }).ToArray()) };
        var echoed = NftBridgeTableObservation.ParseReplacementEcho(echo.ToJsonString()); Assert.True(echoed.IsSuccess, echoed.ErrorCode);
        Assert.Equal(observed.Observation.StateDigest, echoed.Observation!.StateDigest);
        var drift = listing.DeepClone();
        drift["nftables"]![5]!["rule"]!["expr"]![4]!["match"]!["right"]!["set"]![1] = family == IpFamily.IPv4 ? "192.0.2.98" : "2001:db8:1::98";
        var changed = NftBridgeTableObservation.Parse(drift.ToJsonString()); Assert.True(changed.IsSuccess, changed.ErrorCode);
        Assert.NotEqual(observed.Observation.StateDigest, changed.Observation!.StateDigest);
        var duplicate = listing.DeepClone();
        duplicate["nftables"]![5]!["rule"]!["expr"]![0]!["match"]!["left"]!["payload"]!["field"] = "saddr";
        Assert.False(NftBridgeTableObservation.Parse(duplicate.ToJsonString()).IsSuccess);
    }

    /// <summary>Neither bridge scope may silently ignore malformed address sets or unrecognized snapshot fields.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Codec_RejectsMalformedAddressFieldsInBothChains(bool regularChain)
    {
        var valid = Bundle(Policy(new(BridgeEtherType.Any, FilterVerdict.Drop, Family: IpFamily.IPv4)));
        foreach (var (field, value) in new (string, string)[]
        {
            ("sourcePrefixes", "null"), ("destinationPrefixes", "{}"), ("sourcePrefixes", "[null]"),
            ("destinationPrefixes", "[123]"), ("sourceObject", "{}"), ("destinationObject", "null")
        })
        {
            var json = JsonNode.Parse(PolicyBundleJsonCodec.EncodeBundle(valid))!;
            var rule = regularChain ? json["bridge"]!["subChains"]![0]!["rules"]![0]! : json["bridge"]!["rules"]![0]!;
            rule[field] = JsonNode.Parse(value);
            Assert.False(PolicyBundleJsonCodec.DecodeBundle(json.ToJsonString()).IsSuccess);
        }
    }

    private static JsonObject Listing(IpFamily family)
    {
        var proto = family == IpFamily.IPv4 ? "ip" : "ip6";
        JsonNode Match(string protocol, string field, JsonNode right) => new JsonObject { ["match"] = new JsonObject { ["op"] = "==", ["left"] = new JsonObject { ["payload"] = new JsonObject { ["protocol"] = protocol, ["field"] = field } }, ["right"] = right } };
        JsonNode Rule(string chain, int handle, bool returns) => new JsonObject
        {
            ["rule"] = new JsonObject
            {
                ["family"] = "bridge",
                ["table"] = "nergal_bridge",
                ["chain"] = chain,
                ["handle"] = handle,
                ["expr"] = new JsonArray(
            Match("ether", "daddr", JsonValue.Create("02:00:00:00:00:02")!),
                Match("ether", "saddr", JsonValue.Create("02:00:00:00:00:01")!), Match("ether", "type", JsonValue.Create(proto)!),
            Match(proto, "saddr", new JsonObject { ["set"] = new JsonArray(Sources(family).Select(p => (JsonNode)JsonValue.Create(p.Value.Split('/')[0])!).ToArray()) }),
            Match(proto, "daddr", new JsonObject { ["set"] = new JsonArray(Destinations(family).Select(p => (JsonNode)JsonValue.Create(p.Value.Split('/')[0])!).ToArray()) }),
            returns ? new JsonObject { ["return"] = null } : new JsonObject { ["jump"] = new JsonObject { ["target"] = "service" } })
            }
        };
        return new JsonObject
        {
            ["nftables"] = new JsonArray(
            new JsonObject { ["metainfo"] = new JsonObject { ["version"] = "1.1.7", ["release_name"] = "fixture", ["json_schema_version"] = 1 } },
            new JsonObject { ["table"] = new JsonObject { ["family"] = "bridge", ["name"] = "nergal_bridge", ["handle"] = 1, ["comment"] = Identity.Comment } },
            new JsonObject { ["chain"] = new JsonObject { ["family"] = "bridge", ["table"] = "nergal_bridge", ["name"] = "forward", ["handle"] = 1, ["type"] = "filter", ["hook"] = "forward", ["prio"] = -5, ["policy"] = "drop" } },
            new JsonObject { ["chain"] = new JsonObject { ["family"] = "bridge", ["table"] = "nergal_bridge", ["name"] = "service", ["handle"] = 2 } }, Rule("forward", 3, false), Rule("service", 4, true))
        };
    }
}
