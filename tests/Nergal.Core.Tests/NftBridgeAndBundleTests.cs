using System.Globalization;
using System.Text.Json.Nodes;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Verifies bridge filtering, multi-table atomic compilation, diagnostics, and native bridge observations.</summary>
public sealed class NftBridgeAndBundleTests
{
    private static readonly Guid Owner = Guid.Parse("00000000-0000-0000-0000-000000000001");
    private static readonly Guid Resource = Guid.Parse("00000000-0000-0000-0000-000000000007");

    /// <summary>Single-table bundles do not require AtomicMultiTableCommit; multi-table bundles require it along with component features.</summary>
    [Fact]
    public void Bundle_RequiredFeatures_ReflectComponentTables()
    {
        var filter = new FilterPolicy(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Drop, []);
        var single = new FirewallPolicyBundle(FirewallPolicyBundle.CurrentSchemaVersion, filter);
        Assert.DoesNotContain(FirewallFeature.AtomicMultiTableCommit, single.GetRequiredFeatures());
        Assert.DoesNotContain(FirewallFeature.BridgeFiltering, single.GetRequiredFeatures());

        var bridgeRules = new List<BridgeFilterRule?>
        {
            new(BridgeEtherType.Arp, FilterVerdict.Accept, "br_a", "br_b"),
        };
        var bridge = new BridgePolicy(BridgePolicy.CurrentSchemaVersion, FilterVerdict.Drop, bridgeRules);
        bridgeRules.Clear();
        Assert.Single(bridge.Rules);
        Assert.Contains(FirewallFeature.BridgeFiltering, bridge.GetRequiredFeatures());

        var bundle = new FirewallPolicyBundle(
            FirewallPolicyBundle.CurrentSchemaVersion,
            filter,
            new(1, [new(IpFamily.IPv4, FilterProtocol.Tcp, new("192.0.2.1/32"), "198.51.100.2", 80, 8080)], []),
            bridge);

        Assert.Equal(
            [
                FirewallFeature.DualStackFiltering,
                FirewallFeature.DestinationNat,
                FirewallFeature.BridgeFiltering,
                FirewallFeature.AtomicMultiTableCommit,
                FirewallFeature.ForeignTablePreservation,
            ],
            bundle.GetRequiredFeatures().Order().ToArray());
    }

    /// <summary>Invalid bridge schema, rule nulls, ether types, verdicts, and interface names fail closed.</summary>
    [Fact]
    public void BridgeCompiler_InvalidPolicy_ReturnsStableDiagnostics()
    {
        var policy = new BridgePolicy(99, (FilterVerdict)99,
        [
            null,
            new((BridgeEtherType)99, (FilterVerdict)99, "bad/if", "0123456789abcdef"),
        ]);

        var result = NftBridgeCompiler.Compile(policy);
        Assert.False(result.IsSuccess);
        Assert.Null(result.Candidate);
        Assert.Equal(
        [
            new("schema.unsupported", "schemaVersion"),
            new("verdict.unknown", "defaultVerdict"),
            new("bridge.ruleRequired", "rules[0]"),
            new("etherType.unknown", "rules[1].etherType"),
            new("verdict.unknown", "rules[1].verdict"),
            new("interface.invalid", "rules[1].inputInterface"),
            new("interface.invalid", "rules[1].outputInterface"),
        ], result.Diagnostics);
    }

    /// <summary>Valid bridge policies compile deterministically in bridge family with priority -200.</summary>
    [Fact]
    public void BridgeCompiler_ValidRules_CompilesDeterministically()
    {
        var policy = new BridgePolicy(1, FilterVerdict.Drop,
        [
            new(BridgeEtherType.Arp, FilterVerdict.Accept, "br_a", "br_b"),
            new(BridgeEtherType.IPv4, FilterVerdict.Accept),
            new(BridgeEtherType.IPv6, FilterVerdict.Drop, OutputInterface: "br_b"),
            new(BridgeEtherType.Any, FilterVerdict.Drop),
        ]);

        var expected = """
            create table bridge nergal_bridge
            add chain bridge nergal_bridge forward { type filter hook forward priority -200; policy drop; }
            add rule bridge nergal_bridge forward iifname "br_a" oifname "br_b" ether type arp accept
            add rule bridge nergal_bridge forward ether type ip accept
            add rule bridge nergal_bridge forward oifname "br_b" ether type ip6 drop
            add rule bridge nergal_bridge forward drop
            """ + "\n";

        var prev = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-EG");
            var result = NftBridgeCompiler.Compile(policy);
            Assert.True(result.IsSuccess);
            Assert.Equal(expected, result.Candidate);
        }
        finally
        {
            CultureInfo.CurrentCulture = prev;
        }
    }

    /// <summary>Native bridge listings and replacement echoes reconstruct typed rules and detect drift or priority tampering.</summary>
    [Fact]
    public void BridgeObservation_RoundTripsAndRejectsTamperedScope()
    {
        var identity = new NftTableIdentity(Owner, Resource);
        var policy = new BridgePolicy(1, FilterVerdict.Drop,
        [
            new(BridgeEtherType.Arp, FilterVerdict.Accept, "br_a", "br_b"),
            new(BridgeEtherType.IPv4, FilterVerdict.Accept),
            new(BridgeEtherType.IPv6, FilterVerdict.Drop),
            new(BridgeEtherType.Any, FilterVerdict.Drop),
        ]);
        var expected = NftBridgeCompiler.Compile(policy, identity).Candidate!;

        var listing = SampleBridgeListing(identity.Comment);
        var echo = SampleBridgeEcho(identity.Comment);
        var parsedList = NftBridgeTableObservation.Parse(listing.ToJsonString());
        var parsedEcho = NftBridgeTableObservation.ParseReplacementEcho(echo.ToJsonString());
        Assert.True(parsedList.IsSuccess, parsedList.ErrorCode);
        Assert.True(parsedEcho.IsSuccess, parsedEcho.ErrorCode);
        Assert.Equal(parsedList.Observation!.StateDigest, parsedEcho.Observation!.StateDigest);
        Assert.Equal(expected, NftBridgeCompiler.Compile(parsedList.Observation.Policy, identity).Candidate);

        var drifted = SampleBridgeListing(identity.Comment);
        drifted["nftables"]![2]!["chain"]!["policy"] = "accept";
        Assert.NotEqual(parsedList.Observation.StateDigest, NftBridgeTableObservation.Parse(drifted.ToJsonString()).Observation!.StateDigest);

        var wrongPrio = SampleBridgeListing(identity.Comment);
        wrongPrio["nftables"]![2]!["chain"]!["prio"] = 0;
        var badPrio = NftBridgeTableObservation.Parse(wrongPrio.ToJsonString());
        Assert.True(badPrio.IsSuccess, badPrio.ErrorCode);
        Assert.NotEqual(parsedList.Observation.StateDigest, badPrio.Observation!.StateDigest);
        wrongPrio["nftables"]![2]!["chain"]!["prio"] = 301;
        Assert.False(NftBridgeTableObservation.Parse(wrongPrio.ToJsonString()).IsSuccess);
    }

    /// <summary>An error in any table blocks bundle compilation, and atomic replacements only delete owned reserved tables.</summary>
    [Fact]
    public void PolicyBundleCompiler_FailClosedAndTargetedReplacementOnly()
    {
        var identity = new NftTableIdentity(Owner, Resource);
        var invalidBundle = new FirewallPolicyBundle(
            FirewallPolicyBundle.CurrentSchemaVersion,
            new(1, FilterVerdict.Drop, []),
            new(1, [new(IpFamily.IPv4, FilterProtocol.Tcp, new("192.0.2.1/32"), "bad-ip")], []),
            new(1, FilterVerdict.Drop, [null]));

        var failed = NftPolicyBundleCompiler.Compile(invalidBundle, identity);
        Assert.False(failed.IsSuccess);
        Assert.Null(failed.Candidate);
        Assert.Equal(
        [
            new("nat.translatedAddressInvalid", "nat.dnatRules[0].translatedAddress"),
            new("bridge.ruleRequired", "bridge.rules[0]"),
        ], failed.Diagnostics);

        var validBundle = new FirewallPolicyBundle(
            1,
            new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Drop, []),
            null,
            new(1, FilterVerdict.Drop, [new(BridgeEtherType.Arp, FilterVerdict.Accept)]));

        var replacement = NftPolicyBundleCompiler.CompileAtomicReplacement(
            validBundle, identity, filterExists: true, natExists: true, bridgeExists: false);
        Assert.True(replacement.IsSuccess);
        Assert.DoesNotContain("flush ruleset", replacement.Candidate!, StringComparison.Ordinal);
        Assert.StartsWith("delete table inet nergal_nat\ndelete table inet nergal_filter\ncreate table inet nergal_filter",
            replacement.Candidate!, StringComparison.Ordinal);
        Assert.Contains("create table bridge nergal_bridge", replacement.Candidate!, StringComparison.Ordinal);
    }

    private static JsonNode SampleBridgeListing(string comment) => JsonNode.Parse("""
        {"nftables":[
          {"metainfo":{"version":"1.1.7","release_name":"fixture","json_schema_version":1}},
          {"table":{"family":"bridge","name":"nergal_bridge","handle":2,"comment":"MARKER"}},
          {"chain":{"family":"bridge","table":"nergal_bridge","name":"forward","handle":1,"type":"filter","hook":"forward","prio":-200,"policy":"drop"}},
          {"rule":{"family":"bridge","table":"nergal_bridge","chain":"forward","handle":2,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"br_a"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"br_b"}},{"match":{"op":"==","left":{"payload":{"protocol":"ether","field":"type"}},"right":"arp"}},{"accept":null}]}},
          {"rule":{"family":"bridge","table":"nergal_bridge","chain":"forward","handle":3,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ether","field":"type"}},"right":"ip"}},{"accept":null}]}},
          {"rule":{"family":"bridge","table":"nergal_bridge","chain":"forward","handle":4,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ether","field":"type"}},"right":"ip6"}},{"drop":null}]}},
          {"rule":{"family":"bridge","table":"nergal_bridge","chain":"forward","handle":5,"expr":[{"drop":null}]}}
        ]}
        """.Replace("MARKER", comment, StringComparison.Ordinal))!;

    private static JsonNode SampleBridgeEcho(string comment) => JsonNode.Parse("""
        {"nftables":[
          {"create":{"table":{"family":"bridge","name":"nergal_bridge","handle":2,"comment":"MARKER"}}},
          {"add":{"chain":{"family":"bridge","table":"nergal_bridge","name":"forward","handle":1,"type":"filter","hook":"forward","prio":-200,"policy":"drop"}}},
          {"add":{"rule":{"family":"bridge","table":"nergal_bridge","chain":"forward","handle":2,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"br_a"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"br_b"}},{"match":{"op":"==","left":{"payload":{"protocol":"ether","field":"type"}},"right":"arp"}},{"accept":null}]}}},
          {"add":{"rule":{"family":"bridge","table":"nergal_bridge","chain":"forward","handle":3,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ether","field":"type"}},"right":"ip"}},{"accept":null}]}}},
          {"add":{"rule":{"family":"bridge","table":"nergal_bridge","chain":"forward","handle":4,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ether","field":"type"}},"right":"ip6"}},{"drop":null}]}}},
          {"add":{"rule":{"family":"bridge","table":"nergal_bridge","chain":"forward","handle":5,"expr":[{"drop":null}]}}}
        ]}
        """.Replace("MARKER", comment, StringComparison.Ordinal))!;
}
