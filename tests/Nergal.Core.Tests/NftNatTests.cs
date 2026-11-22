using System.Globalization;
using System.Text.Json.Nodes;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Verifies dual-stack DNAT/SNAT compilation, validation diagnostics, and native observation round-tripping.</summary>
public sealed class NftNatTests
{
    private static readonly Guid Owner = Guid.Parse("00000000-0000-0000-0000-000000000001");
    private static readonly Guid Resource = Guid.Parse("00000000-0000-0000-0000-000000000005");

    /// <summary>Policies snapshot NAT rules defensively and report accurate semantic requirements.</summary>
    [Fact]
    public void NatPolicy_SnapshotsRulesAndRequiredFeatures()
    {
        var dnats = new List<DnatRule?>
        {
            new(IpFamily.IPv4, FilterProtocol.Tcp, new("192.0.2.1/32"), "198.51.100.2", 18446, 18447),
        };
        var snats = new List<SnatRule?>
        {
            new(IpFamily.IPv4, new("192.0.2.0/24"), "198.51.100.1"),
        };
        var policy = new NatPolicy(NatPolicy.CurrentSchemaVersion, dnats, snats);
        dnats.Clear();
        snats.Clear();

        Assert.Single(policy.DnatRules);
        Assert.Single(policy.SnatRules);
        Assert.Equal(
            [FirewallFeature.DestinationNat, FirewallFeature.ExplicitSourceNat, FirewallFeature.ForeignTablePreservation],
            policy.GetRequiredFeatures().Order().ToArray());
    }

    /// <summary>Invalid schemas, unsupported protocols, mapped/scoped/CIDR NAT targets, and bad ports fail closed.</summary>
    [Fact]
    public void Compile_InvalidNatRules_ReturnsStableDiagnosticsWithoutCandidate()
    {
        var policy = new NatPolicy(99,
        [
            null,
            new(IpFamily.IPv4, FilterProtocol.Icmp, new("2001:db8::/64"), "198.51.100.2/24", 0, 70000, "bad/if", new("2001:db8::/64")),
            new(IpFamily.IPv6, FilterProtocol.Any, new("2001:db8::1/128"), "192.0.2.10", 80, 443),
            new(IpFamily.IPv6, FilterProtocol.Tcp, new("2001:db8::1/128"), "::ffff:192.0.2.10"),
        ],
        [
            null,
            new(IpFamily.IPv4, new("2001:db8::/64"), "2001:db8::1%eth0", new("2001:db8::/64"), "too_long_interface_name"),
            new(IpFamily.IPv6, new("2001:db8::/64"), "192.0.2.1"),
        ]);

        var result = NftNatCompiler.Compile(policy);
        Assert.False(result.IsSuccess);
        Assert.Null(result.Candidate);
        Assert.Equal(
        [
            new("schema.unsupported", "schemaVersion"),
            new("nat.ruleRequired", "dnatRules[0]"),
            new("nat.protocolUnsupported", "dnatRules[1].protocol"),
            new("network.familyMismatch", "dnatRules[1].originalDestination"),
            new("network.familyMismatch", "dnatRules[1].source"),
            new("interface.invalid", "dnatRules[1].inputInterface"),
            new("nat.translatedAddressInvalid", "dnatRules[1].translatedAddress"),
            new("port.outOfRange", "dnatRules[1].originalPort"),
            new("port.requiresTransport", "dnatRules[1].originalPort"),
            new("port.outOfRange", "dnatRules[1].translatedPort"),
            new("port.requiresTransport", "dnatRules[1].translatedPort"),
            new("nat.translatedFamilyMismatch", "dnatRules[2].translatedAddress"),
            new("port.requiresTransport", "dnatRules[2].originalPort"),
            new("port.requiresTransport", "dnatRules[2].translatedPort"),
            new("nat.translatedAddressInvalid", "dnatRules[3].translatedAddress"),
            new("nat.ruleRequired", "snatRules[0]"),
            new("network.familyMismatch", "snatRules[1].source"),
            new("network.familyMismatch", "snatRules[1].destination"),
            new("interface.invalid", "snatRules[1].outputInterface"),
            new("nat.translatedAddressInvalid", "snatRules[1].translatedAddress"),
            new("nat.translatedFamilyMismatch", "snatRules[2].translatedAddress"),
        ], result.Diagnostics);
    }

    /// <summary>Dual-stack DNAT and explicit SNAT compile deterministically across address families and locales.</summary>
    [Fact]
    public void Compile_DualStackDnatAndExplicitSnat_ProducesDeterministicBatch()
    {
        var policy = new NatPolicy(1,
        [
            new(IpFamily.IPv4, FilterProtocol.Tcp, new("192.0.2.1/32"), "198.51.100.2", 18446, 18447, "r_cli"),
            new(IpFamily.IPv6, FilterProtocol.Udp, new("2001:db8:1::1/128"), "2001:db8:2::2", 18446, 18447, "r_cli"),
            new(IpFamily.IPv6, FilterProtocol.Any, new("2001:db8:3::/64"), "2001:db8:2::3"),
        ],
        [
            new(IpFamily.IPv4, new("192.0.2.0/24"), "198.51.100.1", new("198.51.100.0/24"), "r_srv"),
            new(IpFamily.IPv6, new("2001:db8:1::/64"), "2001:db8:2::1", OutputInterface: "r_srv"),
        ]);

        var expected = """
            create table inet nergal_nat
            add chain inet nergal_nat prerouting { type nat hook prerouting priority dstnat; policy accept; }
            add chain inet nergal_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }
            add rule inet nergal_nat prerouting meta nfproto ipv4 iifname "r_cli" ip daddr 192.0.2.1/32 meta l4proto tcp tcp dport 18446 dnat ip to 198.51.100.2:18447
            add rule inet nergal_nat prerouting meta nfproto ipv6 iifname "r_cli" ip6 daddr 2001:db8:1::1/128 meta l4proto udp udp dport 18446 dnat ip6 to [2001:db8:2::2]:18447
            add rule inet nergal_nat prerouting meta nfproto ipv6 ip6 daddr 2001:db8:3::/64 dnat ip6 to 2001:db8:2::3
            add rule inet nergal_nat postrouting meta nfproto ipv4 oifname "r_srv" ip saddr 192.0.2.0/24 ip daddr 198.51.100.0/24 snat ip to 198.51.100.1
            add rule inet nergal_nat postrouting meta nfproto ipv6 oifname "r_srv" ip6 saddr 2001:db8:1::/64 snat ip6 to 2001:db8:2::1
            """ + "\n";

        var prev = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-EG");
            var result = NftNatCompiler.Compile(policy);
            Assert.True(result.IsSuccess);
            Assert.Equal(expected, result.Candidate);
        }
        finally
        {
            CultureInfo.CurrentCulture = prev;
        }
    }

    /// <summary>Native NAT table listings and replacement echoes reconstruct typed policies and reject tampered scopes.</summary>
    [Fact]
    public void NatObservation_AndReplacementEcho_RoundTripsAndRejectsTampering()
    {
        var identity = new NftTableIdentity(Owner, Resource);
        var policy = new NatPolicy(1,
        [
            new(IpFamily.IPv4, FilterProtocol.Tcp, new("192.0.2.1/32"), "198.51.100.2", 18446, 18447, "r_cli"),
            new(IpFamily.IPv6, FilterProtocol.Udp, new("2001:db8:1::1/128"), "2001:db8:2::2", 18446, 18447, "r_cli"),
        ],
        [
            new(IpFamily.IPv4, new("192.0.2.0/24"), "198.51.100.1", new("198.51.100.0/24"), "r_srv"),
            new(IpFamily.IPv6, new("2001:db8:1::/64"), "2001:db8:2::1", OutputInterface: "r_srv"),
        ]);
        var expected = NftNatCompiler.Compile(policy, identity).Candidate!;

        var list = SampleListing(identity.Comment);
        var echo = SampleEcho(identity.Comment);
        var parsedList = NftNatTableObservation.Parse(list.ToJsonString());
        var parsedEcho = NftNatTableObservation.ParseReplacementEcho(echo.ToJsonString());
        Assert.True(parsedList.IsSuccess, parsedList.ErrorCode);
        Assert.True(parsedEcho.IsSuccess, parsedEcho.ErrorCode);
        Assert.Equal(parsedList.Observation!.StateDigest, parsedEcho.Observation!.StateDigest);
        Assert.Equal(expected, NftNatCompiler.Compile(parsedList.Observation.Policy, identity).Candidate);

        var drifted = SampleListing(identity.Comment);
        drifted["nftables"]![7]!["rule"]!["expr"]![2]!["snat"]!["addr"] = "2001:db8:2::9";
        Assert.NotEqual(parsedList.Observation.StateDigest, NftNatTableObservation.Parse(drifted.ToJsonString()).Observation!.StateDigest);

        var familyMismatch = SampleListing(identity.Comment);
        familyMismatch["nftables"]![7]!["rule"]!["expr"]![2]!["snat"]!["addr"] = "198.51.100.9";
        var mismatchResult = NftNatTableObservation.Parse(familyMismatch.ToJsonString());
        Assert.False(mismatchResult.IsSuccess);
        Assert.Equal("observation.rule", mismatchResult.ErrorCode);

        var masquerade = SampleListing(identity.Comment);
        masquerade["nftables"]![7]!["rule"]!["expr"]![2] = JsonNode.Parse("""{"masquerade":null}""")!;
        var changedAction = NftNatTableObservation.Parse(masquerade.ToJsonString());
        Assert.True(changedAction.IsSuccess);
        Assert.NotEqual(parsedList.Observation.StateDigest, changedAction.Observation!.StateDigest);
        Assert.Equal(NatPostroutingAction.Masquerade, changedAction.Observation.Policy.SnatRules[1]!.Action);
    }

    private static JsonNode SampleListing(string comment) => JsonNode.Parse("""
        {"nftables":[
          {"metainfo":{"version":"1.1.7","release_name":"fixture","json_schema_version":1}},
          {"table":{"family":"inet","name":"nergal_nat","handle":1,"comment":"MARKER"}},
          {"chain":{"family":"inet","table":"nergal_nat","name":"prerouting","handle":1,"type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}},
          {"chain":{"family":"inet","table":"nergal_nat","name":"postrouting","handle":2,"type":"nat","hook":"postrouting","prio":100,"policy":"accept"}},
          {"rule":{"family":"inet","table":"nergal_nat","chain":"prerouting","handle":3,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"r_cli"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"192.0.2.1"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":18446}},{"dnat":{"family":"ip","addr":"198.51.100.2","port":18447}}]}},
          {"rule":{"family":"inet","table":"nergal_nat","chain":"prerouting","handle":4,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"r_cli"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"daddr"}},"right":"2001:db8:1::1"}},{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":18446}},{"dnat":{"family":"ip6","addr":"2001:db8:2::2","port":18447}}]}},
          {"rule":{"family":"inet","table":"nergal_nat","chain":"postrouting","handle":5,"expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"r_srv"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"192.0.2.0","len":24}}}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"198.51.100.0","len":24}}}},{"snat":{"family":"ip","addr":"198.51.100.1"}}]}},
          {"rule":{"family":"inet","table":"nergal_nat","chain":"postrouting","handle":6,"expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"r_srv"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"saddr"}},"right":{"prefix":{"addr":"2001:db8:1::","len":64}}}},{"snat":{"family":"ip6","addr":"2001:db8:2::1"}}]}}
        ]}
        """.Replace("MARKER", comment, StringComparison.Ordinal))!;

    private static JsonNode SampleEcho(string comment) => JsonNode.Parse("""
        {"nftables":[
          {"create":{"table":{"family":"inet","name":"nergal_nat","handle":1,"comment":"MARKER"}}},
          {"add":{"chain":{"family":"inet","table":"nergal_nat","name":"prerouting","handle":1,"type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}}},
          {"add":{"chain":{"family":"inet","table":"nergal_nat","name":"postrouting","handle":2,"type":"nat","hook":"postrouting","prio":100,"policy":"accept"}}},
          {"add":{"rule":{"family":"inet","table":"nergal_nat","chain":"prerouting","handle":3,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"r_cli"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"192.0.2.1"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":18446}},{"dnat":{"family":"ip","addr":"198.51.100.2","port":18447}}]}}},
          {"add":{"rule":{"family":"inet","table":"nergal_nat","chain":"prerouting","handle":4,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"r_cli"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"daddr"}},"right":"2001:db8:1::1"}},{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":18446}},{"dnat":{"family":"ip6","addr":"2001:db8:2::2","port":18447}}]}}},
          {"add":{"rule":{"family":"inet","table":"nergal_nat","chain":"postrouting","handle":5,"expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"r_srv"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"192.0.2.0","len":24}}}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"198.51.100.0","len":24}}}},{"snat":{"family":"ip","addr":"198.51.100.1"}}]}}},
          {"add":{"rule":{"family":"inet","table":"nergal_nat","chain":"postrouting","handle":6,"expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"r_srv"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"saddr"}},"right":{"prefix":{"addr":"2001:db8:1::","len":64}}}},{"snat":{"family":"ip6","addr":"2001:db8:2::1"}}]}}}
        ]}
        """.Replace("MARKER", comment, StringComparison.Ordinal))!;
}
