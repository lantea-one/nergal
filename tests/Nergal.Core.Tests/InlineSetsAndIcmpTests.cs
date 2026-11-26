using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Verifies schema-2 inline address/port sets, IPv4 ICMPv4 parameter-problem, codec round-trips, and observation digests.</summary>
public sealed class InlineSetsAndIcmpTests
{
    private static readonly NftTableIdentity SampleIdentity = new(
        Guid.Parse("11111111-2222-3333-4444-555555555555"),
        Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));

    /// <summary>Valid schema-2 inline address/port sets and IPv4 ICMP parameter-problem compile in canonical sorted order and round-trip via JSON codec.</summary>
    [Fact]
    public void InlineSetsAndIcmpV4ParameterProblem_CompileCanonicallyAndRoundTripCodec()
    {
        var policy = new FilterPolicy(
            2,
            FilterVerdict.Drop,
            FilterVerdict.Drop,
            FilterVerdict.Accept,
            [
                new FilterRule(
                    IpFamily.IPv4,
                    FilterProtocol.Tcp,
                    FilterVerdict.Accept,
                    Chain: FilterChainKind.Input,
                    SourcePrefixes: [new NetworkPrefix("198.51.100.0/24"), new NetworkPrefix("192.0.2.0/24")],
                    DestinationPorts: [443, 80]),
                new FilterRule(
                    IpFamily.IPv6,
                    FilterProtocol.Udp,
                    FilterVerdict.Accept,
                    Chain: FilterChainKind.Forward,
                    DestinationPrefixes: [new NetworkPrefix("2001:db8:3::/48"), new NetworkPrefix("2001:db8:1::/48")],
                    DestinationPorts: [5353, 53]),
                new FilterRule(
                    IpFamily.IPv4,
                    FilterProtocol.Icmp,
                    FilterVerdict.Accept,
                    Chain: FilterChainKind.Input,
                    IcmpType: FilterIcmpTypes.ParameterProblem),
            ]);

        var compiled = NftFilterCompiler.Compile(policy, SampleIdentity);
        Assert.True(compiled.IsSuccess);
        Assert.Contains("ip saddr { 192.0.2.0/24, 198.51.100.0/24 }", compiled.Candidate, StringComparison.Ordinal);
        Assert.Contains("tcp dport { 80, 443 }", compiled.Candidate, StringComparison.Ordinal);
        Assert.Contains("ip6 daddr { 2001:db8:1::/48, 2001:db8:3::/48 }", compiled.Candidate, StringComparison.Ordinal);
        Assert.Contains("udp dport { 53, 5353 }", compiled.Candidate, StringComparison.Ordinal);
        Assert.Contains("icmp type parameter-problem accept", compiled.Candidate, StringComparison.Ordinal);

        var bundle = new FirewallPolicyBundle(1, policy);
        var json = PolicyBundleJsonCodec.EncodeBundle(bundle, indented: false);
        var decoded = PolicyBundleJsonCodec.DecodeBundle(json);
        Assert.True(decoded.IsSuccess);
        Assert.Equal(policy.Rules.Count, decoded.Value!.Filter.Rules.Count);
        for (var i = 0; i < policy.Rules.Count; i++)
        {
            Assert.Equal(policy.Rules[i], decoded.Value.Filter.Rules[i]);
        }
    }

    /// <summary>Schema-1 rejection, scalar conflicts, singleton/duplicate/oversized sets, family mismatches, and unsupported ICMPv4 types fail closed.</summary>
    [Fact]
    public void InlineSetsAndIcmpV4_RejectInvalidShapesDeterministically()
    {
        var schema1 = new FilterPolicy(
            1,
            FilterVerdict.Drop,
            [
                new FilterRule(
                    IpFamily.IPv4,
                    FilterProtocol.Tcp,
                    FilterVerdict.Accept,
                    DestinationPorts: [80, 443]),
            ]);
        Assert.Contains(NftFilterCompiler.Compile(schema1).Diagnostics, d => d.Code == "set.requiresSchema2");

        var conflicts = new FilterPolicy(
            2,
            FilterVerdict.Drop,
            FilterVerdict.Drop,
            FilterVerdict.Accept,
            [
                new FilterRule(
                    IpFamily.IPv4,
                    FilterProtocol.Tcp,
                    FilterVerdict.Accept,
                    Source: new NetworkPrefix("192.0.2.0/24"),
                    SourcePrefixes: [new NetworkPrefix("192.0.2.0/24"), new NetworkPrefix("198.51.100.0/24")],
                    DestinationPort: 443,
                    DestinationPorts: [80, 443]),
                new FilterRule(
                    IpFamily.IPv4,
                    FilterProtocol.Tcp,
                    FilterVerdict.Accept,
                    SourcePrefixes: [new NetworkPrefix("192.0.2.0/24")]),
                new FilterRule(
                    IpFamily.IPv4,
                    FilterProtocol.Tcp,
                    FilterVerdict.Accept,
                    SourcePrefixes: [new NetworkPrefix("192.0.2.0/24"), new NetworkPrefix("192.0.2.0/24")]),
                new FilterRule(
                    IpFamily.IPv4,
                    FilterProtocol.Tcp,
                    FilterVerdict.Accept,
                    SourcePrefixes: [new NetworkPrefix("192.0.2.0/24"), new NetworkPrefix("2001:db8::/32")]),
                new FilterRule(
                    IpFamily.IPv4,
                    FilterProtocol.Any,
                    FilterVerdict.Accept,
                    DestinationPorts: [80, 443]),
                new FilterRule(
                    IpFamily.IPv4,
                    FilterProtocol.Icmp,
                    FilterVerdict.Accept,
                    IcmpType: FilterIcmpTypes.NdRouterSolicit),
                new FilterRule(
                    IpFamily.IPv6,
                    FilterProtocol.Udp,
                    FilterVerdict.Accept,
                    DestinationPrefixes: [new NetworkPrefix("2001:db8:2::/48"), new NetworkPrefix("2001:db8:3::/48")]),
            ]);

        var diagnostics = NftFilterCompiler.Compile(conflicts).Diagnostics;
        Assert.Contains(diagnostics, d => d.Code == "set.conflictsWithScalar" && d.Path == "rules[0].sourcePrefixes");
        Assert.Contains(diagnostics, d => d.Code == "set.conflictsWithScalar" && d.Path == "rules[0].destinationPorts");
        Assert.Contains(diagnostics, d => d.Code == "set.minElements" && d.Path == "rules[1].sourcePrefixes");
        Assert.Contains(diagnostics, d => d.Code == "set.duplicate" && d.Path == "rules[2].sourcePrefixes[1]");
        Assert.Contains(diagnostics, d => d.Code == "network.familyMismatch" && d.Path == "rules[3].sourcePrefixes[1]");
        Assert.Contains(diagnostics, d => d.Code == "port.requiresTransport" && d.Path == "rules[4].destinationPorts");
        Assert.Contains(diagnostics, d => d.Code == "icmpType.unsupported" && d.Path == "rules[5].icmpType");
        Assert.Contains(diagnostics, d => d.Code == "set.overlappingOrAdjacent" && d.Path == "rules[6].destinationPrefixes[1]");
    }

    /// <summary>Observation parses nftables JSON anonymous sets into canonical FilterRule sets and changes StateDigest on element mutation.</summary>
    [Fact]
    public void Observation_ParsesInlineSetsAndDetectsElementDigestChange()
    {
        static string BuildListing(int secondPort) => """
            {"nftables":[
              {"metainfo":{"version":"1.0.9","release_name":"test","json_schema_version":1}},
              {"table":{"family":"inet","name":"nergal_filter","handle":5,"comment":"__COMMENT__"}},
              {"chain":{"family":"inet","table":"nergal_filter","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"drop"}},
              {"chain":{"family":"inet","table":"nergal_filter","name":"forward","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
              {"chain":{"family":"inet","table":"nergal_filter","name":"output","handle":3,"type":"filter","hook":"output","prio":0,"policy":"accept"}},
              {"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":10,"expr":[
                {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"set":[{"prefix":{"addr":"198.51.100.0","len":24}},{"prefix":{"addr":"192.0.2.0","len":24}}]}}},
                {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[__PORT__,80]}}},
                {"accept":null}
              ]}},
              {"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":11,"expr":[
                {"match":{"op":"==","left":{"payload":{"protocol":"icmp","field":"type"}},"right":"parameter-problem"}},
                {"accept":null}
              ]}}
            ]}
            """
            .Replace("__COMMENT__", SampleIdentity.Comment, StringComparison.Ordinal)
            .Replace("__PORT__", secondPort.ToString(System.Globalization.CultureInfo.InvariantCulture), StringComparison.Ordinal);

        var obs443 = NftTableObservation.Parse(BuildListing(443));
        Assert.True(obs443.IsSuccess);
        var firstRule = obs443.Observation!.Policy.Rules[0]!;
        Assert.Equal([new NetworkPrefix("192.0.2.0/24"), new NetworkPrefix("198.51.100.0/24")], firstRule.SourcePrefixes);
        Assert.Equal([80, 443], firstRule.DestinationPorts);
        Assert.Equal(FilterIcmpTypes.ParameterProblem, obs443.Observation.Policy.Rules[1]!.IcmpType);

        var obs8443 = NftTableObservation.Parse(BuildListing(8443));
        Assert.True(obs8443.IsSuccess);
        Assert.NotEqual(obs443.Observation.StateDigest, obs8443.Observation!.StateDigest);
    }
}
