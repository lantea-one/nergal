using System.Text.Json.Nodes;
using Nergal.Core.Controller;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>References preserve identity/version while native projection retains every existing matcher.</summary>
public sealed class PolicyObjectReferenceTests
{
    private static readonly Guid Id = Guid.Parse("11111111-1111-4111-8111-111111111111");
    private static PolicyObjectReference Addresses() => new(Id, 1, new("clients", ReusableObjectKind.Ipv4, "Synthetic", ["192.0.2.10", "198.51.100.0/24"]));
    private static FirewallPolicyBundle Bundle(FilterRule rule) => new(1, new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, [rule]));

    /// <summary>Codec equality and native output preserve version identity without weakening MAC, negation or ports.</summary>
    [Fact]
    public void Reference_RoundTripsAndCompilesToExactLiteralEquivalent()
    {
        var rule = new FilterRule(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept,
            SourceObject: Addresses(), DestinationPortObject: new(Id, 2, new("web", ReusableObjectKind.Port, "", ["80", "443"])),
            SourceMac: new("02:00:00:00:00:10"), NegateSource: true, InputInterface: "lan0");
        var bundle = Bundle(rule);
        var json = PolicyBundleJsonCodec.EncodeBundle(bundle);
        var decoded = PolicyBundleJsonCodec.DecodeBundle(json);
        Assert.True(decoded.IsSuccess); Assert.Equal(rule, decoded.Value!.Filter.Rules[0]);
        Assert.Equal(rule.GetHashCode(), decoded.Value.Filter.Rules[0]!.GetHashCode());
        var literal = rule with { SourceObject = null, DestinationPortObject = null, SourcePrefixes = [new("192.0.2.10/32"), new("198.51.100.0/24")], DestinationPorts = [80, 443] };
        var compiled = NftPolicyBundleCompiler.Compile(bundle);
        Assert.True(compiled.IsSuccess); Assert.Equal(NftPolicyBundleCompiler.Compile(Bundle(literal)).Candidate, compiled.Candidate);
        Assert.Contains("sourceObject", json); Assert.Equal(1, bundle.Filter.Rules[0]!.SourceObject!.Version);
        Assert.Equal(2, PolicyObjectReferences.Enumerate(bundle).Count);
    }

    /// <summary>Unsupported family/type/protocol, literal conflicts and merging-sensitive lists never yield candidates.</summary>
    [Theory]
    [InlineData("conflict")]
    [InlineData("family")]
    [InlineData("protocol")]
    [InlineData("kind")]
    [InlineData("overlap")]
    public void Reference_InvalidCombinationsFailClosed(string variant)
    {
        var rule = new FilterRule(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, SourceObject: Addresses());
        rule = variant switch
        {
            "conflict" => rule with { Source = new("203.0.113.1/32") },
            "family" => rule with { Family = IpFamily.IPv6 },
            "protocol" => rule with { Protocol = FilterProtocol.Icmp, DestinationPortObject = new(Id, 1, new("ports", ReusableObjectKind.Port, "", ["443"])) },
            "kind" => rule with { SourceObject = new(Id, 1, new("ports", ReusableObjectKind.Port, "", ["443"])) },
            _ => rule with { SourceObject = new(Id, 1, new("overlap", ReusableObjectKind.Ipv4, "", ["192.0.2.0/24", "192.0.2.1"])) }
        };
        var result = NftPolicyBundleCompiler.Compile(Bundle(rule));
        Assert.False(result.IsSuccess); Assert.Null(result.Candidate); Assert.NotEmpty(result.Diagnostics);
    }

    /// <summary>Unknown flags, digest tampering and invalid identities cannot enter canonical intent.</summary>
    [Theory]
    [InlineData("digest")]
    [InlineData("id")]
    [InlineData("version")]
    [InlineData("flags")]
    [InlineData("kind")]
    public void Reference_CodecRejectsUnknownAndTamperedSnapshots(string field)
    {
        var json = JsonNode.Parse(PolicyBundleJsonCodec.EncodeBundle(Bundle(new(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Drop, SourceObject: Addresses()))))!;
        var reference = json["filter"]!["rules"]![0]!["sourceObject"]!;
        if (field == "version") { reference[field] = 0; }
        else { reference[field] = field == "digest" ? new string('0', 64) : "unsupported"; }
        var result = PolicyBundleJsonCodec.DecodeBundle(json.ToJsonString());
        Assert.False(result.IsSuccess); Assert.Equal("filter.objectReference", Assert.Single(result.Diagnostics).Code);
    }

    /// <summary>Single-element snapshots use existing scalar semantics; schema 1 cannot silently gain reference support.</summary>
    [Fact]
    public void Reference_SingletonAndSchemaBoundaryAreExplicit()
    {
        var rule = new FilterRule(IpFamily.IPv6, FilterProtocol.Udp, FilterVerdict.Accept, SourceObject: new(Id, 1, new("client6", ReusableObjectKind.Ipv6, "", ["2001:db8::1"])));
        var compiled = NftPolicyBundleCompiler.Compile(Bundle(rule));
        Assert.True(compiled.IsSuccess); Assert.Contains("ip6 saddr 2001:db8::1", compiled.Candidate);
        var legacy = NftFilterCompiler.Compile(new FilterPolicy(1, FilterVerdict.Drop, [rule]));
        Assert.Contains(legacy.Diagnostics, d => d.Code == "object.requiresSchema2"); Assert.Null(legacy.Candidate);
        Assert.Throws<ArgumentException>(() => new PolicyObjectReference(Guid.Empty, 1, Addresses().Content));
    }
}
