using System.Globalization;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Verifies invalid drafts cannot become partial or broadened native candidates.</summary>
public sealed class NftFilterCompilerTests
{
    /// <summary>Canonical networks cannot introduce native grammar.</summary>
    [Theory]
    [InlineData("192.0.2.0/24", IpFamily.IPv4, "192.0.2.0/24")]
    [InlineData("2001:0DB8::/32", IpFamily.IPv6, "2001:db8::/32")]
    [InlineData("0.0.0.0/0", IpFamily.IPv4, "0.0.0.0/0")]
    [InlineData("::/0", IpFamily.IPv6, "::/0")]
    public void Network_Canonicalizes(string input, IpFamily family, string expected)
    {
        var network = new NetworkPrefix(input);
        Assert.Equal(family, network.Family);
        Assert.Equal(expected, network.Value);
    }

    /// <summary>Ambiguous networks and native fragments fail at the typed boundary.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("192.0.2.1/24")]
    [InlineData("2001:db8::1/32")]
    [InlineData("192.0.2.0/33")]
    [InlineData("::/129")]
    [InlineData("fe80::%lo/64")]
    [InlineData("::ffff:192.0.2.1/128")]
    [InlineData("example.invalid/24")]
    [InlineData("192.0.2.0/24; flush ruleset")]
    public void Network_Invalid_Throws(string? input)
        => Assert.Throws<ArgumentException>(() => new NetworkPrefix(input!));

    /// <summary>Caller mutation cannot change a compiled policy's authority.</summary>
    [Fact]
    public void Policy_SnapshotsRules()
    {
        var rules = new List<FilterRule?> { new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept) };
        var policy = new FilterPolicy(1, FilterVerdict.Drop, rules);
        var before = NftFilterCompiler.Compile(policy).Candidate;
        rules.Clear();
        Assert.Single(policy.Rules);
        Assert.Equal(before, NftFilterCompiler.Compile(policy).Candidate);
        Assert.Throws<NotSupportedException>(() => ((IList<FilterRule?>)policy.Rules).Clear());
    }

    /// <summary>Missing inputs are never interpreted as permit-all policies.</summary>
    [Fact]
    public void NullInputs_Throw()
    {
        Assert.Throws<ArgumentNullException>(() => new FilterPolicy(1, FilterVerdict.Drop, null!));
        Assert.Throws<ArgumentNullException>(() => NftFilterCompiler.Compile(null!));
    }

    /// <summary>All invalid fields are diagnosed in stable order before any candidate exists.</summary>
    [Fact]
    public void Compile_InvalidSchemaAndRules_ReturnsStableDiagnosticsWithoutCandidate()
    {
        var policy = new FilterPolicy(2, (FilterVerdict)99,
        [
            null,
            new((IpFamily)99, (FilterProtocol)99, (FilterVerdict)99),
            new(IpFamily.IPv4, FilterProtocol.IcmpV6, FilterVerdict.Accept,
                new("2001:db8::/32"), new("2001:db8::/32"), 0),
        ]);
        var result = NftFilterCompiler.Compile(policy);
        Assert.False(result.IsSuccess);
        Assert.Null(result.Candidate);
        Assert.Equal(
        [
            new("schema.unsupported", "schemaVersion"),
            new("verdict.unknown", "defaultVerdict"),
            new("rule.required", "rules[0]"),
            new("family.unknown", "rules[1].family"),
            new("protocol.unknown", "rules[1].protocol"),
            new("verdict.unknown", "rules[1].verdict"),
            new("network.familyMismatch", "rules[2].source"),
            new("network.familyMismatch", "rules[2].destination"),
            new("protocol.familyMismatch", "rules[2].protocol"),
            new("port.outOfRange", "rules[2].destinationPort"),
            new("port.requiresTransport", "rules[2].destinationPort"),
        ], result.Diagnostics);
    }

    /// <summary>Invalid ports cannot silently become broader matches.</summary>
    [Theory]
    [InlineData(FilterProtocol.Any, 80, "port.requiresTransport")]
    [InlineData(FilterProtocol.Icmp, 80, "port.requiresTransport")]
    [InlineData(FilterProtocol.Tcp, -1, "port.outOfRange")]
    [InlineData(FilterProtocol.Udp, 65536, "port.outOfRange")]
    public void Compile_InvalidPort_Rejects(FilterProtocol protocol, int port, string code)
    {
        var result = Compile(new(IpFamily.IPv4, protocol, FilterVerdict.Accept, DestinationPort: port));
        Assert.Null(result.Candidate);
        Assert.Equal(new(code, "rules[0].destinationPort"), Assert.Single(result.Diagnostics));
    }

    /// <summary>Both cross-family ICMP combinations fail rather than matching another protocol.</summary>
    [Theory]
    [InlineData(IpFamily.IPv4, FilterProtocol.IcmpV6)]
    [InlineData(IpFamily.IPv6, FilterProtocol.Icmp)]
    public void Compile_WrongIcmpFamily_Rejects(IpFamily family, FilterProtocol protocol)
    {
        var result = Compile(new(family, protocol, FilterVerdict.Accept));
        Assert.Equal("protocol.familyMismatch", Assert.Single(result.Diagnostics).Code);
        Assert.Null(result.Candidate);
    }

    /// <summary>Ordering, address families and exact port bounds survive invariant compilation.</summary>
    [Fact]
    public void Compile_OrderedDualStackPolicy_ProducesDeterministicBatch()
    {
        var policy = new FilterPolicy(1, FilterVerdict.Drop,
        [
            new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Drop, DestinationPort: 1),
            new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept,
                new("192.0.2.0/24"), new("198.51.100.0/24"), 65535),
            new(IpFamily.IPv6, FilterProtocol.Udp, FilterVerdict.Accept, DestinationPort: 53),
            new(IpFamily.IPv4, FilterProtocol.Icmp, FilterVerdict.Accept),
            new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept),
            new(IpFamily.IPv6, FilterProtocol.Any, FilterVerdict.Drop),
        ]);
        var expected = """
            create table inet nergal_filter
            add chain inet nergal_filter input { type filter hook input priority 0; policy drop; }
            add rule inet nergal_filter input meta nfproto ipv4 meta l4proto tcp tcp dport 1 drop
            add rule inet nergal_filter input meta nfproto ipv4 ip saddr 192.0.2.0/24 ip daddr 198.51.100.0/24 meta l4proto tcp tcp dport 65535 accept
            add rule inet nergal_filter input meta nfproto ipv6 meta l4proto udp udp dport 53 accept
            add rule inet nergal_filter input meta nfproto ipv4 meta l4proto icmp accept
            add rule inet nergal_filter input meta nfproto ipv6 meta l4proto ipv6-icmp accept
            add rule inet nergal_filter input meta nfproto ipv6 drop
            """ + "\n";
        var previousCulture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-EG");
            var result = NftFilterCompiler.Compile(policy);
            Assert.True(result.IsSuccess);
            Assert.Empty(result.Diagnostics);
            Assert.Equal(expected, result.Candidate);
            Assert.Equal(result.Candidate, NftFilterCompiler.Compile(policy).Candidate);
        }
        finally
        {
            CultureInfo.CurrentCulture = previousCulture;
        }
    }

    /// <summary>Empty policies retain explicit defaults and introduce no hidden permits.</summary>
    [Theory]
    [InlineData(FilterVerdict.Accept, "accept")]
    [InlineData(FilterVerdict.Drop, "drop")]
    public void Compile_EmptyPolicy_OnlyEmitsDefault(FilterVerdict verdict, string native)
    {
        var result = NftFilterCompiler.Compile(new(1, verdict, []));
        Assert.Equal("create table inet nergal_filter\n" +
            "add chain inet nergal_filter input { type filter hook input priority 0; policy " + native + "; }\n",
            result.Candidate);
    }

    private static CompilationResult Compile(FilterRule rule)
        => NftFilterCompiler.Compile(new(1, FilterVerdict.Drop, [rule]));
}
