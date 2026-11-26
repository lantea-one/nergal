using System.Text.Json.Nodes;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Postrouting original addresses restrict a DNAT connection independently of its current packet tuple.</summary>
public sealed class NatOriginalTupleTests
{
    private static readonly SnatRule Snat = new(IpFamily.IPv4, null, "192.0.2.1", MatchOriginalDestinationDnat: true);

    /// <summary>Changing caller-owned lists cannot broaden a saved rule or a later re-enable.</summary>
    [Fact]
    public void PolicySnapshotsActiveAndDormantSelectors()
    {
        var sources = new List<NetworkPrefix> { new("192.0.2.0/27") };
        var destinations = new List<NetworkPrefix> { new("203.0.113.4/32"), new("203.0.113.2/32") };
        var rule = Snat with
        {
            Source = new("198.51.100.0/24"),
            Protocol = FilterProtocol.Tcp,
            DestinationPort = 8443,
            OriginalSourcePrefixes = sources,
            OriginalDestinationPrefixes = destinations,
            CountPackets = true,
        };
        var active = new NatPolicy(1, [], [rule]);
        var dormant = new NatPolicy(1, [], [rule with { Enabled = false }]);
        sources.Clear();
        destinations.Clear();
        Assert.Contains(FirewallFeature.OriginalConnectionTuple, dormant.GetRequiredFeatures());
        Assert.DoesNotContain("add rule ", NftNatCompiler.Compile(dormant).Candidate);
        Assert.Equal(2, dormant.SnatRules[0]!.OriginalDestinationPrefixes!.Count);
        Assert.EndsWith("postrouting meta nfproto ipv4 ip saddr 198.51.100.0/24 meta l4proto tcp tcp dport 8443 " +
            "ct status dnat ct original ip saddr 192.0.2.0/27 ct original ip daddr { 203.0.113.2/32, 203.0.113.4/32 } counter snat ip to 192.0.2.1\n",
            NftNatCompiler.Compile(active).Candidate);
    }

    /// <summary>All invalid selectors block the entire candidate, including disabled rules.</summary>
    [Fact]
    public void InvalidRestrictionsBlockCompilation()
    {
        Check(Snat with { OriginalDestinationPrefixes = [new("192.0.2.1/32")], MatchOriginalDestinationDnat = false },
            "ct.originalTupleRequiresDnat", "originalDestinationPrefixes");
        Check(Snat with { OriginalSourcePrefixes = [] }, "set.minElements", "originalSourcePrefixes");
        Check(Snat with { OriginalSourcePrefixes = [null!] }, "set.nullElement", "originalSourcePrefixes[0]");
        Check(Snat with { OriginalDestinationPrefixes = [new("2001:db8::/64")] }, "network.familyMismatch", "originalDestinationPrefixes[0]");
        Check(Snat with { OriginalSourcePrefixes = [new("192.0.2.16/28"), new("192.0.2.0/24")] },
            "set.overlappingOrAdjacent", "originalSourcePrefixes[0]");
        Check(Snat with { OriginalDestinationPrefixes = [new("192.0.2.2/32"), new("192.0.2.2/32")] },
            "set.duplicate", "originalDestinationPrefixes[1]");
        Check(Snat with { Family = IpFamily.DualStack }, "family.unknown", "family");
        var limit = Enumerable.Range(0, 65).Select(i => new NetworkPrefix($"192.0.2.{2 * i}/32")).ToArray();
        Assert.True(NftNatCompiler.Compile(new(1, [], [Snat with { OriginalSourcePrefixes = limit[..64] }])).IsSuccess);
        Check(Snat with { OriginalSourcePrefixes = limit }, "set.tooManyElements", "originalSourcePrefixes");

        static void Check(SnatRule invalid, string code, string field)
        {
            var result = NftNatCompiler.Compile(new(1, [], [Snat, invalid with { Enabled = false }]));
            Assert.Null(result.Candidate);
            Assert.Contains(new(code, "snatRules[1]." + field), result.Diagnostics);
        }
    }

    /// <summary>Each selector is independently optional on all postrouting actions. Status alone restricts explicit SNAT.</summary>
    [Theory]
    [InlineData("snat", "ip", false, false)]
    [InlineData("return", "ip", false, true)]
    [InlineData("masquerade", "ip6", true, false)]
    [InlineData("snat", "ip6", true, true)]
    public void BothEnvelopesReconstructExactOptionalSelectors(string action, string ip, bool source, bool destination)
    {
        var expr = Expressions(ip, action, source, destination);
        var list = Read(expr);
        var echo = Read(expr, echo: true);
        Assert.Equal(list.StateDigest, echo.StateDigest);

        var ipv4 = ip == "ip";
        var rule = list.Policy.SnatRules[^1]!;
        Assert.True(rule.MatchOriginalDestinationDnat);
        Assert.True(rule.CountPackets);
        Assert.Equal(source, rule.OriginalSourcePrefixes is not null);
        Assert.Equal(destination, rule.OriginalDestinationPrefixes is not null);
        var suffix = "ct status dnat ";
        if (source) { suffix += $"ct original {ip} saddr " + (ipv4 ? "192.0.2.0/27 " : "2001:db8:1::/64 "); }
        if (destination)
        {
            suffix += $"ct original {ip} daddr " + (ipv4 ? "{ 203.0.113.2/32, 203.0.113.4/32 } " :
                "{ 2001:db8:2::2/128, 2001:db8:2::4/128 } ");
        }
        suffix += "counter " + action;
        if (action == "snat") { suffix += $" {ip} to " + (ipv4 ? "192.0.2.1" : "2001:db8::1"); }
        Assert.EndsWith(suffix + "\n", NftNatCompiler.Compile(list.Policy).Candidate);
    }

    /// <summary>Every original address affects the receipt even with identical object handles and translation.</summary>
    [Fact]
    public void SameHandleAddressDriftChangesDigestAndSetOrderDoesNot()
    {
        var expr = Expressions("ip", "snat");
        var initial = Read(expr).StateDigest;
        expr[3]!["match"]!["right"]!["set"] = new JsonArray("203.0.113.2", "203.0.113.4");
        Assert.Equal(initial, Read(expr).StateDigest);
        expr[3]!["match"]!["right"]!["set"]![0] = "203.0.113.8";
        Assert.NotEqual(initial, Read(expr).StateDigest);
        expr = Expressions("ip", "snat");
        expr[2]!["match"]!["right"]!["prefix"]!["len"] = 26;
        Assert.NotEqual(initial, Read(expr).StateDigest);
        expr = Expressions("ip", "snat");
        expr.RemoveAt(3);
        Assert.NotEqual(initial, Read(expr).StateDigest);
        Assert.Equal("a61a3f5b03e1a39d44cb805878bc9c3b5c75267a86916f888b6b86c140569a29", Read(null).StateDigest.Value);
    }

    /// <summary>A host literal belongs to the original tuple even when a current address implies the same IP family.</summary>
    [Fact]
    public void CurrentAndOriginalAddressesRemainIndependent()
    {
        var expr = Expressions("ip", "snat", destination: false);
        expr[0] = JsonNode.Parse("""{"match":{"op":"!=","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"198.51.100.5"}}""");
        expr[2]!["match"]!["right"] = "192.0.2.4";
        var rule = Read(expr).Policy.SnatRules[^1]!;
        Assert.True(rule.NegateDestination);
        Assert.Equal("198.51.100.5/32", rule.Destination!.Value);
        Assert.Equal("192.0.2.4/32", Assert.Single(rule.OriginalSourcePrefixes!).Value);
        Assert.Null(rule.Source);
        Assert.Null(rule.OriginalDestinationPrefixes);
    }

    /// <summary>Original-only native matches recover an elided nfproto even on actions with no address of their own.</summary>
    [Theory]
    [InlineData("ip", "snat", false)]
    [InlineData("ip", "masquerade", true)]
    [InlineData("ip6", "snat", true)]
    [InlineData("ip6", "return", false)]
    public void TypedOriginalAddressRecoversElidedFamily(string ip, string action, bool source)
    {
        var expressions = Expressions(ip, action, source: source, destination: !source);
        var explicitFamily = Read(expressions);
        expressions.RemoveAt(0);
        var echo = Read(expressions, echo: true);
        var listing = Read(expressions);
        Assert.Equal(ip == "ip" ? IpFamily.IPv4 : IpFamily.IPv6, listing.Policy.SnatRules[^1]!.Family);
        Assert.Equal(explicitFamily.StateDigest, echo.StateDigest);
        Assert.Equal(echo.StateDigest, listing.StateDigest);
    }

    /// <summary>Whole native observations fail for misplaced expressions, extra fields, unknown semantics and partial sets.</summary>
    [Theory]
    [InlineData("no-status")]
    [InlineData("status-without-family")]
    [InlineData("action-family-conflict")]
    [InlineData("explicit-family-conflict")]
    [InlineData("status-negation")]
    [InlineData("status-equality")]
    [InlineData("wrong-status")]
    [InlineData("duplicate-status")]
    [InlineData("negated-address")]
    [InlineData("reply")]
    [InlineData("bare-key")]
    [InlineData("extra-field")]
    [InlineData("wrong-family")]
    [InlineData("overlap")]
    [InlineData("singleton-set")]
    [InlineData("port-after-original")]
    [InlineData("source-after-destination")]
    [InlineData("counter-before-original")]
    [InlineData("duplicate-destination")]
    public void UnsupportedOrMisplacedExpressionDeniesObservation(string mutation)
    {
        var expr = Expressions("ip", "snat");
        var status = expr[1]!["match"]!;
        var source = expr[2]!["match"]!;
        var destination = expr[3]!["match"]!;
        switch (mutation)
        {
            case "no-status": expr.RemoveAt(1); break;
            case "status-without-family": expr.RemoveAt(3); expr.RemoveAt(2); expr.RemoveAt(0); break;
            case "action-family-conflict":
                expr.RemoveAt(0);
                expr[^1] = JsonNode.Parse("""{"snat":{"family":"ip6","addr":"2001:db8::1"}}""");
                break;
            case "explicit-family-conflict": expr[0]!["match"]!["right"] = "ipv6"; break;
            case "status-negation": status["op"] = "!="; break;
            case "status-equality": status["op"] = "=="; break;
            case "wrong-status": status["right"] = "snat"; break;
            case "duplicate-status": expr.Insert(2, expr[1]!.DeepClone()); break;
            case "negated-address": destination["op"] = "!="; break;
            case "reply": source["left"]!["ct"]!["dir"] = "reply"; break;
            case "bare-key": source["left"]!["ct"]!["key"] = "saddr"; break;
            case "extra-field": source["left"]!["ct"]!["flags"] = 0; break;
            case "wrong-family": destination["left"]!["ct"]!["key"] = "ip6 daddr"; break;
            case "overlap": destination["right"]!["set"]![0] = JsonNode.Parse("""{"prefix":{"addr":"203.0.113.0","len":24}}"""); break;
            case "singleton-set": destination["right"]!["set"]!.AsArray().RemoveAt(0); break;
            case "port-after-original": expr.Insert(4, JsonNode.Parse("""{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}}""")); break;
            case "source-after-destination": expr.RemoveAt(2); expr.Insert(3, new JsonObject { ["match"] = source.DeepClone() }); break;
            case "counter-before-original": expr.RemoveAt(4); expr.Insert(2, Counter()); break;
            case "duplicate-destination": expr.Insert(4, expr[3]!.DeepClone()); break;
        }
        Assert.False(Observe(expr, echo: false).IsSuccess);
        Assert.False(Observe(expr, echo: true).IsSuccess);
    }

    private static JsonArray Expressions(string ip, string action, bool source = true, bool destination = true)
    {
        var ipv4 = ip == "ip";
        var expr = new JsonArray(
            Match("==", new JsonObject { ["meta"] = new JsonObject { ["key"] = "nfproto" } }, ipv4 ? "ipv4" : "ipv6"),
            Match("in", new JsonObject { ["ct"] = new JsonObject { ["key"] = "status" } }, "dnat"));
        if (source)
        {
            var prefix = new JsonObject { ["addr"] = ipv4 ? "192.0.2.0" : "2001:db8:1::", ["len"] = ipv4 ? 27 : 64 };
            expr.Add(Original("saddr", new JsonObject { ["prefix"] = prefix }));
        }
        if (destination)
        {
            var hosts = ipv4 ? new JsonArray("203.0.113.4", "203.0.113.2") : new JsonArray("2001:db8:2::4", "2001:db8:2::2");
            expr.Add(Original("daddr", new JsonObject { ["set"] = hosts }));
        }
        expr.Add(Counter());
        expr.Add(new JsonObject { [action] = action == "snat" ? new JsonObject { ["family"] = ip, ["addr"] = ipv4 ? "192.0.2.1" : "2001:db8::1" } : null });
        return expr;

        JsonNode Original(string field, JsonNode right) => Match("==",
            new JsonObject { ["ct"] = new JsonObject { ["key"] = ip + " " + field, ["dir"] = "original" } }, right);
    }

    private static JsonNode Counter() => JsonNode.Parse("""{"counter":{"packets":10,"bytes":640}}""")!;
    private static JsonNode Match(string op, JsonNode left, JsonNode right) => new JsonObject
    {
        ["match"] = new JsonObject { ["op"] = op, ["left"] = left, ["right"] = right }
    };

    private static NftNatTableObservation Read(JsonArray? expr, bool echo = false)
    {
        var result = Observe(expr, echo);
        Assert.True(result.IsSuccess, result.ErrorCode);
        return result.Observation!;
    }

    private static NftNatObservationResult Observe(JsonArray? expr, bool echo)
    {
        var assembly = typeof(NatOriginalTupleTests).Assembly;
        var filename = echo ? "nat-echo.json" : "nat-list.json";
        var name = assembly.GetManifestResourceNames().Single(n => n.EndsWith(filename, StringComparison.Ordinal));
        using var stream = assembly.GetManifestResourceStream(name)!;
        var root = JsonNode.Parse(stream)!;
        if (expr is not null)
        {
            var tail = root["nftables"]!.AsArray()[^1]!;
            (echo ? tail["add"] : tail)!["rule"]!["expr"] = expr.DeepClone();
        }
        return echo ? NftNatTableObservation.ParseReplacementEcho(root.ToJsonString()) : NftNatTableObservation.Parse(root.ToJsonString());
    }
}
