using System.Text.Json.Nodes;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Anonymous NAT counters belong to one rule, after its matches and before its action.</summary>
public sealed class NatCounterTests
{
    private static readonly DnatRule Dnat = new(IpFamily.IPv4, FilterProtocol.Tcp,
        new("198.51.100.10/32"), "192.0.2.20", OriginalPort: 443, TranslatedPort: 8443);
    private static readonly SnatRule Snat = new(IpFamily.IPv6, new("2001:db8:1::1/128"), "2001:db8:2::1");

    /// <summary>An active or dormant counter on either NAT rule type requires the backend capability.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void RequiredFeaturesIncludeCountersOnlyWhenRequested(bool enabled)
    {
        Assert.DoesNotContain(FirewallFeature.InlineNatCounters, new NatPolicy(1, [Dnat], [Snat]).GetRequiredFeatures());
        Assert.Contains(FirewallFeature.InlineNatCounters,
            new NatPolicy(1, [Dnat with { CountPackets = true, Enabled = enabled }], []).GetRequiredFeatures());
        Assert.Contains(FirewallFeature.InlineNatCounters,
            new NatPolicy(1, [], [Snat with { CountPackets = true, Enabled = enabled }]).GetRequiredFeatures());
    }

    /// <summary>Stored revisions retain dormant counter intent and reject runtime totals supplied as policy.</summary>
    [Fact]
    public void JsonRetainsDormantCounterAndRejectsRuntimeStateAsIntent()
    {
        var nat = new NatPolicy(1, [Dnat, Dnat with { CountPackets = true, Enabled = false }],
            [Snat, Snat with { CountPackets = true, Enabled = false }]);
        var bundle = new FirewallPolicyBundle(1, new(1, FilterVerdict.Drop, []), nat);
        var encoded = PolicyBundleJsonCodec.EncodeBundle(bundle);
        var restored = PolicyBundleJsonCodec.DecodeBundle(encoded).Value!.Nat!;
        Assert.Equal(nat.DnatRules.ToArray(), restored.DnatRules.ToArray());
        Assert.Equal(nat.SnatRules.ToArray(), restored.SnatRules.ToArray());
        Assert.DoesNotContain("counter", NftNatCompiler.Compile(restored).Candidate);

        foreach (var key in new[] { "dnatRules", "snatRules" })
        {
            var root = JsonNode.Parse(encoded)!;
            var rules = root["nat"]![key]!;
            Assert.False(rules[0]!.AsObject().ContainsKey("countPackets"));
            Assert.True(rules[1]!["countPackets"]!.GetValue<bool>());
            rules[1]!["countPackets"] = JsonNode.Parse("""{"packets":0,"bytes":0}""");
            Assert.Null(PolicyBundleJsonCodec.DecodeBundle(root.ToJsonString()).Value);
        }
    }

    /// <summary>Both DNAT hooks and all postrouting actions retain their match and rule order.</summary>
    [Fact]
    public void CompilerCountsOnlyEnabledRulesThatRequestIt()
    {
        var counted = Dnat with { CountPackets = true };
        var post = Snat with { CountPackets = true };
        var policy = new NatPolicy(1, [counted with { Hook = DnatHook.Output }, Dnat, counted], [
            post with { Action = NatPostroutingAction.Return, TranslatedAddress = null },
            Snat, post with { Enabled = false }, post,
            post with { Action = NatPostroutingAction.Masquerade, TranslatedAddress = null }]);
        var compiled = NftNatCompiler.Compile(policy);
        Assert.True(compiled.IsSuccess);
        var rules = compiled.Candidate!.Split('\n').Where(line => line.StartsWith("add rule ", StringComparison.Ordinal));
        Assert.Equal([
            "add rule inet nergal_nat prerouting meta nfproto ipv4 ip daddr 198.51.100.10/32 meta l4proto tcp tcp dport 443 dnat ip to 192.0.2.20:8443",
            "add rule inet nergal_nat prerouting meta nfproto ipv4 ip daddr 198.51.100.10/32 meta l4proto tcp tcp dport 443 counter dnat ip to 192.0.2.20:8443",
            "add rule inet nergal_nat output meta nfproto ipv4 ip daddr 198.51.100.10/32 meta l4proto tcp tcp dport 443 counter dnat ip to 192.0.2.20:8443",
            "add rule inet nergal_nat postrouting meta nfproto ipv6 ip6 saddr 2001:db8:1::1/128 counter return",
            "add rule inet nergal_nat postrouting meta nfproto ipv6 ip6 saddr 2001:db8:1::1/128 snat ip6 to 2001:db8:2::1",
            "add rule inet nergal_nat postrouting meta nfproto ipv6 ip6 saddr 2001:db8:1::1/128 counter snat ip6 to 2001:db8:2::1",
            "add rule inet nergal_nat postrouting meta nfproto ipv6 ip6 saddr 2001:db8:1::1/128 counter masquerade",
        ], rules);
    }

    /// <summary>Counter intent cannot exempt even a dormant rule from the explicit-family requirement.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void SharedFamilyBlocksWholeNatCandidate(bool enabled)
    {
        var policy = new NatPolicy(1, [Dnat, Dnat with { Family = IpFamily.DualStack, CountPackets = true, Enabled = enabled }],
            [Snat with { Family = IpFamily.DualStack, CountPackets = true, Enabled = enabled }]);
        var compiled = NftNatCompiler.Compile(policy);
        Assert.Null(compiled.Candidate);
        Assert.Contains(new("family.unknown", "dnatRules[1].family"), compiled.Diagnostics);
        Assert.Contains(new("family.unknown", "snatRules[0].family"), compiled.Diagnostics);
    }

    /// <summary>The same handles and actions reconstruct across echo and list as unsigned packet and byte totals change.</summary>
    [Theory]
    [InlineData("prerouting", "dnat")]
    [InlineData("output", "dnat")]
    [InlineData("postrouting", "snat")]
    [InlineData("postrouting", "masquerade")]
    [InlineData("postrouting", "return")]
    public void ReceiptBindsCounterPresenceIndependentlyOfTotals(string chain, string action)
    {
        var expressions = RuleExpressions(action);
        var baseline = Observe(chain, expressions, echo: false).Observation!;
        expressions.Insert(expressions.Count - 1, JsonNode.Parse("""{"counter":{"packets":0,"bytes":0}}"""));
        var creation = Observe(chain, expressions, echo: true);
        Assert.True(creation.IsSuccess, creation.ErrorCode);
        expressions[^2] = JsonNode.Parse("""{"counter":{"bytes":18446744073709551615,"packets":9223372036854775808}}""");
        var current = Observe(chain, expressions, echo: false);
        Assert.True(current.IsSuccess, current.ErrorCode);
        Assert.Equal(creation.Observation!.StateDigest, current.Observation!.StateDigest);
        Assert.NotEqual(baseline.StateDigest, current.Observation.StateDigest);
        var policy = current.Observation.Policy;
        if (action == "dnat") { Assert.True(Assert.Single(policy.DnatRules)!.CountPackets); }
        else { Assert.True(Assert.Single(policy.SnatRules)!.CountPackets); }
        Assert.Contains(" counter " + action, NftNatCompiler.Compile(policy).Candidate);
    }

    /// <summary>Malformed totals, unsupported counter objects and misplaced statements deny the full observation.</summary>
    [Theory]
    [InlineData("""{"counter":"named"}""")]
    [InlineData("""{"counter":null}""")]
    [InlineData("""{"counter":{"bytes":0}}""")]
    [InlineData("""{"counter":{"packets":0}}""")]
    [InlineData("""{"counter":{"packets":0,"bytes":0,"name":"named"}}""")]
    [InlineData("""{"counter":{"packets":-1,"bytes":0}}""")]
    [InlineData("""{"counter":{"packets":0,"bytes":18446744073709551616}}""")]
    [InlineData("""{"counter":{"packets":"0","bytes":0}}""")]
    [InlineData("""{"counter":{"packets":0,"bytes":0.5}}""")]
    [InlineData("before-match")]
    [InlineData("after-action")]
    [InlineData("repeated")]
    [InlineData("counter-only")]
    public void UnexpectedCounterStateDeniesBothEnvelopes(string mutation)
    {
        foreach (var (chain, action) in new[] { ("prerouting", "dnat"), ("postrouting", "snat") })
        {
            var expressions = RuleExpressions(action);
            var counter = JsonNode.Parse("""{"counter":{"packets":0,"bytes":0}}""");
            switch (mutation)
            {
                case "before-match": expressions.Insert(0, counter); break;
                case "after-action": expressions.Add(counter); break;
                case "repeated":
                    expressions.Insert(1, counter);
                    expressions.Insert(1, counter!.DeepClone());
                    break;
                case "counter-only": expressions[^1] = counter; break;
                default: expressions.Insert(expressions.Count - 1, JsonNode.Parse(mutation)); break;
            }
            Assert.Equal("observation.rule", Observe(chain, expressions, echo: false).ErrorCode);
            Assert.Equal("observation.rule", Observe(chain, expressions, echo: true).ErrorCode);
        }
    }

    private static JsonArray RuleExpressions(string action)
    {
        var matcher = action == "dnat"
            ? """{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"198.51.100.10"}}"""
            : """{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"saddr"}},"right":"2001:db8:1::1"}}""";
        var target = action switch
        {
            "dnat" => JsonNode.Parse("""{"family":"ip","addr":"192.0.2.20"}"""),
            "snat" => JsonNode.Parse("""{"family":"ip6","addr":"2001:db8:2::1"}"""),
            _ => null,
        };
        return new(JsonNode.Parse(matcher), new JsonObject { [action] = target });
    }

    private static NftNatObservationResult Observe(string chain, JsonArray expressions, bool echo)
    {
        var items = new JsonArray();
        if (!echo) { items.Add(JsonNode.Parse("""{"metainfo":{"version":"1.1.7","release_name":"fixture","json_schema_version":1}}""")); }
        Add("create", "table", JsonNode.Parse("""
            {"family":"inet","name":"nergal_nat","handle":1,"comment":"nergal:v1:00000000000000000000000000000010:00000000000000000000000000000020"}
            """)!);
        AddChain("prerouting", 1, -100);
        if (chain == "output") { AddChain("output", 2, -100); }
        AddChain("postrouting", 3, 100);
        Add("add", "rule", new JsonObject
        {
            ["family"] = "inet",
            ["table"] = "nergal_nat",
            ["chain"] = chain,
            ["handle"] = 4,
            ["expr"] = expressions.DeepClone(),
        });
        var json = new JsonObject { ["nftables"] = items }.ToJsonString();
        return echo ? NftNatTableObservation.ParseReplacementEcho(json) : NftNatTableObservation.Parse(json);

        void AddChain(string name, int handle, int priority) => Add("add", "chain", new JsonObject
        {
            ["family"] = "inet",
            ["table"] = "nergal_nat",
            ["name"] = name,
            ["hook"] = name,
            ["type"] = "nat",
            ["prio"] = priority,
            ["policy"] = "accept",
            ["handle"] = handle,
        });

        void Add(string command, string kind, JsonNode value)
        {
            var entry = new JsonObject { [kind] = value };
            items.Add(echo ? new JsonObject { [command] = entry } : entry);
        }
    }
}
