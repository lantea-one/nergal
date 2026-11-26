using System.Text.Json.Nodes;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Raw NOTRACK is an ordered nonterminal statement in either of two fixed owned hooks.</summary>
public sealed class RawNotrackTests
{
    private const string TrackBypass = """{"notrack":null}""";
    private const string FibMatch = """{"match":{"op":"==","left":{"fib":{"result":"oif","flags":["saddr","iif"]}},"right":"0"}}""";
    private const string EgressMatch = """{"match":{"op":"!=","left":{"meta":{"key":"oifname"}},"right":"test0"}}""";
    private const string UdpMatch = """{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":19044}}""";

    private static FilterPolicy Filter(RpFilterPolicy? prerouting = null, RpFilterPolicy? output = null, int schema = 2) =>
        new(schema, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Drop, [], prerouting, rawOutput: output);

    /// <summary>A later FIB drop still runs after NOTRACK. Disabled rules retain their position in immutable intent.</summary>
    [Fact]
    public void CompilePreservesOrderedHooksAndNonterminalAction()
    {
        var bypass = new RpFilterRule(FilterVerdict.Continue, Protocol: FilterProtocol.Udp, DestinationPort: 19044, Notrack: true);
        RpFilterRule[] rules = [bypass, new(FilterVerdict.Accept, Enabled: false), new(FilterVerdict.Drop, MatchFibUnreachable: true)];
        var filter = Filter(new(FilterVerdict.Accept, rules), new(FilterVerdict.Accept,
            [bypass with { OutputInterface = "test0", NegateOutputInterface = true }, new(FilterVerdict.Drop)]));
        rules[0] = new(FilterVerdict.Accept);

        var result = NftFilterCompiler.Compile(filter);
        Assert.True(result.IsSuccess, string.Join(", ", result.Diagnostics));
        Assert.Equal("""
            add rule inet nergal_filter rpfilter udp dport 19044 notrack
            add rule inet nergal_filter rpfilter fib saddr . iif oif == 0 drop
            add rule inet nergal_filter raw_output oifname != "test0" udp dport 19044 notrack
            add rule inet nergal_filter raw_output drop
            """, string.Join('\n', result.Candidate!.Split('\n').Where(line => line.StartsWith("add rule", StringComparison.Ordinal))));
        Assert.Contains("rpfilter { type filter hook prerouting priority raw; policy accept; }", result.Candidate);
        Assert.Contains("raw_output { type filter hook output priority raw; policy accept; }", result.Candidate);
        Assert.False(filter.RpFilter!.Rules[1]!.Enabled);
    }

    /// <summary>Contradictory verdicts, unsupported hooks, unbounded interfaces and disabled invalid rules deny the whole candidate.</summary>
    [Theory]
    [InlineData("terminal", "raw.notrackRequiresContinue")]
    [InlineData("empty", "verdict.unknown")]
    [InlineData("iif", "interface.chainMismatch")]
    [InlineData("oif", "interface.chainMismatch")]
    [InlineData("wildcard", "interface.invalid")]
    [InlineData("negation", "negation.requiresMatcher")]
    [InlineData("fib", "fib.chainMismatch")]
    [InlineData("outputDrop", "raw.requiresAcceptDefault")]
    [InlineData("preroutingDrop", "raw.requiresAcceptDefault")]
    [InlineData("schema1", "rpfilter.requiresSchema2")]
    [InlineData("tooMany", "rpfilter.tooManyRules")]
    public void CompileDeniesUnrepresentableRawPolicy(string scenario, string code)
    {
        var bypass = new RpFilterRule(FilterVerdict.Continue, Notrack: true);
        var rule = scenario switch
        {
            "terminal" => bypass with { Verdict = FilterVerdict.Accept },
            "empty" => bypass with { Notrack = false },
            "iif" => bypass with { InputInterface = "test0" },
            "oif" => bypass with { OutputInterface = "test0" },
            "wildcard" => bypass with { OutputInterface = "test*" },
            "negation" => bypass with { NegateOutputInterface = true },
            "fib" => bypass with { MatchFibUnreachable = true, Enabled = false },
            _ => bypass,
        };
        var chain = new RpFilterPolicy(scenario is "outputDrop" or "preroutingDrop" ? FilterVerdict.Drop : FilterVerdict.Accept,
            Enumerable.Repeat(rule, scenario == "tooMany" ? 4097 : 1));
        var policy = scenario is "oif" or "preroutingDrop" ? Filter(prerouting: chain) : Filter(output: chain, schema: scenario == "schema1" ? 1 : 2);
        var result = NftFilterCompiler.Compile(policy);
        Assert.Null(result.Candidate);
        Assert.Contains(result.Diagnostics, d => d.Code == code);
    }

    /// <summary>Reject an active batch that exceeds the complete native observation budget before returning any artifact.</summary>
    [Fact]
    public void RawOutputMustFitCompleteEchoBudget()
    {
        var rule = new RpFilterRule(FilterVerdict.Continue, Notrack: true);
        var chain = new RpFilterPolicy(FilterVerdict.Accept, Enumerable.Repeat(rule, 900));
        var compiled = NftFilterCompiler.Compile(Filter(output: chain));
        Assert.Null(compiled.Candidate);
        Assert.Equal(new("raw.nativeObservationTooLarge", "rawOutput"), Assert.Single(compiled.Diagnostics));
    }

    /// <summary>Serialization, compilation, and observation agree on which reserved role owns each raw hook.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RecompileRestoresBothHooksWithinTheSelectedRole(bool auxiliary)
    {
        var (policy, _) = Observe(Listing(auxiliary), auxiliary, false);
        var bundle = auxiliary ? new(1, Filter(), auxiliaryFilter: new(-5, policy!)) : new FirewallPolicyBundle(1, policy!);
        var encoded = PolicyBundleJsonCodec.EncodeBundle(bundle);
        var decoded = PolicyBundleJsonCodec.DecodeBundle(encoded);
        Assert.True(decoded.IsSuccess, string.Join(", ", decoded.Diagnostics));
        var projection = NftPolicyBundleCompiler.Compile(decoded.Value!);
        Assert.True(projection.IsSuccess, string.Join(", ", projection.Diagnostics));
        var table = auxiliary ? "nergal_aux" : "nergal_filter";
        Assert.Contains($"add rule inet {table} rpfilter notrack\n", projection.Candidate);
        Assert.Contains($"add rule inet {table} raw_output oifname != \"test0\" udp dport 19044 notrack\n", projection.Candidate);
        Assert.Contains($"add chain inet {table} raw_output {{ type filter hook output priority raw; policy accept; }}", projection.Candidate);
    }

    /// <summary>Both reserved tables reconstruct the same raw matches, verdicts and handles from echo and listing.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BothRolesBindRawObjectHandlesOrderAndSemantics(bool auxiliary)
    {
        var listing = Listing(auxiliary);
        var (echoPolicy, echoDigest) = Observe(Echo(listing), auxiliary, true);
        var (policy, digest) = Observe(listing, auxiliary, false);
        Assert.NotNull(digest);
        Assert.Equal(digest, echoDigest);
        Assert.Equal(policy!.RpFilter!.Rules, echoPolicy!.RpFilter!.Rules);
        Assert.Equal(policy.RawOutput!.Rules, echoPolicy.RawOutput!.Rules);
        Assert.True(policy.RpFilter.Rules[0]!.Notrack);
        Assert.True(policy.RpFilter.Rules[1]!.MatchFibUnreachable);
        Assert.Equal(new(FilterVerdict.Continue, Protocol: FilterProtocol.Udp, DestinationPort: 19044,
            Notrack: true, OutputInterface: "test0", NegateOutputInterface: true), policy.RawOutput.Rules[0]);

        foreach (var (before, after) in new[] { ("\"handle\":4", "\"handle\":40"), ("\"handle\":5", "\"handle\":50"),
                     ("\"handle\":6", "\"handle\":60"), ("\"handle\":8", "\"handle\":80"), ("test0", "test1"), ("19044", "19045"), (TrackBypass, """{"accept":null}""") })
        {
            var changedDigest = Observe(listing.Replace(before, after, StringComparison.Ordinal), auxiliary, false).Digest;
            Assert.NotNull(changedDigest);
            Assert.NotEqual(digest, changedDigest);
        }
        var reordered = JsonNode.Parse(listing)!;
        var items = reordered["nftables"]!.AsArray();
        var first = items[7]!.DeepClone();
        items.RemoveAt(7);
        items.Insert(8, first);
        var reorderDigest = Observe(reordered.ToJsonString(), auxiliary, false).Digest;
        Assert.NotNull(reorderDigest);
        Assert.NotEqual(digest, reorderDigest);
    }

    /// <summary>A partial or extended raw expression cannot authorize a receipt in either native representation.</summary>
    [Theory]
    [InlineData("\"prio\":-300", "\"prio\":-299")]
    [InlineData("\"name\":\"raw_output\"", "\"name\":\"other\"")]
    [InlineData("\"name\":\"raw_output\"", "\"flags\":[\"offload\"],\"name\":\"raw_output\"")]
    [InlineData("\"hook\":\"prerouting\"", "\"hook\":\"output\"")]
    [InlineData("\"prio\":-300,\"policy\":\"accept\"", "\"prio\":-300,\"policy\":\"drop\"")]
    [InlineData("\"handle\":8", "\"handle\":5")]
    [InlineData("oifname", "iifname")]
    [InlineData(EgressMatch, FibMatch)]
    [InlineData("\"flags\":[\"saddr\",\"iif\"]", "\"flags\":[\"saddr\",\"mark\",\"iif\"]")]
    [InlineData(TrackBypass, """{"notrack":{"flags":[]}}""")]
    [InlineData(TrackBypass, """{"notrack":null},{"accept":null}""")]
    [InlineData(UdpMatch, """{"counter":null}""")]
    public void DeniesUnsupportedChainsAndExpressions(string before, string after)
    {
        foreach (var auxiliary in new[] { false, true })
        {
            var listing = Listing(auxiliary);
            Assert.Contains(before, listing);
            var changed = listing.Replace(before, after, StringComparison.Ordinal);
            Assert.Null(Observe(changed, auxiliary, false).Digest);
            Assert.Null(Observe(Echo(changed), auxiliary, true).Digest);
        }
    }

    /// <summary>Static set expansion must never turn an unsupported raw lookup into a valid scalar port matcher.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DeniesNamedSetInRawOutputEvenWithOneElement(bool auxiliary)
    {
        const string name = "nergal_obj_00000000000000000000000000000099_1_p";
        var listing = JsonNode.Parse(Listing(auxiliary))!;
        var items = listing["nftables"]!.AsArray();
        var rule = items.Single(i => (string?)i?["rule"]?["chain"] == "raw_output")!["rule"]!;
        rule["expr"]![1]!["match"]!["right"] = "@" + name;
        items.Insert(7, new JsonObject
        {
            ["set"] = new JsonObject
            {
                ["family"] = "inet",
                ["table"] = auxiliary ? "nergal_aux" : "nergal_filter",
                ["name"] = name,
                ["handle"] = 90,
                ["type"] = "inet_service",
                ["flags"] = new JsonArray("constant"),
                ["elem"] = new JsonArray(19044)
            }
        });
        Assert.Null(Observe(listing.ToJsonString(), auxiliary, false).Digest);
        Assert.Null(Observe(Echo(listing.ToJsonString()), auxiliary, true).Digest);
    }

    private static (FilterPolicy? Policy, string? Digest) Observe(string json, bool auxiliary, bool echo)
    {
        if (auxiliary)
        {
            var table = echo ? NftAuxiliaryTableObservation.ParseReplacementEcho(json) : NftAuxiliaryTableObservation.Parse(json);
            return (table?.Policy.Filter, table?.StateDigest.Value);
        }
        var result = echo ? NftTableObservation.ParseReplacementEcho(json) : NftTableObservation.Parse(json);
        return (result.Observation?.Policy, result.Observation?.StateDigest.Value);
    }

    private static string Listing(bool auxiliary)
    {
        var table = auxiliary ? "nergal_aux" : "nergal_filter";
        var priority = auxiliary ? -5 : 0;
        JsonObject Chain(string name, string hook, int prio, int handle) => new()
        {
            ["chain"] = new JsonObject
            {
                ["family"] = "inet",
                ["table"] = table,
                ["name"] = name,
                ["handle"] = handle,
                ["type"] = "filter",
                ["hook"] = hook,
                ["prio"] = prio,
                ["policy"] = "accept"
            }
        };
        JsonObject Rule(string chain, int handle, params string[] expr) => new()
        {
            ["rule"] = new JsonObject
            {
                ["family"] = "inet",
                ["table"] = table,
                ["chain"] = chain,
                ["handle"] = handle,
                ["expr"] = JsonNode.Parse("[" + string.Join(',', expr) + "]")
            }
        };
        return new JsonObject
        {
            ["nftables"] = new JsonArray(
                JsonNode.Parse("""{"metainfo":{"version":"1","release_name":"fixture","json_schema_version":1}}"""),
                new JsonObject
                {
                    ["table"] = new JsonObject
                    {
                        ["family"] = "inet",
                        ["name"] = table,
                        ["handle"] = 1,
                        ["comment"] = "nergal:v1:00000000000000000000000000000010:00000000000000000000000000000020"
                    }
                },
                Chain("input", "input", priority, 1), Chain("forward", "forward", priority, 2), Chain("output", "output", priority, 3),
                Chain("rpfilter", "prerouting", -300, 4), Chain("raw_output", "output", -300, 5),
                Rule("rpfilter", 6, TrackBypass), Rule("rpfilter", 7, FibMatch, """{"drop":null}"""),
                Rule("raw_output", 8, EgressMatch, UdpMatch, TrackBypass))
        }.ToJsonString();
    }

    private static string Echo(string listing)
    {
        var objects = JsonNode.Parse(listing)!["nftables"]!.AsArray().Skip(1);
        return new JsonObject
        {
            ["nftables"] = new JsonArray(objects.Select(item =>
                new JsonObject { [item!["table"] is null ? "add" : "create"] = item.DeepClone() }).ToArray())
        }.ToJsonString();
    }
}
