using System.Text.Json.Nodes;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Call targets and caller continuation belong to the owned inet table and its complete receipt.</summary>
public sealed class FilterChainCallTests
{
    private static readonly FilterRule Call = new(IpFamily.DualStack, FilterProtocol.Any, FilterVerdict.Jump, JumpTarget: "outer");
    private static FilterPolicy Policy(string[] names, params FilterRule[] rules) =>
        new(2, FilterVerdict.Drop, FilterVerdict.Accept, FilterVerdict.Accept, rules, regularChains: names);

    /// <summary>Caller mutation and inline toggles preserve declarations, rule order and implicit return from an empty chain.</summary>
    [Fact]
    public void EmptyChainAndRetainedCallsSurviveJsonAndStateChanges()
    {
        string[] names = ["outer", "empty"];
        var nested = Call with { Chain = FilterChainKind.Regular, RegularChain = "outer", JumpTarget = "empty" };
        var policy = Policy(names, Call, nested, nested with { Verdict = FilterVerdict.Return, JumpTarget = null });
        names[0] = "changed";
        var bundle = PolicyBundleJsonCodec.DecodeBundle(PolicyBundleJsonCodec.EncodeBundle(new(1, policy))).Value!;
        Assert.Equal(policy.RegularChains, bundle.Filter.RegularChains);
        Assert.Equal(policy.Rules, bundle.Filter.Rules);
        Assert.Contains(FirewallFeature.FilterChainCalls, bundle.Filter.GetRequiredFeatures());
        var artifact = NftFilterCompiler.Compile(bundle.Filter).Candidate!;
        Assert.EndsWith("add rule inet nergal_filter input jump ngc_outer\n" +
            "add rule inet nergal_filter ngc_outer jump ngc_empty\n" +
            "add rule inet nergal_filter ngc_outer return\n", artifact);
        var disabled = PolicyRuleStates.SetEnabled(bundle, PolicyRuleScope.Filter, 1, null, false);
        Assert.DoesNotContain("jump ngc_empty", NftFilterCompiler.Compile(disabled.Filter).Candidate!);
        Assert.Equal(artifact, NftFilterCompiler.Compile(PolicyRuleStates.SetEnabled(disabled, PolicyRuleScope.Filter, 1, null, true).Filter).Candidate);
    }

    /// <summary>Validate the entire graph even when an invalid edge or chain is disabled or unreachable.</summary>
    [Theory]
    [InlineData("foreign", "jump.invalidTarget")]
    [InlineData("foreignCaller", "chain.undeclared")]
    [InlineData("baseReturn", "return.requiresRegularChain")]
    [InlineData("cycle", "jump.cycleOrDepth")]
    [InlineData("depth", "jump.cycleOrDepth")]
    [InlineData("scope", "chain.callerHookMismatch")]
    [InlineData("action", "jump.invalidTarget")]
    [InlineData("name", "chain.invalidName")]
    [InlineData("duplicate", "chain.invalidName")]
    public void InvalidGraphDeniesWholeCandidate(string change, string code)
    {
        var nested = Call with { Chain = FilterChainKind.Regular, RegularChain = "outer", JumpTarget = "inner", Enabled = false };
        string[] names = ["outer", "inner"];
        var policy = change switch
        {
            "foreign" => Policy(names, Call with { JumpTarget = "output" }),
            "foreignCaller" => Policy(names, nested with { RegularChain = "missing" }),
            "baseReturn" => Policy(names, Call with { Verdict = FilterVerdict.Return, JumpTarget = null }),
            "cycle" => Policy(names, nested, nested with { RegularChain = "inner", JumpTarget = "outer" }),
            "depth" => Policy(["a", "b", "c", "d", "e", "f", "g", "h", "i"],
                "abcdefgh".Select(c => nested with { RegularChain = c.ToString(), JumpTarget = ((char)(c + 1)).ToString() }).ToArray()),
            "scope" => Policy(names, Call, nested, nested with { RegularChain = "inner", Verdict = FilterVerdict.Return, JumpTarget = null, OutputInterface = "eth0" }),
            "action" => Policy(names, Call with { Family = IpFamily.IPv4, Verdict = FilterVerdict.Drop }),
            "name" => Policy(["outer; drop"]),
            "duplicate" => Policy(["outer", "outer"]),
            _ => throw new ArgumentOutOfRangeException(nameof(change)),
        };
        var result = NftFilterCompiler.Compile(policy);
        Assert.Null(result.Candidate);
        Assert.Contains(result.Diagnostics, d => d.Code == code);
    }

    /// <summary>Check native listing mutations against the recorded synthetic packet fixture in both observation modes.</summary>
    [Theory]
    [InlineData("chainHandle", true)]
    [InlineData("order", true)]
    [InlineData("redirect", true)]
    [InlineData("missingTarget", false)]
    [InlineData("unknownField", false)]
    [InlineData("handleCollision", false)]
    [InlineData("cycle", false)]
    [InlineData("goto", false)]
    [InlineData("foreignTable", false)]
    public void NativeDriftIsBoundOrDenied(string change, bool stillValid)
    {
        var assembly = typeof(FilterChainCallTests).Assembly;
        using var stream = assembly.GetManifestResourceStream(assembly.GetManifestResourceNames().Single(n => n.EndsWith("filter-calls-list.json", StringComparison.Ordinal)))!;
        using var reader = new StreamReader(stream);
        var original = reader.ReadToEnd();
        var expected = NftTableObservation.Parse(original).Observation!;
        var root = JsonNode.Parse(original)!;
        var items = root["nftables"]!.AsArray();
        var outer = items.Select(i => i!["chain"]).SingleOrDefault(c => (string?)c?["name"] == "ngc_outer")!;
        var call = items.Select(i => i!["rule"]).Single(r => (string?)r?["chain"] == "input" && r["expr"]!.AsArray()[^1]!["jump"] is not null)!;
        var action = call["expr"]!.AsArray()[^1]!;
        switch (change)
        {
            case "chainHandle": outer["handle"] = 80; break;
            case "order":
                var first = items.IndexOf(call.Parent);
                var saved = items[first]!.DeepClone();
                items.RemoveAt(first);
                items.Insert(first + 1, saved);
                break;
            case "redirect": action["jump"]!["target"] = "ngc_inner"; break;
            case "missingTarget": action["jump"]!["target"] = "ngc_unknown"; break;
            case "unknownField": action["jump"]!["extra"] = true; break;
            case "handleCollision": outer["handle"] = (int)call["handle"]!; break;
            case "cycle":
                var edge = items.Select(i => i!["rule"]).Single(r => (string?)r?["chain"] == "ngc_outer" && r["expr"]!.AsArray()[^1]!["jump"] is not null)!;
                edge["expr"]!.AsArray()[^1]!["jump"]!["target"] = "ngc_outer";
                break;
            case "goto": call["expr"]!.AsArray()[^1] = new JsonObject { ["goto"] = action["jump"]!.DeepClone() }; break;
            case "foreignTable": outer["table"] = "foreign"; break;
        }
        var listing = NftTableObservation.Parse(root.ToJsonString());
        var commands = items.Skip(1).Select(i => new JsonObject { [i!["table"] is null ? "add" : "create"] = i.DeepClone() });
        var echo = NftTableObservation.ParseReplacementEcho(new JsonObject { ["nftables"] = new JsonArray(commands.ToArray<JsonNode?>()) }.ToJsonString());
        Assert.Equal(stillValid, listing.IsSuccess);
        Assert.Equal(stillValid, echo.IsSuccess);
        if (stillValid)
        {
            Assert.Equal(listing.Observation!.StateDigest, echo.Observation!.StateDigest);
            Assert.NotEqual(expected.StateDigest, listing.Observation.StateDigest);
        }
    }
}
