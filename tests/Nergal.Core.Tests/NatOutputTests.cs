using System.Text.Json.Nodes;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Locally generated DNAT uses an explicit base hook and receipt-bound rule placement.</summary>
public sealed class NatOutputTests
{
    private static readonly DnatRule Output = new(IpFamily.IPv4, FilterProtocol.Tcp,
        new("198.51.100.10/32"), "192.0.2.20", 443, 8443, Hook: DnatHook.Output);

    private static FirewallPolicyBundle Bundle(params DnatRule[] rules) =>
        new(1, new(1, FilterVerdict.Drop, []), new(1, rules, []));

    /// <summary>Only nondefault hooks need a JSON field, including for dormant intent.</summary>
    [Fact]
    public void JsonPreservesHookAndDormantIntent()
    {
        var policy = Bundle(Output with { Hook = DnatHook.Prerouting }, Output with { Enabled = false });
        var json = PolicyBundleJsonCodec.EncodeBundle(policy);
        var root = JsonNode.Parse(json)!;
        var rules = root["nat"]!["dnatRules"]!;
        Assert.False(rules[0]!.AsObject().ContainsKey("hook"));
        Assert.Equal("output", rules[1]!["hook"]!.GetValue<string>());
        rules[0]!["hook"] = "prerouting";
        var decoded = PolicyBundleJsonCodec.DecodeBundle(root.ToJsonString());
        Assert.True(decoded.IsSuccess);
        Assert.Equal(json, PolicyBundleJsonCodec.EncodeBundle(decoded.Value!));
        Assert.DoesNotContain("hook output", NftNatCompiler.Compile(decoded.Value!.Nat!).Candidate);
    }

    /// <summary>Unknown hooks, including null and numeric enum values, cannot bind to PREROUTING.</summary>
    [Theory]
    [InlineData("null")]
    [InlineData("1")]
    [InlineData("\"OUTPUT\"")]
    [InlineData("\"postrouting\"")]
    public void JsonRejectsUnsupportedHook(string value)
    {
        var root = JsonNode.Parse(PolicyBundleJsonCodec.EncodeBundle(Bundle(Output)))!;
        root["nat"]!["dnatRules"]![0]!["hook"] = JsonNode.Parse(value);
        var decoded = PolicyBundleJsonCodec.DecodeBundle(root.ToJsonString());
        Assert.Null(decoded.Value);
        Assert.Equal("nat.hookUnsupported", Assert.Single(decoded.Diagnostics).Code);
    }

    /// <summary>Invalid typed options block the whole candidate even on disabled OUTPUT rules.</summary>
    [Fact]
    public void CompilerDeniesUnknownHookIngressAndInvalidPorts()
    {
        var policy = Bundle(Output,
            Output with { Hook = (DnatHook)7 },
            Output with { Enabled = false, InputInterface = "eth0" },
            Output with { OriginalPort = 0, TranslatedPort = 65536 },
            Output with { Protocol = FilterProtocol.Any }).Nat!;
        var result = NftNatCompiler.Compile(policy);
        Assert.Null(result.Candidate);
        Assert.Equal([
            new("nat.hookUnsupported", "dnatRules[1].hook"),
            new("interface.chainMismatch", "dnatRules[2].inputInterface"),
            new("port.outOfRange", "dnatRules[3].originalPort"),
            new("port.outOfRange", "dnatRules[3].translatedPort"),
            new("port.requiresTransport", "dnatRules[4].originalPort"),
            new("port.requiresTransport", "dnatRules[4].translatedPort"),
        ], result.Diagnostics);
    }

    /// <summary>Interleaved input groups by native hook, preserving first-match order within OUTPUT.</summary>
    [Fact]
    public void BothNativeEnvelopesReconstructTheCompiledCandidate()
    {
        var listing = NativeListing();
        var observed = NftNatTableObservation.Parse(listing.ToJsonString());
        Assert.True(observed.IsSuccess, observed.ErrorCode);
        var nat = observed.Observation!;
        Assert.Equal(2UL, nat.OutputChainHandle);
        var echo = NftNatTableObservation.ParseReplacementEcho(Echo(listing));
        Assert.True(echo.IsSuccess, echo.ErrorCode);
        Assert.Equal(nat.StateDigest, echo.Observation!.StateDigest);
        var destination = Output with { TranslatedPort = 9443 };
        var remote = Output with { Hook = DnatHook.Prerouting };
        var local6 = new DnatRule(IpFamily.IPv6, FilterProtocol.Udp, new("2001:db8:1::10/128"),
            "2001:db8:2::20", 53, Hook: DnatHook.Output);
        var expected = NftNatCompiler.Compile(Bundle(destination, remote, local6).Nat!, nat.Identity).Candidate!;
        Assert.Contains("type nat hook output priority dstnat; policy accept;", expected);
        Assert.Contains("output meta nfproto ipv4 ip daddr 198.51.100.10/32 meta l4proto tcp tcp dport 443 dnat ip to 192.0.2.20:9443", expected);
        Assert.Equal(new[] { remote, destination, local6 }, nat.Policy.DnatRules);
        Assert.Equal(expected, NftNatCompiler.Compile(nat.Policy, nat.Identity).Candidate);
        Assert.Equal(expected, NftNatCompiler.Compile(echo.Observation.Policy, nat.Identity).Candidate);
    }

    /// <summary>Rule migration to another valid hook and output-chain recreation change the receipt.</summary>
    [Fact]
    public void DigestBindsRuleHookAndOutputChainHandle()
    {
        var listing = NativeListing();
        var digest = NftNatTableObservation.Parse(listing.ToJsonString()).Observation!.StateDigest;
        var items = listing["nftables"]!;
        items[6]!["rule"]!["chain"] = "prerouting";
        Assert.NotEqual(digest, NftNatTableObservation.Parse(listing.ToJsonString()).Observation!.StateDigest);
        items[6]!["rule"]!["chain"] = "output";
        items[3]!["chain"]!["handle"] = 27;
        Assert.NotEqual(digest, NftNatTableObservation.Parse(listing.ToJsonString()).Observation!.StateDigest);
    }

    /// <summary>Wrong base chain semantics, invalid handles and unsupported transport shapes invalidate both envelopes.</summary>
    [Theory]
    [InlineData("priority")]
    [InlineData("hook")]
    [InlineData("policy")]
    [InlineData("chain-handle")]
    [InlineData("rule-handle")]
    [InlineData("absent-chain")]
    [InlineData("empty-chain")]
    [InlineData("unknown-rule-chain")]
    [InlineData("source-port")]
    [InlineData("negated-port")]
    [InlineData("service-name")]
    [InlineData("translation-range")]
    [InlineData("translation-overflow")]
    [InlineData("ingress")]
    public void UnrepresentableNativeStateDeniesWholeObservation(string mutation)
    {
        var listing = NativeListing();
        var items = listing["nftables"]!.AsArray();
        var chain = items[3]!["chain"]!;
        var rule = items[6]!["rule"]!;
        var expr = rule["expr"]!.AsArray();
        switch (mutation)
        {
            case "priority": chain["prio"] = -99; break;
            case "hook": chain["hook"] = "prerouting"; break;
            case "policy": chain["policy"] = "drop"; break;
            case "chain-handle": chain["handle"] = 1; break;
            case "rule-handle": rule["handle"] = 2; break;
            case "absent-chain": items.RemoveAt(3); break;
            case "empty-chain": items.RemoveAt(7); items.RemoveAt(6); break;
            case "unknown-rule-chain": rule["chain"] = "forward"; break;
            case "source-port": expr[1]!["match"]!["left"]!["payload"]!["field"] = "sport"; break;
            case "negated-port": expr[1]!["match"]!["op"] = "!="; break;
            case "service-name": expr[1]!["match"]!["right"] = "https"; break;
            case "translation-range": expr[2]!["dnat"]!["port"] = JsonNode.Parse("""{"range":[443,445]}"""); break;
            case "translation-overflow": expr[2]!["dnat"]!["port"] = 65536; break;
            case "ingress": expr.Insert(0, JsonNode.Parse("""{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}}""")); break;
            default: throw new ArgumentException(nameof(mutation));
        }
        Assert.Null(NftNatTableObservation.Parse(listing.ToJsonString()).Observation);
        Assert.Null(NftNatTableObservation.ParseReplacementEcho(Echo(listing)).Observation);
    }

    // Synthetic numeric listing in the nft JSON ABI; the table and chain handle spaces are independent.
    private static JsonNode NativeListing() => JsonNode.Parse("""
        {"nftables":[
          {"metainfo":{"version":"1.1.7","release_name":"fixture","json_schema_version":1}},
          {"table":{"family":"inet","name":"nergal_nat","handle":1,"comment":"nergal:v1:00000000000000000000000000000010:00000000000000000000000000000020"}},
          {"chain":{"family":"inet","table":"nergal_nat","name":"prerouting","hook":"prerouting","type":"nat","prio":-100,"policy":"accept","handle":1}},
          {"chain":{"family":"inet","table":"nergal_nat","name":"output","hook":"output","type":"nat","prio":-100,"policy":"accept","handle":2}},
          {"chain":{"family":"inet","table":"nergal_nat","name":"postrouting","hook":"postrouting","type":"nat","prio":100,"policy":"accept","handle":3}},
          {"rule":{"family":"inet","table":"nergal_nat","chain":"prerouting","handle":4,"expr":[
            {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"198.51.100.10"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},
            {"dnat":{"family":"ip","addr":"192.0.2.20","port":8443}}]}},
          {"rule":{"family":"inet","table":"nergal_nat","chain":"output","handle":5,"expr":[
            {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"198.51.100.10"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},
            {"dnat":{"family":"ip","addr":"192.0.2.20","port":9443}}]}},
          {"rule":{"family":"inet","table":"nergal_nat","chain":"output","handle":6,"expr":[
            {"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"daddr"}},"right":"2001:db8:1::10"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":53}},
            {"dnat":{"family":"ip6","addr":"2001:db8:2::20"}}]}}
        ]}
        """)!;

    private static string Echo(JsonNode listing)
    {
        var commands = new JsonArray();
        foreach (var entry in listing["nftables"]!.AsArray().Skip(1))
        {
            var command = entry!["table"] is null ? "add" : "create";
            commands.Add(new JsonObject { [command] = entry.DeepClone() });
        }
        return new JsonObject { ["nftables"] = commands }.ToJsonString();
    }
}
