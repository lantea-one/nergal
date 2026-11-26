using System.Text.Json.Nodes;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>IPv6 hop-limit equality and one rule-local token bucket survive every policy and receipt boundary.</summary>
public sealed class HopLimitPacketRateTests
{
    private static readonly FilterRule Rule = new(IpFamily.IPv6, FilterProtocol.Any, FilterVerdict.Accept,
        Ipv6HopLimit: 255, PacketLimit: new(4, RateLimitTimeUnit.Minute, 2));

    /// <summary>Endpoints, rule identity, capabilities and disabled settings survive canonical JSON and edits.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(255)]
    public void RuleRoundTripsWithBucketAndExactHop(int hop)
    {
        var rule = Rule with { Ipv6HopLimit = (byte)hop };
        var bundle = new FirewallPolicyBundle(1, new(2, FilterVerdict.Drop, [rule]));
        var copy = PolicyBundleJsonCodec.DecodeBundle(PolicyBundleJsonCodec.EncodeBundle(bundle)).Value!;
        Assert.Equal(rule, Assert.Single(copy.Filter.Rules));
        Assert.Contains(FirewallFeature.Ipv6HopLimit, copy.Filter.GetRequiredFeatures());
        Assert.Contains(FirewallFeature.RulePacketRateLimiting, copy.Filter.GetRequiredFeatures());
        var text = NftFilterCompiler.Compile(copy.Filter).Candidate!;
        Assert.Contains($"ip6 hoplimit {hop} limit rate 4/minute burst 2 packets accept", text);
        var disabled = PolicyRuleStates.SetEnabled(copy, PolicyRuleScope.Filter, 0, null, false);
        Assert.DoesNotContain("limit rate", NftFilterCompiler.Compile(disabled.Filter).Candidate!);
        Assert.Equal(rule with { Enabled = false }, Assert.Single(disabled.Filter.Rules));
    }

    /// <summary>Fail closed for unsupported schemas, families, colliding bucket semantics, bounds and oversized receipts.</summary>
    [Fact]
    public void InvalidOrUnobservableRulesBlockEntireCandidate()
    {
        foreach (var invalid in new[] {
            Rule with { Family = IpFamily.IPv4 }, Rule with { Family = IpFamily.DualStack },
            Rule with { RateLimit = new(4, RateLimitTimeUnit.Minute, 2) },
            Rule with { PacketLimit = new(0, RateLimitTimeUnit.Minute, 1) },
            Rule with { PacketLimit = new(1_000_001, RateLimitTimeUnit.Minute, 1) },
            Rule with { PacketLimit = new(1, (RateLimitTimeUnit)42, 1) },
            Rule with { PacketLimit = new(1, RateLimitTimeUnit.Second, 0) },
            Rule with { PacketLimit = new(1, RateLimitTimeUnit.Second, 10_001) },
        })
        {
            Assert.Null(NftFilterCompiler.Compile(new(2, FilterVerdict.Drop, [Rule, invalid with { Enabled = false }])).Candidate);
        }
        Assert.Null(NftFilterCompiler.Compile(new(1, FilterVerdict.Drop, [Rule])).Candidate);
        var oversized = NftFilterCompiler.Compile(new(2, FilterVerdict.Drop, Enumerable.Repeat(Rule, 700)));
        Assert.Null(oversized.Candidate);
        Assert.Contains(oversized.Diagnostics, d => d.Code == "packetMatcher.nativeObservationTooLarge");
    }

    /// <summary>Reject invalid JSON values and unknown bucket properties even on disabled rules.</summary>
    [Theory]
    [InlineData("ipv6HopLimit", "256")]
    [InlineData("ipv6HopLimit", "-1")]
    [InlineData("ipv6HopLimit", "null")]
    [InlineData("ipv6HopLimit", "\"64\"")]
    [InlineData("packetLimit", "{}")]
    [InlineData("packetLimit", """{"packetsPerWindow":1,"windowUnit":"second","burst":1,"keyKind":"sourceAddress"}""")]
    [InlineData("packetLimit", """{"packetsPerWindow":1,"windowUnit":"second","burst":0}""")]
    public void MalformedPolicyHasNoPartialResult(string field, string value)
    {
        var json = JsonNode.Parse(PolicyBundleJsonCodec.EncodeBundle(new(1, new(2, FilterVerdict.Drop, [Rule with { Enabled = false }]))))!;
        json["filter"]!["rules"]![0]![field] = JsonNode.Parse(value);
        Assert.Null(PolicyBundleJsonCodec.DecodeBundle(json.ToJsonString()).Value);
    }

    /// <summary>Valid drift changes the digest. Unrecognized expressions and stateful reordering deny echo and listing alike.</summary>
    [Theory]
    [InlineData("hop", true)]
    [InlineData("rate", true)]
    [InlineData("unit", true)]
    [InlineData("burst", true)]
    [InlineData("removedBucket", true)]
    [InlineData("handle", true)]
    [InlineData("overflow", false)]
    [InlineData("negation", false)]
    [InlineData("wrongHeader", false)]
    [InlineData("rateBeforeMatch", false)]
    [InlineData("duplicateBucket", false)]
    [InlineData("missingBurst", false)]
    [InlineData("byteRate", false)]
    [InlineData("inverted", false)]
    public void NativeEvidenceBindsTheCompleteRule(string change, bool valid)
    {
        var assembly = typeof(HopLimitPacketRateTests).Assembly;
        using var stream = assembly.GetManifestResourceStream(assembly.GetManifestResourceNames().Single(n => n.EndsWith("hop-rate-list.json", StringComparison.Ordinal)))!;
        using var reader = new StreamReader(stream);
        var original = reader.ReadToEnd();
        var expected = NftTableObservation.Parse(original).Observation!;
        Assert.Equal(Rule, Assert.Single(expected.Policy.Rules));
        var root = JsonNode.Parse(original)!;
        var items = root["nftables"]!.AsArray();
        var rule = items.Single(item => item!["rule"] is not null)!["rule"]!;
        var expressions = rule["expr"]!.AsArray();
        var hop = expressions[0]!["match"]!;
        var limit = expressions[1]!["limit"]!.AsObject();
        switch (change)
        {
            case "hop": hop["right"] = 64; break;
            case "rate": limit["rate"] = 5; break;
            case "unit": limit["per"] = "second"; break;
            case "burst": limit["burst"] = 3; break;
            case "removedBucket": expressions.RemoveAt(1); break;
            case "handle": rule["handle"] = 99; break;
            case "overflow": hop["right"] = 256; break;
            case "negation": hop["op"] = "!="; break;
            case "wrongHeader": hop["left"]!["payload"]!["protocol"] = "ip"; break;
            case "rateBeforeMatch":
                var bucket = expressions[1];
                expressions.RemoveAt(1);
                expressions.Insert(0, bucket);
                break;
            case "duplicateBucket": expressions.Insert(1, expressions[1]!.DeepClone()); break;
            case "missingBurst": limit.Remove("burst"); break;
            case "byteRate": limit["rate_unit"] = "bytes"; break;
            case "inverted": limit["inv"] = true; break;
        }
        var listing = NftTableObservation.Parse(root.ToJsonString());
        var commands = items.Skip(1).Select(i => new JsonObject { [i!["table"] is null ? "add" : "create"] = i.DeepClone() });
        var echo = NftTableObservation.ParseReplacementEcho(new JsonObject { ["nftables"] = new JsonArray(commands.ToArray<JsonNode?>()) }.ToJsonString());
        Assert.Equal(valid, listing.IsSuccess);
        Assert.Equal(valid, echo.IsSuccess);
        if (valid)
        {
            Assert.Equal(listing.Observation!.StateDigest, echo.Observation!.StateDigest);
            Assert.NotEqual(expected.StateDigest, listing.Observation.StateDigest);
        }
    }
}
