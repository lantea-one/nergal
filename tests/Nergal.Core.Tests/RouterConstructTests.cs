using Nergal.Core.Controller;
using Nergal.Core.Policy;
using Nergal.Nftables;
using Nergal.Testing;
using Xunit;

namespace Nergal.Core.Tests;

/// <summary>Router additions must survive serialization, reject malformed combinations, and preserve caller isolation.</summary>
public sealed class RouterConstructTests
{
    /// <summary>No new matcher or action may disappear during controller/agent serialization.</summary>
    [Fact]
    public void RouterBundle_RoundTripsEveryMatcherAndAction()
    {
        var bundle = new FirewallPolicyBundle(1, RouterPolicySamples.Filter(), RouterPolicySamples.Nat(), RouterPolicySamples.Bridge(),
            new(-5, new(2, FilterVerdict.Accept, FilterVerdict.Accept, FilterVerdict.Accept, [])));
        var candidate = NftPolicyBundleCompiler.Compile(bundle);
        Assert.True(candidate.IsSuccess, string.Join(", ", candidate.Diagnostics));
        var json = PolicyBundleJsonCodec.EncodeBundle(bundle);
        var decoded = PolicyBundleJsonCodec.DecodeBundle(json);
        Assert.True(decoded.IsSuccess, string.Join(", ", decoded.Diagnostics));
        Assert.Equal(candidate.Candidate, NftPolicyBundleCompiler.Compile(decoded.Value!).Candidate);
        Assert.Equal(json, PolicyBundleJsonCodec.EncodeBundle(decoded.Value!));
        Assert.Contains("ether saddr !=", candidate.Candidate);
        Assert.Contains("fib saddr . iif oif == 0 drop", candidate.Candidate);
        Assert.Contains("ip6 daddr timeout", candidate.Candidate);
        Assert.Contains("masquerade", candidate.Candidate);
    }

    /// <summary>Unknown enum keys, dangling negation, impossible MAC hooks, and schema-1 upgrades fail closed.</summary>
    [Theory]
    [InlineData(0, "negation.requiresMatcher")]
    [InlineData(1, "mac.chainMismatch")]
    [InlineData(2, "rateLimit.keyUnknown")]
    [InlineData(3, "router.requiresSchema2")]
    [InlineData(4, "set.duplicate")]
    public void Filter_DeniesUnsupportedCombinations(int scenario, string code)
    {
        var rule = new FilterRule(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Accept);
        rule = scenario switch
        {
            0 => rule with { NegateSource = true },
            1 => rule with { Chain = FilterChainKind.Output, SourceMac = new("02:00:00:00:00:01") },
            2 => rule with { RateLimit = new(1, RateLimitTimeUnit.Second, 1, KeyKind: (RateLimitKeyKind)99) },
            3 => rule with { Verdict = FilterVerdict.Reject },
            _ => rule with { SourceMacs = [new("02:00:00:00:00:01"), new("02:00:00:00:00:01")] },
        };
        var result = NftFilterCompiler.Compile(new(scenario == 3 ? 1 : 2, FilterVerdict.Drop, [rule]));
        Assert.Null(result.Candidate);
        Assert.Contains(result.Diagnostics, d => d.Code == code);
    }

    /// <summary>Reject is a rule action, never a base-chain policy.</summary>
    [Fact]
    public void Filter_DeniesRejectBasePolicyAndInvalidMss()
    {
        Assert.False(NftFilterCompiler.Compile(new(2, FilterVerdict.Reject, [])).IsSuccess);
        Assert.False(NftFilterCompiler.Compile(new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, [], forwardTcpMssClamp: 0)).IsSuccess);
        Assert.False(NftBridgeCompiler.Compile(new(1, FilterVerdict.Reject, [])).IsSuccess);
    }

    /// <summary>NAT exemptions cannot carry an ignored translation target.</summary>
    [Theory]
    [InlineData(NatPostroutingAction.Masquerade)]
    [InlineData(NatPostroutingAction.Return)]
    public void Nat_DeniesConflictingTranslationTarget(NatPostroutingAction action)
    {
        var result = NftNatCompiler.Compile(new(1, [], [new(IpFamily.IPv4, null, "192.0.2.1", Action: action)]));
        Assert.Null(result.Candidate);
        Assert.Contains(result.Diagnostics, d => d.Code == "nat.actionConflictsWithAddress");
    }

    /// <summary>The pure compiler supports targeted replacement but rejects cyclic or missing jump targets.</summary>
    [Fact]
    public void ExtendedBridgeAndAuxiliary_CompileTargetedReplacementAndRejectCycles()
    {
        var identity = new NftTableIdentity(Guid.NewGuid(), Guid.NewGuid());
        var bundle = new FirewallPolicyBundle(1, new(1, FilterVerdict.Drop, []), bridge: RouterPolicySamples.Bridge());
        Assert.True(NftPolicyBundleCompiler.Compile(bundle).IsSuccess);
        var replacement = NftPolicyBundleCompiler.CompileAtomicReplacement(bundle, identity, true, false, true);
        Assert.True(replacement.IsSuccess);
        Assert.Contains("delete table bridge nergal_bridge\n", replacement.Candidate);
        var cycle = new BridgePolicy(1, FilterVerdict.Accept, [], subChains:
            [new("cycle", [new(BridgeEtherType.Any, FilterVerdict.Drop, JumpTarget: "cycle")])]);
        Assert.Contains(NftBridgeCompiler.Compile(cycle).Diagnostics, d => d.Code == "jump.cycleOrDepth");
        var missing = new BridgePolicy(1, FilterVerdict.Accept, [new(BridgeEtherType.Any, FilterVerdict.Drop, JumpTarget: "missing")]);
        Assert.Contains(NftBridgeCompiler.Compile(missing).Diagnostics, d => d.Code == "jump.invalidTarget");
    }

    /// <summary>Caller-owned collections must not alter a previously validated policy.</summary>
    [Fact]
    public void Policy_SnapshotsNestedMatcherCollections()
    {
        var macs = new List<MacAddress> { new("02:00:00:00:00:01"), new("02:00:00:00:00:03") };
        var ports = new List<int> { 443, 9001 };
        var filter = new FilterPolicy(2, FilterVerdict.Drop, [new(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Accept, SourceMacs: macs)]);
        var nat = new NatPolicy(1, [], [new(IpFamily.IPv4, null, null, Action: NatPostroutingAction.Masquerade, Protocol: FilterProtocol.Tcp, DestinationPorts: ports)]);
        var before = NftPolicyBundleCompiler.Compile(new(1, filter, nat)).Candidate;
        macs.Clear(); ports.Clear();
        Assert.Equal(before, NftPolicyBundleCompiler.Compile(new(1, filter, nat)).Candidate);
    }

    /// <summary>Malformed and unknown MAC/boolean/enum values cannot be silently ignored.</summary>
    [Theory]
    [InlineData("\"sourceMac\":\"02:00:00:00:00:01\"", "\"sourceMac\":\"bad\"")]
    [InlineData("\"negateSourceMac\":true", "\"negateSourceMac\":\"true\"")]
    [InlineData("\"keyKind\":\"destinationAddress\"", "\"keyKind\":\"unknown\"")]
    public void Json_DeniesInvalidRouterFields(string from, string to)
    {
        var json = PolicyBundleJsonCodec.EncodeBundle(new(1, RouterPolicySamples.Filter()), false);
        Assert.Contains(from, json);
        Assert.False(PolicyBundleJsonCodec.DecodeBundle(json.Replace(from, to, StringComparison.Ordinal)).IsSuccess);
    }

    /// <summary>Recorded native samples test complete reconstruction, stable echo/list fingerprints, and semantic drift.</summary>
    [Fact]
    public void NativeObservation_RoundTripsAndDetectsRouterDrift()
    {
        static string Read(string filename)
        {
            var assembly = typeof(RouterConstructTests).Assembly;
            using var stream = assembly.GetManifestResourceStream(assembly.GetManifestResourceNames().Single(n => n.EndsWith(filename, StringComparison.Ordinal)))!;
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd();
        }
        var original = Read("filter-list.json");
        var observed = NftTableObservation.Parse(original);
        Assert.True(observed.IsSuccess);
        var echoed = NftTableObservation.ParseReplacementEcho(Read("filter-echo.json"));
        Assert.Equal(observed.Observation!.StateDigest, echoed.Observation!.StateDigest);
        Assert.Equal(NftFilterCompiler.Compile(RouterPolicySamples.Filter(), observed.Observation.Identity).Candidate,
            NftFilterCompiler.Compile(observed.Observation.Policy, observed.Observation.Identity).Candidate);
        var changedMss = NftTableObservation.Parse(original.Replace("1360", "1361", StringComparison.Ordinal));
        Assert.True(changedMss.IsSuccess);
        Assert.NotEqual(observed.Observation.StateDigest, changedMss.Observation!.StateDigest);
        var changedMac = NftTableObservation.Parse(original.Replace("02:00:00:00:00:01", "02:00:00:00:00:09", StringComparison.Ordinal));
        Assert.True(changedMac.IsSuccess);
        Assert.NotEqual(observed.Observation.StateDigest, changedMac.Observation!.StateDigest);
        Assert.False(NftTableObservation.Parse(original.Replace("admin-prohibited", "port-unreachable", StringComparison.Ordinal)).IsSuccess);
        var nat = NftNatTableObservation.Parse(Read("nat-list.json"));
        Assert.True(nat.IsSuccess);
        Assert.Equal(nat.Observation!.StateDigest, NftNatTableObservation.ParseReplacementEcho(Read("nat-echo.json")).Observation!.StateDigest);
    }

    /// <summary>Refresh intent survives strict serialization, requires its semantic capability and preserves legacy defaults.</summary>
    [Fact]
    public void MeterRefresh_CodecRequiresExplicitBooleanAndCapability()
    {
        var filter = new FilterPolicy(2, FilterVerdict.Drop, [new(IpFamily.IPv4, FilterProtocol.Udp, FilterVerdict.Accept,
            DestinationPort: 53, RateLimit: new(1, RateLimitTimeUnit.Second, 1, RefreshEntryTimeout: true))]);
        var json = PolicyBundleJsonCodec.EncodeBundle(new(1, filter));
        Assert.Contains("refreshEntryTimeout", json);
        Assert.True(PolicyBundleJsonCodec.DecodeBundle(json).Value!.Filter.Rules[0]!.RateLimit!.RefreshEntryTimeout);
        Assert.Contains(Nergal.Core.FirewallFeature.MeterEntryTimeoutRefresh, filter.GetRequiredFeatures());
        Assert.False(PolicyBundleJsonCodec.DecodeBundle(json.Replace("\"refreshEntryTimeout\": true", "\"refreshEntryTimeout\": \"true\"", StringComparison.Ordinal)).IsSuccess);
        var legacy = filter.Rules[0]! with { RateLimit = filter.Rules[0]!.RateLimit! with { RefreshEntryTimeout = false } };
        Assert.DoesNotContain("refreshEntryTimeout", PolicyBundleJsonCodec.EncodeBundle(new(1, new(2, FilterVerdict.Drop, [legacy]))));
    }

    /// <summary>Stored settings corruption must not silently reset security-related intent.</summary>
    [Theory]
    [InlineData("null")]
    [InlineData("{\"branding\":null}")]
    [InlineData("{\"unknown\":true}")]
    [InlineData("{\"branding\":{},\"branding\":{}}")]
    public void Settings_RejectsMalformedSnapshots(string json)
    {
        Assert.Throws<System.Text.Json.JsonException>(() => SystemSettingsCodec.Deserialize(json));
    }
}
