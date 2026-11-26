using Nergal.Core.Controller;
using Nergal.Core.Policy;
using Nergal.Nftables;
using Nergal.Testing;

namespace Nergal.Core.Tests;

/// <summary>Conversion reviews must preserve full scoped intent or expose blocking gaps without a partial candidate.</summary>
public sealed class NativeImportPlannerTests
{
    /// <summary>Literal source names require explicit roles, and family-neutral rules preserve both IP families.</summary>
    [Fact]
    public void DeclarativeFilter_MapsDefaultsOrderAndDualStackWithoutExecutingSource()
    {
        var source = Source("""
            table inet sample {
              chain input { type filter hook input priority filter; policy drop; iifname "lo" accept; }
              chain forward { type filter hook forward priority 0; policy drop; }
              chain output { type filter hook output priority 0; policy accept; }
            }
            """);
        var plan = NativeImportPlanner.Plan(Request(source, new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter)), [source]);
        Assert.True(plan.CanCreateRevision, Codes(plan));
        var policy = PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!;
        Assert.Equal(2, policy.Filter.Rules.Count);
        Assert.Equal(new[] { IpFamily.IPv4, IpFamily.IPv6 }, policy.Filter.Rules.Select(r => r!.Family));
        Assert.Equal(source.Content.Digest, Assert.Single(plan.Sources).Digest);
        Assert.Contains(plan.Mappings, m => m.Disposition == "rule");
        Assert.DoesNotContain("sample", plan.ToString());
        Assert.False(NativeImportPlanner.Plan(new(source.Summary.Id, [], []), [source]).CanCreateRevision);
    }

    /// <summary>Existing generated native syntax re-enters the shared parser with all seven router constructs retained.</summary>
    [Fact]
    public void GeneratedRouterBundle_RoundTripsFullCandidateBytes()
    {
        var bundle = new FirewallPolicyBundle(1, RouterPolicySamples.Filter(), RouterPolicySamples.Nat(), RouterPolicySamples.Bridge(),
            new(-5, new(2, FilterVerdict.Accept, FilterVerdict.Accept, FilterVerdict.Accept, [])));
        var original = NftPolicyBundleCompiler.Compile(bundle);
        Assert.True(original.IsSuccess);
        var source = Source(original.Candidate!);
        var request = Request(source, new NativeImportTableBinding("inet", "nergal_filter", NativeImportTableRole.Filter), new NativeImportTableBinding("inet", "nergal_nat", NativeImportTableRole.Nat),
            new NativeImportTableBinding("inet", "nergal_aux", NativeImportTableRole.Auxiliary), new NativeImportTableBinding("bridge", "nergal_bridge", NativeImportTableRole.Bridge));
        var plan = NativeImportPlanner.Plan(request, [source]);
        Assert.True(plan.CanCreateRevision, Codes(plan));
        var imported = PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!;
        Assert.Equal(original.Candidate, NftPolicyBundleCompiler.Compile(imported).Candidate);
        Assert.Equal(original.Digest!.Value, plan.CandidateDigest);
    }

    /// <summary>Includes bind only uploaded identities and definitions capture prior values in lexical scope.</summary>
    [Fact]
    public void IncludesAndDefinitions_ResolveExplicitSnapshotsAndPreserveOriginalBytes()
    {
        var child = Source("chain input { type filter hook input priority 0; policy drop; ip saddr $host tcp dport $ports accept; }\n");
        var root = Source("define host = 192.0.2.1\ndefine ports = {80,443}\ntable inet sample { include \"/never/open/chains.conf\"; }\n");
        var request = new NativeImportRequest(root.Summary.Id, [new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter)], [new("/never/open/chains.conf", [child.Summary.Id])]);
        var plan = NativeImportPlanner.Plan(request, [root, child]);
        Assert.True(plan.CanCreateRevision, Codes(plan));
        Assert.Equal(2, plan.Sources.Count);
        var table = Assert.Single(plan.Mappings, m => m.Disposition == "table-role");
        Assert.Equal(3, table.Span.Line); Assert.Equal(1, table.Span.Column);
        Assert.Equal(root.Content.Text.IndexOf("table inet", StringComparison.Ordinal), table.Span.Offset);
        var rule = Assert.Single(PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!.Filter.Rules)!;
        Assert.Equal("192.0.2.1/32", rule.Source!.Value);
        Assert.Equal(new[] { 80, 443 }, rule.DestinationPorts);
        Assert.Contains("$ports", child.Content.Text);
        var missing = NativeImportPlanner.Plan(Request(root, new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter)), [root, child]);
        Assert.False(missing.CanCreateRevision);
        Assert.Contains(missing.Gaps, g => g.Code == "import.includeBindingRequired");
    }

    /// <summary>Unknown stateful operations, macros and contexts cannot be approved away or yield a weaker candidate.</summary>
    [Theory]
    [InlineData("counter accept", "import.expressionUnsupported")]
    [InlineData("log accept", "import.expressionUnsupported")]
    [InlineData("ip saddr $missing accept", "import.definitionUnresolved")]
    [InlineData("ip saddr 192.0.2.1 ip saddr 198.51.100.1 accept", "import.repeatedMatcherUnsupported")]
    [InlineData("ip6 nexthdr tcp accept", "import.addressExpressionUnsupported")]
    [InlineData("ip saddr 192.0.2.1 accept log", "import.ruleTrailingInput")]
    public void UnsupportedRule_BlocksWholeCandidate(string rule, string code)
    {
        var source = Source("table inet sample { chain input { type filter hook input priority 0; " + rule + "; } }");
        var plan = NativeImportPlanner.Plan(Request(source, new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter)), [source]);
        Assert.False(plan.CanCreateRevision);
        Assert.Null(plan.PolicyJson); Assert.Null(plan.CandidateDigest); Assert.Empty(plan.Objects);
        Assert.Contains(plan.Gaps, g => g.Code == code);
        Assert.All(plan.Gaps, g => Assert.DoesNotContain("192.0.2", g.ToString()));
    }

    /// <summary>Only explicit managed-resource restriction can account for global flush; it never enters generated text.</summary>
    [Fact]
    public void GlobalFlush_RequiresRecordedScopeRestriction()
    {
        var source = Source("flush ruleset\ntable inet sample { chain input { type filter hook input priority 0; policy drop; } }");
        var mapping = new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter);
        Assert.False(NativeImportPlanner.Plan(Request(source, mapping), [source]).CanCreateRevision);
        var plan = NativeImportPlanner.Plan(new(source.Summary.Id, [mapping], [], true), [source]);
        Assert.True(plan.CanCreateRevision, Codes(plan));
        Assert.Contains(plan.Mappings, m => m.Disposition == "scope-restricted");
        Assert.DoesNotContain("flush", NftPolicyBundleCompiler.Compile(PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!).Candidate!);
        var lateFlush = Source("table inet sample {chain input {type filter hook input priority 0; policy drop;}}\nflush ruleset\n");
        var denied = NativeImportPlanner.Plan(new(lateFlush.Summary.Id, [mapping], [], true), [lateFlush]);
        Assert.False(denied.CanCreateRevision);
        Assert.Contains(denied.Gaps, g => g.Code == "import.flushOrderUnsupported");
    }

    /// <summary>A leading destroy can only describe the replacement of a selected, recreated table.</summary>
    [Fact]
    public void LeadingDestroyOfSelectedTable_PreservesCreateOnlyCandidate()
    {
        const string definition = "table inet sample { chain input { type filter hook input priority 0; policy drop; } }";
        var source = Source($"destroy table inet sample\n{definition}");
        var clean = Source(definition);
        var mapping = new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter);
        var explicitPlan = NativeImportPlanner.Plan(new(source.Summary.Id, [mapping], [], true), [source]);
        var cleanPlan = NativeImportPlanner.Plan(Request(clean, mapping), [clean]);

        Assert.True(explicitPlan.CanCreateRevision, Codes(explicitPlan));
        Assert.Equal(cleanPlan.CandidateDigest, explicitPlan.CandidateDigest);
        Assert.Contains(explicitPlan.Mappings, m => m.Disposition == "scope-restricted" && m.Span.Line == 1);
        var missingConsent = NativeImportPlanner.Plan(Request(source, mapping), [source]);
        Assert.Contains(missingConsent.Gaps, g => g.Code == "import.scopeDecisionRequired");
        Assert.Null(missingConsent.PolicyJson);
    }

    /// <summary>Cleanup cannot discard selected source clauses or touch a foreign target.</summary>
    [Theory]
    [InlineData("destroy table inet foreign\ntable inet sample { chain input { type filter hook input priority 0; policy drop; } }", "import.tableMappingRequired")]
    [InlineData("table inet sample { chain input { type filter hook input priority 0; policy drop; } }\ndestroy table inet sample", "import.destroyOrderUnsupported")]
    [InlineData("destroy table inet sample", "import.tableMappingUnused")]
    [InlineData("destroy chain inet sample input", "import.commandUnsupported")]
    public void UnsafeDestroy_DeniesWholeCandidate(string native, string code)
    {
        var source = Source(native);
        var mapping = new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter);
        var plan = NativeImportPlanner.Plan(new(source.Summary.Id, [mapping], [], true), [source]);

        Assert.Contains(plan.Gaps, g => g.Code == code);
        Assert.Null(plan.PolicyJson);
        Assert.Null(plan.CandidateDigest);
    }

    /// <summary>Named static sets remain pinned references rather than collapsing into anonymous IP-only accepts.</summary>
    [Fact]
    public void NamedSet_ProducesPinnedObjectAndRejectsUnusedOrDynamicOptions()
    {
        var source = Source("table inet sample { set hosts { type ipv4_addr; flags constant,interval; elements = {192.0.2.1,198.51.100.1}; } chain input { type filter hook input priority 0; ip saddr @hosts accept; } }");
        var request = Request(source, new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter));
        var plan = NativeImportPlanner.Plan(request, [source]);
        Assert.True(plan.CanCreateRevision, Codes(plan));
        var reference = Assert.Single(plan.Objects);
        var rule = Assert.Single(PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!.Filter.Rules)!;
        Assert.Equal(reference, rule.SourceObject);
        Assert.Null(rule.Source); Assert.Null(rule.SourcePrefixes);
        Assert.True(reference.NativeSet);
        var unused = Source("table inet sample { set hosts {type ipv4_addr; elements={192.0.2.1};} chain input {type filter hook input priority 0; accept;} }");
        var denied = NativeImportPlanner.Plan(Request(unused, new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter)), [unused]);
        Assert.Contains(denied.Gaps, g => g.Code == "import.unusedObjectUnsupported");
        Assert.False(denied.CanCreateRevision);
    }

    /// <summary>Native meter syntax uses timeout refresh, while explicit add retains creation-based expiry.</summary>
    [Theory]
    [InlineData("60s")]
    [InlineData("1m")]
    public void InlineMeter_PreservesUpdateRatherThanWeakeningToAdd(string duration)
    {
        var source = Source("table inet sample { chain forward { type filter hook forward priority 0; policy drop; udp dport 19001 meter bucket { ip daddr timeout " + duration + " limit rate 1/minute burst 1 packets } accept; } }");
        var plan = NativeImportPlanner.Plan(Request(source, new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter)), [source]);
        Assert.True(plan.CanCreateRevision, Codes(plan));
        var policy = PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!;
        var limit = Assert.Single(policy.Filter.Rules)!.RateLimit!;
        Assert.True(limit.RefreshEntryTimeout);
        Assert.Equal(60, limit.EntryTimeoutSeconds);
        Assert.Contains("update @", NftPolicyBundleCompiler.Compile(policy).Candidate!);
    }

    /// <summary>Source durations that cannot be represented exactly never yield a candidate.</summary>
    [Theory]
    [InlineData("0m")]
    [InlineData("1ms")]
    [InlineData("2147483647m")]
    public void InlineMeter_RejectsUnrepresentableDuration(string duration)
    {
        var source = Source("table inet sample { chain forward { type filter hook forward priority 0; policy drop; udp dport 19001 meter bucket { ip daddr timeout " + duration + " limit rate 1/minute burst 1 packets } accept; } }");
        var plan = NativeImportPlanner.Plan(Request(source, new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter)), [source]);

        Assert.Contains(plan.Gaps, gap => gap.Code == "import.meterTimeoutRequired");
        Assert.Null(plan.PolicyJson);
    }

    /// <summary>Include cycles and missing definitions remain explicit, and callers cannot mutate saved choices/results.</summary>
    [Fact]
    public void ScopeAndCycles_AreBoundedAndChoicesAreImmutable()
    {
        var first = Source("include \"cycle\"\n");
        var request = new NativeImportRequest(first.Summary.Id, [new("inet", "sample", NativeImportTableRole.Filter)], [new("cycle", [first.Summary.Id])]);
        var cycle = NativeImportPlanner.Plan(request, [first]);
        Assert.Contains(cycle.Gaps, g => g.Code == "import.includeCycleOrDepth");
        Assert.Null(cycle.PolicyJson);
        Assert.Throws<NotSupportedException>(() => ((IList<NativeImportTableBinding>)request.Tables).Clear());
        Assert.Throws<NotSupportedException>(() => ((IList<Guid>)request.Includes[0].Sources).Clear());
        Assert.Throws<NotSupportedException>(() => ((IList<NativeImportGap>)cycle.Gaps).Clear());
        var source = Source("define host=192.0.2.1\ndefine alias=$host\nredefine host=198.51.100.1\ntable inet sample { chain input {type filter hook input priority 0; ip saddr $alias accept;} }");
        var plan = NativeImportPlanner.Plan(Request(source, new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter)), [source]);
        Assert.True(plan.CanCreateRevision, Codes(plan));
        Assert.Equal("192.0.2.1/32", Assert.Single(PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!.Filter.Rules)!.Source!.Value);
    }

    /// <summary>Identical relative include literals in different uploaded files must not alias each other's bindings.</summary>
    [Fact]
    public void NestedIncludes_ResolveRelativeLabelsAgainstIncludingSnapshot()
    {
        var first = Source("define alpha = 192.0.2.1\ninclude \"rules.conf\"\n");
        var second = Source("define beta = 198.51.100.1\ninclude \"rules.conf\"\n");
        var input = Source("chain input {type filter hook input priority 0; ip saddr $alpha accept;}\n");
        var output = Source("chain output {type filter hook output priority 0; ip saddr $beta accept;}\n");
        var root = Source("table inet sample { include \"first/*\"; include \"second/*\"; }\n");
        var request = new NativeImportRequest(root.Summary.Id, [new("inet", "sample", NativeImportTableRole.Filter)],
            [new("first/*", [first.Summary.Id]), new("second/*", [second.Summary.Id]),
             new("rules.conf", [input.Summary.Id], first.Summary.Id), new("rules.conf", [output.Summary.Id], second.Summary.Id)]);
        var plan = NativeImportPlanner.Plan(request, [root, first, second, input, output]);
        Assert.True(plan.CanCreateRevision, Codes(plan));
        var rules = PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!.Filter.Rules;
        Assert.Equal("192.0.2.1/32", rules.Single(r => r!.Chain == FilterChainKind.Input)!.Source!.Value);
        Assert.Equal("198.51.100.1/32", rules.Single(r => r!.Chain == FilterChainKind.Output)!.Source!.Value);
        Assert.Equal(5, plan.Sources.Count);
    }

    private static NativeImportRequest Request(NativeSourceSnapshot source, params NativeImportTableBinding[] tables) => new(source.Summary.Id, tables, []);
    private static NativeSourceSnapshot Source(string text)
    {
        var content = new NativeSourceContent("synthetic", text);
        return new(new(Guid.NewGuid(), content.Name, content.Digest, content.ByteLength, "synthetic-actor", DateTimeOffset.UnixEpoch), content);
    }
    private static string Codes(NativeImportPlan plan) => string.Join(", ", plan.Gaps.Select(g => g.Code + "@" + g.Span.Line + ":" + g.Span.Column));
}
