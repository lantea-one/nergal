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
    [InlineData("counter packets 3 bytes 60 accept", "import.counterPlacementUnsupported")]
    [InlineData("log accept", "import.expressionUnsupported")]
    [InlineData("ip saddr $missing accept", "import.definitionUnresolved")]
    [InlineData("ip saddr 192.0.2.1 ip saddr 198.51.100.1 accept", "import.repeatedMatcherUnsupported")]
    [InlineData("ip6 nexthdr tcp accept", "import.addressExpressionUnsupported")]
    [InlineData("iif 2 accept", "import.interfaceIndexUnsupported")]
    [InlineData("udp dport 443 reject with icmpx type host-unreachable", "import.rejectTypeUnsupported")]
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

    /// <summary>Disjoint sets preserve each permitted packet class and adjacent rule order.</summary>
    [Fact]
    public void PositiveEqualitySets_ExpandIntoOrderedDisjointRules()
    {
        var source = Source("""
            table inet sample {
              chain input {
                type filter hook input priority 0; policy drop;
                ip saddr 192.0.2.1 iifname { "edge0", "edge1" } meta l4proto { tcp, udp } th dport 443 accept;
                icmpv6 type { echo-request, nd-neighbor-solicit } accept;
                ip saddr 198.51.100.1 drop;
              }
            }
            """);
        var plan = NativeImportPlanner.Plan(Request(source, new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter)), [source]);

        Assert.True(plan.CanCreateRevision, Codes(plan));
        var rules = PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!.Filter.Rules.Select(r => r!).ToArray();
        Assert.Equal(7, rules.Length);
        Assert.Equal(
            [("edge0", FilterProtocol.Tcp), ("edge0", FilterProtocol.Udp), ("edge1", FilterProtocol.Tcp), ("edge1", FilterProtocol.Udp)],
            rules.Take(4).Select(rule => (rule.InputInterface, rule.Protocol)));
        Assert.All(rules.Take(4), rule => Assert.Equal(443, rule.DestinationPort));
        Assert.Equal(["echo-request", "nd-neighbor-solicit"], rules.Skip(4).Take(2).Select(rule => rule.IcmpType));
        Assert.Equal(FilterVerdict.Drop, rules[^1].Verdict);
        Assert.Equal(3, plan.Mappings.Count(mapping => mapping.Disposition == "rule"));
    }

    /// <summary>Do not split negated sets, shared state, or unguarded transport-header matches.</summary>
    [Theory]
    [InlineData("iifname != { edge0, edge1 } accept", "import.alternativeNegationUnsupported")]
    [InlineData("iifname { edge0, edge1 } udp dport 443 meter bucket { ip saddr timeout 60s limit rate 1/minute burst 1 packets } accept", "import.alternativeStatefulUnsupported")]
    [InlineData("ip saddr 192.0.2.1 iifname { edge0, edge1 } counter accept", "import.alternativeStatefulUnsupported")]
    [InlineData("ip saddr 192.0.2.1 counter udp dport 443 accept", "import.counterPlacementUnsupported")]
    [InlineData("udp dport 443 meter bucket { ip saddr timeout 60s limit rate 1/minute } iifname edge0 accept", "import.meterPlacementUnsupported")]
    [InlineData("th dport 443 accept", "import.transportGuardRequired")]
    [InlineData("meta l4proto { tcp, ipv6-icmp } th dport 443 accept", "import.protocolAlternativesUnsupported")]
    public void UnrepresentableAlternatives_DenyWholeCandidate(string rule, string code)
    {
        var source = Source("table inet sample { chain input { type filter hook input priority 0; " + rule + "; } }");
        var plan = NativeImportPlanner.Plan(Request(source, new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter)), [source]);

        Assert.Contains(plan.Gaps, gap => gap.Code == code);
        Assert.Null(plan.PolicyJson);
    }

    /// <summary>A local DNAT rule stays on output and an inline counter stays on its explicit family.</summary>
    [Fact]
    public void LocalDnatAndScopedCounter_PreserveIntent()
    {
        var source = Source("""
            table inet sample {
              chain input { type filter hook input priority filter; policy drop; ip saddr 192.0.2.1 counter accept; }
            }
            table inet translate {
              chain output {
                type nat hook output priority dstnat; policy accept;
                ip daddr 192.0.2.3 udp dport 443 counter dnat ip to 198.51.100.4:8443;
              }
            }
            """);
        var plan = NativeImportPlanner.Plan(Request(source,
            new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter),
            new NativeImportTableBinding("inet", "translate", NativeImportTableRole.Nat)), [source]);
        Assert.True(plan.CanCreateRevision, Codes(plan));
        var bundle = PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!;
        Assert.True(Assert.Single(bundle.Filter.Rules)!.CountPackets);
        var dnat = Assert.Single(bundle.Nat!.DnatRules)!;
        Assert.Equal(DnatHook.Output, dnat.Hook);
        Assert.True(dnat.CountPackets);
    }

    /// <summary>A family-neutral counted rule compiles once and carries no family selector.</summary>
    [Fact]
    public void DualStackCounter_ProducesOneNativeRule()
    {
        var source = Source("table inet sample { chain input { type filter hook input priority 0; udp dport 443 counter drop; } }");
        var plan = NativeImportPlanner.Plan(Request(source, new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter)), [source]);
        Assert.True(plan.CanCreateRevision, Codes(plan));
        var bundle = PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!;
        var rule = Assert.Single(bundle.Filter.Rules)!;
        Assert.Equal(IpFamily.DualStack, rule.Family);
        Assert.True(rule.CountPackets);
        var candidate = NftFilterCompiler.Compile(bundle.Filter).Candidate!;
        var nativeRule = Assert.Single(candidate.Split('\n'), line => line.StartsWith("add rule ", StringComparison.Ordinal));
        Assert.EndsWith("input meta l4proto udp udp dport 443 counter drop", nativeRule, StringComparison.Ordinal);
    }

    /// <summary>An anonymous counter without a verdict preserves subsequent rule evaluation.</summary>
    [Fact]
    public void CounterOnly_KeepsFollowingVerdictInOrder()
    {
        var source = Source("table inet sample { chain input { type filter hook input priority 0; udp dport 443 counter; udp dport 443 drop; } }");
        var plan = NativeImportPlanner.Plan(Request(source, new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter)), [source]);
        Assert.True(plan.CanCreateRevision, Codes(plan));
        var rules = PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!.Filter.Rules;
        Assert.Equal(3, rules.Count);
        Assert.Equal(FilterVerdict.Continue, rules[0]!.Verdict);
        Assert.True(rules[0]!.CountPackets);
        Assert.All(rules.Skip(1), rule => Assert.Equal(FilterVerdict.Drop, rule!.Verdict));
    }

    /// <summary>Raw output and ordinary output remain distinct and apply tracking only before conntrack.</summary>
    [Fact]
    public void Notrack_RequiresRawHookAndPreservesOutput()
    {
        var source = Source("""
            table inet sample {
              chain early { type filter hook output priority raw; policy accept; oifname "edge0" udp sport 443 notrack; }
              chain normal { type filter hook output priority filter; policy drop; ct state untracked accept; }
            }
            """);
        var binding = new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter);
        var plan = NativeImportPlanner.Plan(Request(source, binding), [source]);
        Assert.True(plan.CanCreateRevision, Codes(plan));
        var rules = PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!.Filter;
        var raw = Assert.Single(rules.RawOutput!.Rules)!;
        Assert.Equal("edge0", raw.OutputInterface);
        Assert.True(raw.Notrack);
        Assert.Equal(FilterVerdict.Drop, rules.OutputDefaultVerdict);
        var misplaced = Source("table inet sample { chain normal { type filter hook output priority 0; udp sport 443 notrack; } }");
        var denied = NativeImportPlanner.Plan(Request(misplaced, binding), [misplaced]);
        Assert.Contains(denied.Gaps, gap => gap.Code == "import.filterActionUnsupported");
        Assert.Null(denied.PolicyJson);
    }

    /// <summary>Named index binding and a dynamic name matcher retain their different native selectors.</summary>
    [Fact]
    public void InterfaceBinding_PreservesNamedIndexSelector()
    {
        var source = Source("table inet sample { chain input { type filter hook input priority 0; iif edge0 accept; iifname edge0 drop; } }");
        var plan = NativeImportPlanner.Plan(Request(source, new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter)), [source]);
        Assert.True(plan.CanCreateRevision, Codes(plan));
        var filter = PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!.Filter;
        Assert.All(filter.Rules.Take(2), rule => Assert.True(rule!.BindInputInterfaceIndex));
        Assert.All(filter.Rules.Skip(2), rule => Assert.False(rule!.BindInputInterfaceIndex));
        var native = NftFilterCompiler.Compile(filter).Candidate!;
        Assert.Contains("iif \"edge0\" accept", native, StringComparison.Ordinal);
        Assert.Contains("iifname \"edge0\" drop", native, StringComparison.Ordinal);
    }

    /// <summary>Route MSS is an ordered, nonterminal forward rule with native routing semantics.</summary>
    [Fact]
    public void RouteMss_KeepsItsPositionBetweenOrdinaryRules()
    {
        const string expression = "tcp flags syn tcp option maxseg size set rt mtu";
        var source = Source("table inet sample { chain forward { type filter hook forward priority 0; ip saddr 192.0.2.1 drop; " +
            expression + "; ip saddr 198.51.100.1 accept; } }");
        var binding = new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter);
        var plan = NativeImportPlanner.Plan(Request(source, binding), [source]);
        Assert.True(plan.CanCreateRevision, Codes(plan));
        var filter = PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!.Filter;
        Assert.Equal([FilterVerdict.Drop, FilterVerdict.ClampRouteMss, FilterVerdict.Accept], filter.Rules.Select(rule => rule!.Verdict));
        var nativeRules = NftFilterCompiler.Compile(filter).Candidate!.Split('\n')
            .Where(line => line.StartsWith("add rule ", StringComparison.Ordinal)).ToArray();
        Assert.EndsWith("forward " + expression, nativeRules[1], StringComparison.Ordinal);

        var input = Source("table inet sample { chain input { type filter hook input priority 0; " + expression + "; } }");
        var denied = NativeImportPlanner.Plan(Request(input, binding), [input]);
        Assert.Contains(denied.Gaps, gap => gap.Code == "import.mssRouteHookUnsupported");
        Assert.Null(denied.PolicyJson);
    }

    /// <summary>An explicit but empty output hook requires a policy representation before import.</summary>
    [Fact]
    public void EmptyOutputNat_DeniesWholeCandidate()
    {
        var source = Source("""
            table inet sample { chain input { type filter hook input priority filter; policy drop; } }
            table inet translate { chain output { type nat hook output priority dstnat; policy accept; } }
            """);
        var plan = NativeImportPlanner.Plan(Request(source,
            new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter),
            new NativeImportTableBinding("inet", "translate", NativeImportTableRole.Nat)), [source]);
        Assert.Contains(plan.Gaps, gap => gap.Code == "import.emptyNatOutputUnsupported");
        Assert.Null(plan.PolicyJson);
    }

    /// <summary>The translation's own family does not restrict an earlier counter.</summary>
    [Fact]
    public void NatCounterWithoutPriorFamily_DeniesWholeCandidate()
    {
        var source = Source("""
            table inet sample { chain input { type filter hook input priority filter; policy drop; } }
            table inet translate {
              chain output {
                type nat hook output priority dstnat; policy accept;
                udp dport 443 counter dnat ip to 192.0.2.3:8443;
              }
            }
            """);
        var plan = NativeImportPlanner.Plan(Request(source,
            new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter),
            new NativeImportTableBinding("inet", "translate", NativeImportTableRole.Nat)), [source]);
        Assert.Contains(plan.Gaps, gap => gap.Code == "import.natCounterFamilyRequired");
        Assert.Null(plan.PolicyJson);
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

    /// <summary>Unmapped, cyclic or non-call control flow blocks every source rule in the candidate.</summary>
    [Theory]
    [InlineData("jump unknown", "return")]
    [InlineData("jump input", "return")]
    [InlineData("return", "return")]
    [InlineData("goto inner", "return")]
    [InlineData("jump inner", "jump inner")]
    [InlineData("jump inner drop", "return")]
    [InlineData("jump inner", "policy drop")]
    public void InvalidFilterCallsBlockConversion(string caller, string body)
    {
        var source = Source("table inet sample { chain input { type filter hook input priority 0; " + caller +
            "; } chain inner { " + body + "; } }");
        var plan = NativeImportPlanner.Plan(Request(source, new NativeImportTableBinding("inet", "sample", NativeImportTableRole.Filter)), [source]);
        Assert.False(plan.CanCreateRevision);
        Assert.Null(plan.PolicyJson);
        Assert.Null(plan.CandidateDigest);
    }

    private static NativeImportRequest Request(NativeSourceSnapshot source, params NativeImportTableBinding[] tables) => new(source.Summary.Id, tables, []);
    private static NativeSourceSnapshot Source(string text)
    {
        var content = new NativeSourceContent("synthetic", text);
        return new(new(Guid.NewGuid(), content.Name, content.Digest, content.ByteLength, "synthetic-actor", DateTimeOffset.UnixEpoch), content);
    }
    private static string Codes(NativeImportPlan plan) => string.Join(", ", plan.Gaps.Select(g => g.Code + "@" + g.Span.Line + ":" + g.Span.Column));
}
