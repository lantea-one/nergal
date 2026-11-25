using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Whole-rule parsing cannot turn a recognized prefix into a weakened policy.</summary>
public sealed class NativeRuleExpressionTests
{
    /// <summary>Ordered predicates preserve MAC+IP pinning, repeats, negation, protocol fields and exact source identity.</summary>
    [Fact]
    public void CompleteRule_RetainsOrderedTypedPredicatesAndProvenance()
    {
        var analysis = Analyze("ether saddr 02:00:00:00:00:01 ip saddr != { 192.0.2.0/24, 198.51.100.2 } ip saddr 203.0.113.1 meta iifname != \"lo\" tcp dport == { 80, 443 } udp sport 68 reject with icmpx type admin-prohibited");
        var catalog = analysis.Rules!;
        Assert.Same(analysis.Declarations, catalog.Declarations);
        var entry = Assert.Single(catalog.Entries);
        var rule = Assert.IsType<NativeParsedRule>(entry.Rule);
        Assert.Same(entry.Statement, rule.Statement);
        Assert.Null(entry.Diagnostic);
        Assert.Equal(new[] { NativeRuleField.EtherSource, NativeRuleField.IpSource, NativeRuleField.IpSource,
            NativeRuleField.InputInterface, NativeRuleField.TcpDestinationPort, NativeRuleField.UdpSourcePort }, rule.Matches.Select(m => m.Field));
        Assert.Equal(NativeRuleVerdict.RejectAdminProhibited, rule.Verdict);
        Assert.True(rule.Matches[1].Negated);
        Assert.True(rule.Matches[3].Negated);
        Assert.False(rule.Matches[4].Negated);
        Assert.Equal("02:00:00:00:00:01", Assert.IsType<NativeMacLiteral>(rule.Matches[0].Values[0]).Address.Value);
        Assert.Equal("198.51.100.2/32", Assert.IsType<NativeAddressLiteral>(rule.Matches[1].Values[1]).Prefix.Value);
        Assert.Equal("lo", Assert.IsType<NativeInterfaceLiteral>(rule.Matches[3].Values[0]).Name);
        Assert.Equal((ushort)443, Assert.IsType<NativePortLiteral>(rule.Matches[4].Values[1]).Port);
        var document = analysis.Lexical.Document!;
        Assert.Equal("tcp dport == { 80, 443 }", Slice(document, rule.Matches[4].Span));
        Assert.Equal("reject with icmpx type admin-prohibited", Slice(document, rule.VerdictSpan));
        Assert.False(analysis.Review.CanConvert);
    }

    /// <summary>Both IP families, both MAC directions, all transport fields and bridge metadata remain typed without family inference.</summary>
    [Theory]
    [InlineData("ip daddr 192.0.2.1 accept", NativeRuleField.IpDestination)]
    [InlineData("ip6 saddr 2001:db8::/32 drop", NativeRuleField.Ip6Source)]
    [InlineData("ip6 daddr 2001:db8::1 return", NativeRuleField.Ip6Destination)]
    [InlineData("ether daddr != { 02:00:00:00:00:01, 02:00:00:00:00:02 } drop", NativeRuleField.EtherDestination)]
    [InlineData("tcp sport 0 accept", NativeRuleField.TcpSourcePort)]
    [InlineData("udp dport 65535 drop", NativeRuleField.UdpDestinationPort)]
    [InlineData("oifname uplink0 return", NativeRuleField.OutputInterface)]
    [InlineData("meta ibrname \"bridge0\" accept", NativeRuleField.InputBridge)]
    [InlineData("obrname bridge1 drop", NativeRuleField.OutputBridge)]
    public void Fields_DoNotLoseDirectionOrSourceMeaning(string source, NativeRuleField field)
    {
        var rule = Assert.IsType<NativeParsedRule>(Assert.Single(Analyze(source).Rules!.Entries).Rule);
        Assert.Equal(field, Assert.Single(rule.Matches).Field);
    }

    /// <summary>Unsupported expressions, unresolved references and suffixes deny the whole rule, including previously parsed matchers.</summary>
    [Theory]
    [InlineData("ip saddr 192.0.2.1 counter accept", "source.ruleExpressionUnsupported")]
    [InlineData("ip saddr 192.0.2.1 accept log", "source.ruleTrailingInput")]
    [InlineData("accept drop", "source.ruleTrailingInput")]
    [InlineData("ip saddr $addresses accept", "source.ruleReferenceUnresolved")]
    [InlineData("ip saddr @addresses accept", "source.ruleReferenceUnresolved")]
    [InlineData("tcp dport http accept", "source.ruleLiteralUnsupported")]
    [InlineData("tcp dport 80-90 accept", "source.ruleLiteralUnsupported")]
    [InlineData("iifname \"eth*\" accept", "source.ruleLiteralUnsupported")]
    [InlineData("iifname \"eth\\x30\" accept", "source.ruleLiteralUnsupported")]
    [InlineData("iifname 'lo' accept", "source.ruleLiteralUnsupported")]
    [InlineData("tcp dport 65536 accept", "source.ruleLiteralUnsupported")]
    [InlineData("tcp dport 010 accept", "source.ruleLiteralUnsupported")]
    [InlineData("ip saddr 127.1 accept", "source.ruleLiteralUnsupported")]
    [InlineData("ip saddr 192.0.2.001 accept", "source.ruleLiteralUnsupported")]
    [InlineData("ip saddr 192.0.2.1/24 accept", "source.ruleLiteralUnsupported")]
    [InlineData("ip saddr 2001:db8::1 accept", "source.ruleLiteralUnsupported")]
    [InlineData("ip6 saddr ::ffff:192.0.2.1 accept", "source.ruleLiteralUnsupported")]
    [InlineData("ip6 saddr fe80::1%eth0 accept", "source.ruleLiteralUnsupported")]
    [InlineData("ether saddr 02:00:00:00:00 accept", "source.ruleLiteralUnsupported")]
    [InlineData("ip saddr {} accept", "source.ruleSetUnsupported")]
    [InlineData("ip saddr { 192.0.2.1, } accept", "source.ruleSetUnsupported")]
    [InlineData("ip saddr { 192.0.2.1; } accept", "source.ruleSetUnsupported")]
    [InlineData("ip saddr { 192.0.2.1 192.0.2.2 } accept", "source.ruleSetUnsupported")]
    [InlineData("reject", "source.ruleVerdictUnsupported")]
    [InlineData("reject with icmp type port-unreachable", "source.ruleVerdictUnsupported")]
    [InlineData("jump target", "source.ruleExpressionUnsupported")]
    [InlineData("tcp dport 80", "source.ruleVerdictRequired")]
    [InlineData("ip saddr !=", "source.ruleValueRequired")]
    public void Failure_ExposesNoPartialRule(string source, string code)
    {
        var analysis = Analyze(source);
        var entry = Assert.Single(analysis.Rules!.Entries);
        Assert.Null(entry.Rule);
        Assert.Equal(code, entry.Diagnostic!.Code);
        Assert.Equal(0, analysis.RuleParsing.ParsedRules);
        Assert.Equal(1, analysis.RuleParsing.TotalRules);
        Assert.Contains(analysis.Review.Signals, s => s.Code == "source.unparsedRules");
        Assert.False(analysis.Review.CanConvert);
        Assert.DoesNotContain("192.0.2", entry.Diagnostic.ToString());
    }

    /// <summary>Physical diagnostics and immutable summaries remain safe while later rules retain their own source order.</summary>
    [Fact]
    public void Catalog_RetainsFailuresAndExactPositionsWithoutValues()
    {
        var analysis = NativeSourceAnalyzer.Analyze("table inet sample { chain input {\r\n  ip saddr 192.0.2.1 \\\r\n    counter accept\r\n  return\r\n} }");
        var catalog = analysis.Rules!;
        Assert.Equal(2, catalog.Entries.Count);
        var failure = catalog.Entries[0].Diagnostic!;
        Assert.Equal(3, failure.Span.Line);
        Assert.Equal(5, failure.Span.Column);
        Assert.Equal(NativeRuleVerdict.Return, catalog.Entries[1].Rule!.Verdict);
        Assert.Equal(1, catalog.Summary.ParsedRules);
        var json = System.Text.Json.JsonSerializer.Serialize(catalog.Summary);
        Assert.DoesNotContain("192.0.2", json);
        Assert.DoesNotContain("sample", json);
        Assert.DoesNotContain("counter", json);
        Assert.Throws<NotSupportedException>(() => ((IList<NativeRuleParseEntry>)catalog.Entries).Clear());
        Assert.Throws<NotSupportedException>(() => ((IList<NativeRuleDiagnostic>)catalog.Summary.Diagnostics).Clear());
        var parsed = Analyze("ip saddr 192.0.2.1 accept").Rules!.Entries[0].Rule!;
        Assert.Throws<NotSupportedException>(() => ((IList<NativeRuleMatch>)parsed.Matches).Clear());
        Assert.Throws<NotSupportedException>(() => ((IList<NativeRuleLiteral>)parsed.Matches[0].Values).Clear());
        Assert.DoesNotContain("192.0.2", parsed.ToString());
        Assert.DoesNotContain("192.0.2", parsed.Matches[0].Values[0].ToString());
    }

    /// <summary>Inclusive limits reject excess input without truncating predicates or elements.</summary>
    [Fact]
    public void Limits_AreInclusiveAndDoNotTruncate()
    {
        var allowed = string.Concat(Enumerable.Repeat("ip saddr 192.0.2.1 ", NativeRuleExpressionParser.MaximumPredicates));
        Assert.Equal(NativeRuleExpressionParser.MaximumPredicates, Analyze(allowed + "accept").Rules!.Entries[0].Rule!.Matches.Count);
        Assert.Equal("source.rulePredicateLimit", Analyze(allowed + "ip saddr 192.0.2.1 accept").Rules!.Entries[0].Diagnostic!.Code);
        var values = Enumerable.Range(0, NativeRuleExpressionParser.MaximumSetElements).Select(n => (1000 + n).ToString(System.Globalization.CultureInfo.InvariantCulture));
        var ports = string.Join(",", values);
        Assert.Equal(NativeRuleExpressionParser.MaximumSetElements, Analyze("tcp dport {" + ports + "} accept").Rules!.Entries[0].Rule!.Matches[0].Values.Count);
        Assert.Equal("source.ruleSetLimit", Analyze("tcp dport {" + ports + ",9999} accept").Rules!.Entries[0].Diagnostic!.Code);
        var failed = NativeSourceAnalyzer.Analyze("table inet sample {]");
        Assert.Null(failed.Rules);
        Assert.False(failed.RuleParsing.IsAvailable);
        Assert.Equal(0, failed.RuleParsing.TotalRules);
        Assert.Empty(failed.RuleParsing.Diagnostics);
        Assert.Throws<ArgumentNullException>(() => NativeRuleExpressionParser.Parse(null!));
    }

    private static NativeSourceAnalysis Analyze(string rule) => NativeSourceAnalyzer.Analyze("table inet sample { chain input { " + rule + "; } }");
    private static string Slice(NativeSourceDocument document, NativeSourceSpan span) => document.Source.Substring(span.Offset, span.Length);
}
