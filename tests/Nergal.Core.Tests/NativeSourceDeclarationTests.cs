using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Contextual source partitioning preserves every node without granting conversion or execution authority.</summary>
public sealed class NativeSourceDeclarationTests
{
    /// <summary>Supported block heads retain original names, scopes and opaque object bodies.</summary>
    [Fact]
    public void Blocks_RetainContextAndEveryOriginalNode()
    {
        const string source = """
            # retained
            table inet "sample" {
                comment "metadata";
                set addresses { type ipv4_addr; elements = { 192.0.2.1 }; }
                map ports { type inet_service : verdict; }
                counter hits { packets 0 bytes 0; }
                quota budget { over 1 mbytes; }
                flowtable fast { hook ingress priority 0; devices = { "eth0" }; }
                chain input {
                    type filter hook input priority 0; policy drop;
                    ip saddr { 192.0.2.1, 192.0.2.2 } accept
                    counter jump next
                }
                chain next { return; }
            }
            table fallback { chain output {} }
            """;
        var analysis = NativeSourceAnalyzer.Analyze(source);
        var declarations = analysis.Declarations!;
        Assert.Same(analysis.Structure.Tree, declarations.Structure);
        Assert.Equal(2, declarations.TableCount);
        Assert.Equal(3, declarations.ChainCount);
        Assert.Empty(declarations.Diagnostics);
        CheckPartition(declarations.Structure.Nodes, declarations.Statements);
        var table = declarations.Statements.First(n => n.Kind == NativeSourceStatementKind.Table);
        var document = declarations.Structure.Document;
        Assert.Equal("\"sample\"", document.GetText(table.NameTokenIndex!.Value));
        Assert.Equal("inet", document.GetText(table.FamilyTokenIndex!.Value));
        Assert.Null(declarations.Statements.Last(n => n.Kind == NativeSourceStatementKind.Table).FamilyTokenIndex);
        foreach (var kind in new[] { NativeSourceStatementKind.Set, NativeSourceStatementKind.Map, NativeSourceStatementKind.Counter,
            NativeSourceStatementKind.Quota, NativeSourceStatementKind.Flowtable })
        {
            var item = Assert.Single(table.Children, n => n.Kind == kind);
            Assert.NotNull(item.Body);
            Assert.Empty(item.Children);
        }
        var chain = table.Children.First(n => n.Kind == NativeSourceStatementKind.Chain);
        Assert.Equal(new[] { NativeSourceStatementKind.ChainProperty, NativeSourceStatementKind.ChainProperty,
            NativeSourceStatementKind.Rule, NativeSourceStatementKind.Rule }, chain.Children.Where(n => n.Kind != NativeSourceStatementKind.Trivia).Select(n => n.Kind));
        Assert.False(analysis.Review.CanConvert);
    }

    /// <summary>Directives and dangerous native commands remain private raw data; includes are never opened.</summary>
    [Fact]
    public void DirectivesAndCommands_RetainCompleteExpressionsWithoutExecution()
    {
        const string source = "define addresses = { 192.0.2.1, 192.0.2.2 }; redefine addresses = { 198.51.100.1 };\nundefine addresses\ninclude \"/never/open/private/*.conf\"\nflush ruleset\nadd table inet sample\n";
        var analysis = NativeSourceAnalyzer.Analyze(source);
        var declarations = analysis.Declarations!;
        Assert.Equal(new[] { NativeSourceStatementKind.Define, NativeSourceStatementKind.Redefine, NativeSourceStatementKind.Undefine,
            NativeSourceStatementKind.Include, NativeSourceStatementKind.Command, NativeSourceStatementKind.Command }, declarations.Statements.Select(n => n.Kind));
        Assert.Equal(0, declarations.TableCount);
        Assert.Equal(0, declarations.ChainCount);
        CheckPartition(declarations.Structure.Nodes, declarations.Statements);
        Assert.Contains(analysis.Review.Signals, s => s.Code == "source.includes");
        Assert.Contains(analysis.Review.Signals, s => s.Code == "scope.flush");
        Assert.DoesNotContain("private", System.Text.Json.JsonSerializer.Serialize(analysis.Review));
        Assert.False(analysis.Review.CanConvert);
    }

    /// <summary>Newlines before bodies, adjacent blocks, and anonymous expression groups preserve statement boundaries.</summary>
    [Fact]
    public void Boundaries_DistinguishNamedBlocksFromAnonymousRuleExpressions()
    {
        const string source = "table inet sample\r\n# between\r\n{ chain first\n{ ip saddr { 192.0.2.1 } accept; counter accept\n}chain second{} }table other{}\n";
        var analysis = NativeSourceAnalyzer.Analyze(source);
        Assert.Equal(2, analysis.Review.TableDeclarations);
        Assert.Equal(2, analysis.Review.ChainDeclarations);
        var declarations = analysis.Declarations!;
        CheckPartition(declarations.Structure.Nodes, declarations.Statements);
        var first = declarations.Statements.First().Children.First(n => n.Kind == NativeSourceStatementKind.Chain);
        Assert.Equal(2, first.Children.Count(n => n.Kind == NativeSourceStatementKind.Rule));
        Assert.Equal(4, first.Children.First(n => n.Kind == NativeSourceStatementKind.Rule).HeadSpan.Line);
    }

    /// <summary>Keywords in raw expressions or illegal contexts cannot inflate declaration counts.</summary>
    [Theory]
    [InlineData("define x = table inet fake { chain fake {} }", 0, 0)]
    [InlineData("table future sample { chain hidden {} }", 0, 0)]
    [InlineData("chain outside {}", 0, 0)]
    [InlineData("table inet sample { set objects { chain hidden {} } chain input { table inet hidden { chain hidden {} } } }", 1, 1)]
    [InlineData("table inet sample; { chain hidden {} }", 0, 0)]
    public void Counts_RequireContextualBlockHeaders(string source, int tables, int chains)
    {
        var analysis = NativeSourceAnalyzer.Analyze(source);
        Assert.Equal(tables, analysis.Review.TableDeclarations);
        Assert.Equal(chains, analysis.Review.ChainDeclarations);
        CheckPartition(analysis.Structure.Tree!.Nodes, analysis.Declarations!.Statements);
        Assert.False(analysis.Review.CanConvert);
    }

    /// <summary>Unknown heads remain ordered gaps with immutable, value-free diagnostics.</summary>
    [Fact]
    public void Unknowns_CannotDisappearOrLeakPrivateValues()
    {
        var analysis = NativeSourceAnalyzer.Analyze("# comment\r\nprivate_future value\nunknown_again; table inet sample { future_property secret; }\n");
        var declarations = analysis.Declarations!;
        Assert.Equal(new[] { 2, 3, 3 }, declarations.Diagnostics.Select(d => d.Span.Line));
        Assert.All(declarations.Diagnostics, d => Assert.Equal("source.statementUnclassified", d.Code));
        var signal = Assert.Single(analysis.Review.Signals);
        Assert.Equal("source.unclassifiedStatements", signal.Code);
        Assert.Equal(new[] { 2, 3 }, signal.Lines);
        Assert.DoesNotContain("private_future", signal.ToString());
        Assert.Throws<NotSupportedException>(() => ((IList<NativeSourceStatement>)declarations.Statements).Clear());
        Assert.Throws<NotSupportedException>(() => ((IList<NativeSourceDeclarationDiagnostic>)declarations.Diagnostics).Clear());
        var unknown = declarations.Statements.First();
        Assert.DoesNotContain("private_future", unknown.ToString());
        Assert.Throws<NotSupportedException>(() => ((IList<NativeSourceNode>)unknown.Nodes).Clear());
        Assert.Throws<NotSupportedException>(() => ((IList<NativeSourceStatement>)unknown.Children).Clear());
        CheckPartition(declarations.Structure.Nodes, declarations.Statements);
    }

    /// <summary>Failed structure has no misleading partial declaration catalog; huge trivia remains one bounded partition.</summary>
    [Fact]
    public void FailureAndWidth_DoNotProducePartialOrUnboundedPartitions()
    {
        Assert.Null(NativeSourceAnalyzer.Analyze("table inet sample {]").Declarations);
        Assert.Throws<ArgumentNullException>(() => NativeSourceDeclarationParser.Parse(null!));
        var blank = NativeSourceAnalyzer.Analyze(new string('\n', NativeSourceLexer.MaximumTokens));
        Assert.Equal(NativeSourceStatementKind.Trivia, Assert.Single(blank.Declarations!.Statements).Kind);
        CheckPartition(blank.Structure.Tree!.Nodes, blank.Declarations.Statements);
        var wide = NativeSourceAnalyzer.Analyze(new string('x', 100_000) + string.Concat(Enumerable.Repeat("{}", 30_000)));
        Assert.Equal(NativeSourceStatementKind.Unknown, Assert.Single(wide.Declarations!.Statements).Kind);
        Assert.Single(wide.Declarations.Diagnostics);
    }

    private static void CheckPartition(IReadOnlyList<NativeSourceNode> nodes, IReadOnlyList<NativeSourceStatement> statements)
    {
        var actual = statements.SelectMany(s => s.Nodes).ToArray();
        Assert.Equal(nodes.Count, actual.Length);
        for (var i = 0; i < nodes.Count; i++) { Assert.Same(nodes[i], actual[i]); }
        foreach (var statement in statements)
        {
            var start = statement.Nodes[0].Span;
            var end = statement.Nodes[^1].Span;
            Assert.Equal(start with { Length = end.Offset + end.Length - start.Offset }, statement.Span);
            if (statement.Kind is NativeSourceStatementKind.Table or NativeSourceStatementKind.Chain)
            { CheckPartition(statement.Body!.Children, statement.Children); }
        }
    }
}
