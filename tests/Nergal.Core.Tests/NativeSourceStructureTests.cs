using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Structural accounting retains exact source order and rejects incomplete or excessive nesting without partial results.</summary>
public sealed class NativeSourceStructureTests
{
    /// <summary>Every original token is covered exactly once, including unknown syntax, nested sets, expressions, comments and continuations.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("\ufeff# comment\r\ninclude \"/not/opened/[missing\"\rdefine x = { 1, 2 }\nunknown [a (b) { c }] \\\n token;\n")]
    [InlineData("table inet sample { chain input { type filter hook input priority 0; ip saddr { 192.0.2.1, 192.0.2.2 } counter accept; } }")]
    [InlineData("create table inet sample\nadd chain inet sample input { type filter hook input priority 0; policy drop; }\n")]
    [InlineData("\"{[)\" '}}}' $counter @lookup # ( unmatched comment\n")]
    public void CompleteStructure_CoversEveryOriginalTokenWithoutInterpretation(string source)
    {
        var lexical = NativeSourceLexer.Lex(source);
        var result = NativeSourceStructureParser.Parse(lexical);
        var tree = Assert.IsType<NativeSourceStructure>(result.Tree);
        Assert.Same(lexical.Document, tree.Document);
        Assert.True(result.Summary.IsComplete);
        Assert.Null(result.Summary.Diagnostic);
        Assert.Equal(lexical.Document!.Tokens.Count, result.Summary.TokenCount);
        Assert.Equal(Enumerable.Range(0, tree.Document.Tokens.Count), Flatten(tree.Nodes));
        Assert.Equal(source, string.Concat(Flatten(tree.Nodes).Select(tree.Document.GetText)));
        CheckSpans(tree.Document, tree.Nodes);
        Assert.Throws<NotSupportedException>(() => ((IList<NativeSourceNode>)tree.Nodes).Clear());
    }

    /// <summary>Groups include their exact delimiters and trivia; quoted/comment contents never introduce extra groups.</summary>
    [Fact]
    public void Groups_RetainExactBoundsAndImmutableChildren()
    {
        const string source = "# ignored (\r\n{ [ (\"}\") ] }";
        var result = NativeSourceAnalyzer.Analyze(source);
        var tree = result.Structure.Tree!;
        Assert.Equal(3, tree.GroupCount);
        Assert.Equal(3, tree.MaximumDepth);
        var outer = Assert.Single(tree.Nodes, n => n.Kind == NativeSourceNodeKind.Braces);
        Assert.Equal(new NativeSourceSpan(13, 13, 2, 1), outer.Span);
        Assert.Equal("{ [ (\"}\") ] }", tree.Document.Source.Substring(outer.Span.Offset, outer.Span.Length));
        Assert.Throws<NotSupportedException>(() => ((IList<NativeSourceNode>)outer.Children).Clear());
        Assert.DoesNotContain("ignored", tree.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("ignored", outer.ToString(), StringComparison.Ordinal);
        Assert.True(result.Review.InventoryComplete);
        Assert.False(result.Review.CanConvert);
    }

    /// <summary>Unexpected/mismatched closers and missing closes are diagnosed at exact physical source positions.</summary>
    [Theory]
    [InlineData("}\n", "source.unbalancedBraces", 0, 1, 1)]
    [InlineData("# context\r\n{", "source.unbalancedBraces", 11, 2, 1)]
    [InlineData("unknown ]", "source.unbalancedDelimiter", 8, 1, 9)]
    [InlineData("[ value", "source.unbalancedDelimiter", 0, 1, 1)]
    [InlineData("( value", "source.unbalancedDelimiter", 0, 1, 1)]
    [InlineData("{\r\n  ]", "source.mismatchedDelimiter", 5, 2, 3)]
    [InlineData("[}", "source.mismatchedDelimiter", 1, 1, 2)]
    [InlineData("{ counter } (", "source.unbalancedDelimiter", 12, 1, 13)]
    public void Failure_ExposesNoPartialTreeOrInventory(string source, string code, int offset, int line, int column)
    {
        var analysis = NativeSourceAnalyzer.Analyze(source);
        Assert.NotNull(analysis.Lexical.Document);
        Assert.Null(analysis.Structure.Tree);
        var summary = analysis.Structure.Summary;
        Assert.False(summary.IsComplete);
        Assert.Equal(0, summary.TokenCount);
        Assert.Equal(0, summary.GroupCount);
        Assert.Equal(0, summary.MaximumDepth);
        Assert.Equal(code, summary.Diagnostic!.Code);
        Assert.Equal(new NativeSourceSpan(offset, 1, line, column), summary.Diagnostic.Span);
        Assert.False(analysis.Review.InventoryComplete);
        Assert.Empty(analysis.Review.Signals);
        Assert.Equal(code, analysis.Review.Diagnostic);
        Assert.False(analysis.Review.CanConvert);
        Assert.DoesNotContain("context", summary.Diagnostic.ToString(), StringComparison.Ordinal);
    }

    /// <summary>Nesting is inclusive at the documented bound and rejected before recursive work can exceed it.</summary>
    [Fact]
    public void DepthBound_IsInclusiveAndFailureIsValueFree()
    {
        var depth = NativeSourceStructureParser.MaximumDepth;
        var allowed = NativeSourceAnalyzer.Analyze(new string('{', depth) + new string('}', depth));
        Assert.Equal(depth, allowed.Structure.Tree!.MaximumDepth);
        Assert.Equal(depth, allowed.Structure.Tree.GroupCount);
        var denied = NativeSourceAnalyzer.Analyze(new string('{', depth + 1) + "private-value" + new string('}', depth + 1));
        Assert.Null(denied.Structure.Tree);
        Assert.Equal("source.nestingTooDeep", denied.Structure.Summary.Diagnostic!.Code);
        Assert.Equal(new NativeSourceSpan(depth, 1, 1, depth + 1), denied.Structure.Summary.Diagnostic.Span);
        Assert.DoesNotContain("private-value", denied.Structure.Summary.Diagnostic.ToString(), StringComparison.Ordinal);
        Assert.Empty(denied.Review.Signals);
    }

    /// <summary>Lexical failure codes/positions propagate unchanged, without manufacturing an empty successful structure.</summary>
    [Fact]
    public void LexicalFailure_PropagatesAndNullInputIsRejected()
    {
        var lexical = NativeSourceLexer.Lex("# private\n\"unterminated");
        var structure = NativeSourceStructureParser.Parse(lexical);
        Assert.Null(structure.Tree);
        Assert.Equal(lexical.Diagnostic!.Code, structure.Summary.Diagnostic!.Code);
        Assert.Equal(lexical.Diagnostic.Span, structure.Summary.Diagnostic.Span);
        Assert.Throws<ArgumentNullException>(() => NativeSourceStructureParser.Parse(null!));
    }

    /// <summary>Maximum-width documents remain bounded and do not turn adjacent groups into recursive nesting.</summary>
    [Fact]
    public void WideDocuments_AcceptTheExistingInclusiveTokenBounds()
    {
        var flat = NativeSourceAnalyzer.Analyze(new string('\n', NativeSourceLexer.MaximumTokens));
        Assert.Equal(NativeSourceLexer.MaximumTokens, flat.Structure.Tree!.Nodes.Count);
        Assert.Equal(0, flat.Structure.Tree.MaximumDepth);
        var groups = NativeSourceLexer.MaximumSignificantTokens / 2;
        var adjacent = NativeSourceAnalyzer.Analyze(string.Concat(Enumerable.Repeat("{}", groups)));
        Assert.Equal(groups, adjacent.Structure.Tree!.GroupCount);
        Assert.Equal(1, adjacent.Structure.Tree.MaximumDepth);
        Assert.Equal(groups * 2, adjacent.Structure.Summary.TokenCount);
    }

    private static IEnumerable<int> Flatten(IEnumerable<NativeSourceNode> nodes)
    {
        foreach (var node in nodes)
        {
            yield return node.StartTokenIndex;
            if (node.Kind == NativeSourceNodeKind.Token) { continue; }
            foreach (var index in Flatten(node.Children)) { yield return index; }
            yield return node.EndTokenIndex - 1;
        }
    }

    private static void CheckSpans(NativeSourceDocument document, IEnumerable<NativeSourceNode> nodes)
    {
        foreach (var node in nodes)
        {
            var start = document.Tokens[node.StartTokenIndex].Span;
            var end = document.Tokens[node.EndTokenIndex - 1].Span;
            Assert.Equal(start with { Length = end.Offset + end.Length - start.Offset }, node.Span);
            if (node.Kind == NativeSourceNodeKind.Token) { Assert.Empty(node.Children); }
            else { CheckSpans(document, node.Children); }
        }
    }
}
