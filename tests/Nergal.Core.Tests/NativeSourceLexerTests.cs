using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Source tokenization retains every code unit without interpretation, partial output or private-value diagnostics.</summary>
public sealed class NativeSourceLexerTests
{
    /// <summary>Trivia, opaque values, unknown syntax and references cannot disappear before semantic accounting.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("\ufeff# header\r\ndefine iface = \"wan # \\\"0\\\"\";\rip saddr $counter \\\r\n ether daddr @log != 02:00:00:00:00:01 accept\n")]
    [InlineData("mystery foo 'uninterpreted' [x] (y) ^ && || << >> <= >= == != $value @lookup { 1, 2 }; # unknown\n")]
    [InlineData("include \"/not/a/server/file/*.nft\"\nredefine value = { $old, 192.0.2.1/32 }; undefine value\n")]
    [InlineData("a\\\nb $counter\\\r\n@log\\\rd # counter\\\naccept\n")]
    [InlineData("\"opaque\nmultiline\\\r\nchunk\"\r'é'\n")]
    public void CompleteDocument_ReconstructsEveryOriginalCodeUnit(string source)
    {
        var result = NativeSourceLexer.Lex(source);
        Assert.True(result.IsComplete);
        Assert.Null(result.Diagnostic);
        var document = result.Document!;
        Assert.Equal(source, document.Source);
        Assert.Equal(source, string.Concat(Enumerable.Range(0, document.Tokens.Count).Select(document.GetText)));
        var offset = 0;
        foreach (var token in document.Tokens)
        {
            Assert.Equal(offset, token.Span.Offset);
            Assert.True(token.Span.Length > 0);
            offset += token.Span.Length;
        }
        Assert.Equal(source.Length, offset);
    }

    /// <summary>Positions use physical CRLF/CR/LF lines and UTF-16 columns, retaining BOM and tabs exactly.</summary>
    [Fact]
    public void Positions_AreExactAndNotNormalized()
    {
        var document = NativeSourceLexer.Lex("\ufeffa\r\n\tb\rc\n").Document!;
        NativeSourceSpan[] positions = [new(0, 1, 1, 1), new(1, 1, 1, 2), new(2, 2, 1, 3), new(4, 1, 2, 1),
            new(5, 1, 2, 2), new(6, 1, 2, 3), new(7, 1, 3, 1), new(8, 1, 3, 2)];
        Assert.Equal(positions, document.Tokens.Select(t => t.Span));
        var unicode = NativeSourceLexer.Lex("🔒 x").Document!;
        Assert.Equal(new(0, 2, 1, 1), unicode.Tokens[0].Span);
        Assert.Equal(new(3, 1, 1, 4), unicode.Tokens[2].Span);
        Assert.Equal("🔒", unicode.GetText(0));
        var unknownWhitespace = NativeSourceLexer.Lex("a\u00a0b\u2028c").Document!;
        Assert.Equal(NativeSourceTokenKind.Bare, Assert.Single(unknownWhitespace.Tokens).Kind);
        Assert.Equal("a\u00a0b\u2028c", unknownWhitespace.GetText(0));
    }

    /// <summary>Keywords inside quoted values and references stay distinct; a non-quoted continuation joins physical lines.</summary>
    [Fact]
    public void Categories_PreserveKeywordBoundariesAndContinuations()
    {
        var document = NativeSourceLexer.Lex("\"counter\" 'log' $notrack @return counter\\\r\n!= # jump\\\naccept").Document!;
        var significant = document.Tokens.Where(t => !t.IsTrivia && t.Kind != NativeSourceTokenKind.NewLine).ToArray();
        Assert.Equal(new[] { NativeSourceTokenKind.DoubleQuoted, NativeSourceTokenKind.SingleQuoted,
            NativeSourceTokenKind.VariableReference, NativeSourceTokenKind.AtReference, NativeSourceTokenKind.Bare,
            NativeSourceTokenKind.Symbol, NativeSourceTokenKind.Bare }, significant.Select(t => t.Kind));
        var continuation = Assert.Single(document.Tokens, t => t.Kind == NativeSourceTokenKind.Continuation);
        Assert.Equal(new NativeSourceSpan(40, 3, 1, 41), continuation.Span);
        Assert.Equal(3, significant[^1].Span.Line);
        Assert.Equal(1, significant[^1].Span.Column);
        Assert.DoesNotContain("counter", significant[0].ToString(), StringComparison.Ordinal);
    }

    /// <summary>A failure yields no partial document or source values, including controls hidden in comments/quotes/trivia.</summary>
    [Theory]
    [InlineData("do-not-log \"secret", "source.unterminatedString")]
    [InlineData("do-not-log 'secret\\", "source.unterminatedString")]
    [InlineData("do-not-log\0", "source.invalidCharacter")]
    [InlineData("# do-not-log\u0001", "source.invalidCharacter")]
    [InlineData("\"do-not-log\u007f\"", "source.invalidCharacter")]
    [InlineData(" \vdo-not-log", "source.invalidCharacter")]
    public void InvalidSource_FailsWithoutPartialDocumentOrPrivateDiagnostic(string source, string code)
    {
        var result = NativeSourceLexer.Lex(source);
        Assert.False(result.IsComplete);
        Assert.Null(result.Document);
        Assert.Equal(code, result.Diagnostic!.Code);
        Assert.DoesNotContain("do-not-log", result.Diagnostic.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("secret", result.Diagnostic.ToString(), StringComparison.Ordinal);
    }

    /// <summary>UTF-8 bytes, meaningful tokens and total retained trivia have independent inclusive bounds.</summary>
    [Fact]
    public void CapacityLimits_AreInclusiveAndIndependent()
    {
        Assert.True(NativeSourceLexer.Lex(new string('é', NativeSourceLexer.MaximumBytes / 2)).IsComplete);
        Assert.Equal("source.tooLarge", NativeSourceLexer.Lex(new string('é', NativeSourceLexer.MaximumBytes / 2 + 1)).Diagnostic!.Code);
        Assert.True(NativeSourceLexer.Lex(new string(';', NativeSourceLexer.MaximumSignificantTokens)).IsComplete);
        Assert.Equal("source.tooManyTokens", NativeSourceLexer.Lex(new string(';', NativeSourceLexer.MaximumSignificantTokens + 1)).Diagnostic!.Code);
        Assert.True(NativeSourceLexer.Lex(new string('\n', NativeSourceLexer.MaximumTokens)).IsComplete);
        Assert.Equal("source.tooManyTokens", NativeSourceLexer.Lex(new string('\n', NativeSourceLexer.MaximumTokens + 1)).Diagnostic!.Code);
        // Attribute arguments encode strings as UTF-8 and cannot retain an unpaired surrogate.
        Assert.Equal("source.invalidEncoding", NativeSourceLexer.Lex(new string('\ud800', 1)).Diagnostic!.Code);
        Assert.Throws<ArgumentNullException>(() => NativeSourceLexer.Lex(null!));
    }

    /// <summary>Consumers cannot mutate token order or read outside the owning document; string representations omit values.</summary>
    [Fact]
    public void Documents_AreImmutableAndValueFreeWhenFormatted()
    {
        var document = NativeSourceLexer.Lex("private-value\n").Document!;
        Assert.Throws<NotSupportedException>(() => ((IList<NativeSourceToken>)document.Tokens).Clear());
        Assert.Throws<ArgumentOutOfRangeException>(() => document.GetText(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() => document.GetText(document.Tokens.Count));
        Assert.DoesNotContain("private-value", document.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("private-value", document.Tokens[0].ToString(), StringComparison.Ordinal);
        Assert.Equal("private-value", document.GetText(0));
    }

    /// <summary>Viewer/import consumers share one document and inventory; compatibility review cannot take a divergent lexical path.</summary>
    [Fact]
    public void SharedAnalysis_UsesTheSameDocumentAndPhysicalLineEvidence()
    {
        const string source = "# private-name\r\nether \\\r\n saddr 02:00:00:00:00:01 accept\rcounter\n$log @notrack \"jump\"\n";
        var analysis = NativeSourceAnalyzer.Analyze(source);
        Assert.Equal(source, analysis.Lexical.Document!.Source);
        Assert.True(analysis.Review.InventoryComplete);
        Assert.False(analysis.Review.CanConvert);
        Assert.Equal(new[] { 2 }, analysis.Review.Signals.Single(s => s.Code == "review.sourceMac").Lines);
        Assert.Equal(new[] { 4 }, analysis.Review.Signals.Single(s => s.Code == "gap.counters").Lines);
        Assert.DoesNotContain(analysis.Review.Signals, s => s.Code is "gap.logging" or "gap.notrack" or "review.jumps");
        var compatibility = NativeMigrationReviewer.Review(source);
        Assert.Equal(analysis.Review.Signals.Select(s => (s.Code, string.Join(',', s.Lines))), compatibility.Signals.Select(s => (s.Code, string.Join(',', s.Lines))));
        Assert.DoesNotContain("private-name", analysis.ToString(), StringComparison.Ordinal);
        var failed = NativeSourceAnalyzer.Analyze("# private-name\0");
        Assert.Null(failed.Lexical.Document);
        Assert.False(failed.Review.InventoryComplete);
        Assert.False(failed.Review.CanConvert);
        Assert.Empty(failed.Review.Signals);
        Assert.Equal(failed.Lexical.Diagnostic!.Code, failed.Review.Diagnostic);
    }
}
