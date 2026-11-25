using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Migration inventories cannot grant conversion authority, hide gaps, or interpret private literals as keywords.</summary>
public sealed class NativeMigrationReviewerTests
{
    /// <summary>Recognized features retain source locations without copying private values.</summary>
    [Fact]
    public void Review_ReportsGapsAndTypedMappingAtExactSourceLinesWithoutLiteralValues()
    {
        var review = NativeMigrationReviewer.Review("""
            define service = 18080
            table inet synthetic {
                chain forward {
                    type filter hook forward priority 0; policy drop;
                    ether saddr 02:00:00:00:00:01 ip saddr 192.0.2.2 tcp dport $service counter accept
                    ct state untracked notrack
                    ip daddr map { 192.0.2.2 : 198.51.100.2 } accept
                }
            }
            """);
        Assert.True(review.InventoryComplete);
        Assert.False(review.CanConvert);
        Assert.Equal(1, review.TableDeclarations);
        Assert.Equal(1, review.ChainDeclarations);
        Assert.Equal([5], review.Signals.Single(s => s.Code == "gap.counters").Lines);
        Assert.Equal(MigrationSignalKind.ContractGap, review.Signals.Single(s => s.Code == "gap.notrack").Kind);
        Assert.Contains(review.Signals, s => s.Code == "gap.maps");
        Assert.Contains(review.Signals, s => s.Code == "review.sourceMac");
        var json = System.Text.Json.JsonSerializer.Serialize(review);
        Assert.DoesNotContain("192.0.2.2", json);
        Assert.DoesNotContain("02:00:00:00:00:01", json);
    }

    /// <summary>Comments, literals and variable names cannot masquerade as semantic keywords.</summary>
    [Fact]
    public void Review_CommentsQuotedStringsAndVariablesCannotInjectSignals()
    {
        var review = NativeMigrationReviewer.Review("""
            # include "missing"; notrack counter map
            table inet synthetic { chain forward {
                iifname "counter notrack map {" comment "escaped \" include"
                ip saddr $counter accept
            } }
            """);
        Assert.True(review.InventoryComplete);
        Assert.Equal("source.unparsedRules", Assert.Single(review.Signals).Code);
        Assert.DoesNotContain(review.Signals, s => s.Code is "gap.counters" or "gap.notrack" or "gap.maps" or "source.includes");
        Assert.Equal(1, review.TableDeclarations);
        Assert.False(review.CanConvert);
    }

    /// <summary>Malformed source never returns a partial inventory.</summary>
    [Theory]
    [InlineData("table inet example {", "source.unbalancedBraces")]
    [InlineData("}", "source.unbalancedBraces")]
    [InlineData("include \"unterminated", "source.unterminatedString")]
    public void Review_MalformedInputCannotYieldPartialInventory(string source, string diagnostic)
    {
        var review = NativeMigrationReviewer.Review(source);
        Assert.False(review.InventoryComplete);
        Assert.Equal(diagnostic, review.Diagnostic);
        Assert.Empty(review.Signals);
        Assert.False(review.CanConvert);
    }

    /// <summary>Resource and encoding failures are explicit and bounded.</summary>
    [Fact]
    public void Review_BoundsBytesTokensAndEncodingWithoutProducingPartialResults()
    {
        Assert.Equal("source.tooLarge", NativeMigrationReviewer.Review(new string('é', 262_145)).Diagnostic);
        Assert.Equal("source.tooManyTokens", NativeMigrationReviewer.Review(new string(';', 65_537)).Diagnostic);
        Assert.Equal("source.invalidEncoding", NativeMigrationReviewer.Review("\ud800").Diagnostic);
        Assert.Throws<ArgumentNullException>(() => NativeMigrationReviewer.Review(null!));
    }

    /// <summary>Callers cannot mutate evidence, and unknown input never receives conversion authority.</summary>
    [Fact]
    public void Review_IsImmutableAndUnknownOrEmptySourceNeverBecomesConvertible()
    {
        foreach (var source in new[] { "", "unknownfutureconstruct accept", "counter\ncounter" })
        {
            var review = NativeMigrationReviewer.Review(source);
            Assert.False(review.CanConvert);
            Assert.Throws<NotSupportedException>(() => ((IList<MigrationSignal>)review.Signals).Add(null!));
            foreach (var signal in review.Signals)
            {
                Assert.Throws<NotSupportedException>(() => ((IList<int>)signal.Lines).Add(100));
            }
        }
    }
}
