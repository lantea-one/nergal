namespace Nergal.Nftables;

/// <summary>One immutable analysis shared by source viewing and the import workflow; no conversion authority is granted.</summary>
/// <remarks>The lexical document contains private source values. Use the value-masked Review for inventory reports.</remarks>
public sealed class NativeSourceAnalysis
{
    internal NativeSourceAnalysis(NativeSourceLexingResult lexical, NativeSourceStructureResult structure, NativeMigrationReview review)
    { Lexical = lexical; Structure = structure; Review = review; }

    /// <summary>Gets the complete source tokens or the exact lexical failure used by the review.</summary>
    public NativeSourceLexingResult Lexical { get; }
    /// <summary>Gets the complete structural tree or failure over the same token document.</summary>
    public NativeSourceStructureResult Structure { get; }
    /// <summary>Gets the non-exhaustive inventory derived only from this same complete structural result.</summary>
    public NativeMigrationReview Review { get; }
    /// <summary>Returns status only, never private source values.</summary>
    public override string ToString() => Structure.Tree is not null ? "Native source analysis (structured; conversion blocked)" : "Native source analysis (incomplete; conversion blocked)";
}

/// <summary>The common pure analysis entry point for the combined native source viewer/import workflow.</summary>
/// <remarks>Later semantic mapping must consume this same source document; no separate viewer grammar or include lookup is authorized.</remarks>
public static class NativeSourceAnalyzer
{
    /// <summary>Tokenizes once and derives a value-masked review from the exact same immutable source spans.</summary>
    /// <exception cref="ArgumentNullException">Source is null.</exception>
    public static NativeSourceAnalysis Analyze(string source)
    {
        var lexical = NativeSourceLexer.Lex(source);
        var structure = NativeSourceStructureParser.Parse(lexical);
        return new(lexical, structure, NativeMigrationReviewer.Review(structure));
    }
}
