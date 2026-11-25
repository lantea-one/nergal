using System.Collections.ObjectModel;

namespace Nergal.Nftables;

/// <summary>Meaning of a lexical migration signal; no category certifies semantic equivalence.</summary>
public enum MigrationSignalKind
{
    /// <summary>A typed construct exists, but this source occurrence still needs explicit mapping.</summary>
    TypedMapping,
    /// <summary>The occurrence needs semantics beyond the currently implemented policy contract.</summary>
    ContractGap,
    /// <summary>Source definitions or file scope need explicit resolution before conversion.</summary>
    SourceResolution,
}

/// <summary>A review topic and immutable one-based source line references, without private token values.</summary>
public sealed record MigrationSignal(string Code, string Description, MigrationSignalKind Kind, IReadOnlyList<int> Lines);

/// <summary>A bounded lexical inventory. It is never an executable or partially converted policy.</summary>
/// <param name="InventoryComplete">Whether bounded tokenization and structural grouping completed; this is not native syntax validation.</param>
/// <param name="Diagnostic">Stable diagnostic for incomplete inventory, or null.</param>
/// <param name="TableDeclarations">Number of recognized declarative table headers.</param>
/// <param name="ChainDeclarations">Number of recognized declarative chain headers.</param>
/// <param name="Signals">Review signals in stable catalog order.</param>
public sealed record NativeMigrationReview(bool InventoryComplete, string? Diagnostic, int TableDeclarations,
    int ChainDeclarations, IReadOnlyList<MigrationSignal> Signals)
{
    /// <summary>No lexical inventory can authorize conversion or imply lossless policy coverage.</summary>
    public bool CanConvert => false;
}

/// <summary>Inventories private native source in memory without executing nft, resolving includes, or producing policy.</summary>
/// <remarks>Signals are deliberately non-exhaustive. Unknown input never becomes an approved candidate.
/// No private identifiers or literal values are copied into the report.</remarks>
public static class NativeMigrationReviewer
{
    private sealed record Token(string Text, int Line, bool Word);
    private sealed record Topic(string Code, string Description, MigrationSignalKind Kind, string[] Pattern);
    private static readonly Topic[] Topics =
    [
        new("source.definitions", "Resolve named definitions against this exact source snapshot.", MigrationSignalKind.SourceResolution, ["define"]),
        new("source.includes", "Resolve external includes explicitly; this review never opens another file.", MigrationSignalKind.SourceResolution, ["include"]),
        new("scope.flush", "Replace whole-ruleset operations with explicit managed-resource ownership.", MigrationSignalKind.SourceResolution, ["flush", "ruleset"]),
        new("gap.maps", "Preserve named/inline map lookup semantics; map translation is not modeled.", MigrationSignalKind.ContractGap, ["map"]),
        new("gap.verdictMaps", "Preserve verdict-map control flow; verdict maps are not modeled.", MigrationSignalKind.ContractGap, ["vmap"]),
        new("gap.notrack", "Preserve connection-tracking bypass and raw-hook ordering; notrack is not modeled.", MigrationSignalKind.ContractGap, ["notrack"]),
        new("gap.counters", "Preserve counter identity and reset/observation semantics; counter statements are not modeled.", MigrationSignalKind.ContractGap, ["counter"]),
        new("gap.logging", "Preserve logging behavior; native log statements are not modeled.", MigrationSignalKind.ContractGap, ["log"]),
        new("gap.flowtables", "Preserve flow-offload behavior; flowtables are not modeled.", MigrationSignalKind.ContractGap, ["flowtable"]),
        new("gap.queue", "Preserve userspace queue behavior; queue statements are not modeled.", MigrationSignalKind.ContractGap, ["queue"]),
        new("gap.redirect", "Preserve redirect translation; redirect statements are not modeled.", MigrationSignalKind.ContractGap, ["redirect"]),
        new("gap.tproxy", "Preserve transparent-proxy behavior; tproxy is not modeled.", MigrationSignalKind.ContractGap, ["tproxy"]),
        new("review.fib", "Map reverse-path FIB checks and their ordered bypasses.", MigrationSignalKind.TypedMapping, ["fib"]),
        new("review.mss", "Map TCP MSS clamping, flags and hook placement.", MigrationSignalKind.TypedMapping, ["maxseg"]),
        new("review.sourceMac", "Preserve source MAC restrictions together with IP restrictions.", MigrationSignalKind.TypedMapping, ["ether", "saddr"]),
        new("review.destinationMac", "Preserve destination MAC restrictions and negation.", MigrationSignalKind.TypedMapping, ["ether", "daddr"]),
        new("review.meters", "Map meter keys, rates, bursts and address-family scope.", MigrationSignalKind.TypedMapping, ["meter"]),
        new("review.masquerade", "Preserve postrouting translation order and exemptions.", MigrationSignalKind.TypedMapping, ["masquerade"]),
        new("review.return", "Preserve return behavior in its original chain and caller context.", MigrationSignalKind.TypedMapping, ["return"]),
        new("review.jumps", "Map every jump target and preserve rule ordering.", MigrationSignalKind.TypedMapping, ["jump"]),
        new("review.bridgeMaster", "Preserve bridge-master interface matching.", MigrationSignalKind.TypedMapping, ["ibrname"]),
    ];

    /// <summary>Returns a deterministic, immutable review with bounded work and no host access.</summary>
    /// <exception cref="ArgumentNullException">Source is null.</exception>
    public static NativeMigrationReview Review(string source) => NativeSourceAnalyzer.Analyze(source).Review;

    internal static NativeMigrationReview Review(NativeSourceStructureResult structure, NativeSourceDeclarations? declarations, NativeRuleCatalog? rules)
    {
        if (structure.Tree is not { } tree) { return Incomplete(structure.Summary.Diagnostic!.Code); }
        ArgumentNullException.ThrowIfNull(declarations);
        var document = tree.Document;
        var tokens = new List<Token>();
        for (var i = 0; i < document.Tokens.Count; i++)
        {
            var token = document.Tokens[i];
            if (token.IsTrivia || token.Kind == NativeSourceTokenKind.NewLine) { continue; }
            // Keep private quoted/reference values opaque even though the frontend retains their spans.
            var text = token.Kind is NativeSourceTokenKind.Bare or NativeSourceTokenKind.Symbol ? document.GetText(i) : "";
            tokens.Add(new(text, token.Span.Line, token.Kind == NativeSourceTokenKind.Bare && text.All(IsWord)));
        }
        var signals = new List<MigrationSignal>();
        foreach (var topic in Topics)
        {
            var lines = new List<int>();
            for (var i = 0; i < tokens.Count; i++)
            {
                if (Match(tokens, i, topic.Pattern) && (lines.Count == 0 || lines[^1] != tokens[i].Line)) { lines.Add(tokens[i].Line); }
            }
            if (lines.Count > 0) { signals.Add(new(topic.Code, topic.Description, topic.Kind, lines.AsReadOnly())); }
        }
        if (declarations.Diagnostics.Count > 0)
        {
            signals.Add(new("source.unclassifiedStatements", "Map unclassified source statements explicitly; none may be discarded.",
                MigrationSignalKind.SourceResolution, Array.AsReadOnly(declarations.Diagnostics.Select(d => d.Span.Line).Distinct().ToArray())));
        }
        if (rules is { Summary.Diagnostics.Count: > 0 })
        {
            signals.Add(new("source.unparsedRules", "Resolve every unparsed rule expression; no partial rule may be converted.",
                MigrationSignalKind.SourceResolution, Array.AsReadOnly(rules.Summary.Diagnostics.Select(d => d.Span.Line).Distinct().ToArray())));
        }
        return new(true, null, declarations.TableCount, declarations.ChainCount, signals.AsReadOnly());
    }

    private static bool IsWord(char c) => char.IsLetterOrDigit(c) || c is '_' or '-' or '.' or '/' or ':';
    private static bool Match(List<Token> tokens, int start, string[] pattern)
    {
        if (start + pattern.Length > tokens.Count) { return false; }
        for (var j = 0; j < pattern.Length; j++)
        {
            if (!tokens[start + j].Word || tokens[start + j].Text != pattern[j]) { return false; }
        }
        return true;
    }
    private static NativeMigrationReview Incomplete(string code) => new(false, code, 0, 0, ReadOnlyCollection<MigrationSignal>.Empty);
}
