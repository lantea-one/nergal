namespace Nergal.Nftables;

/// <summary>A structural token or delimiter group; no kind certifies native syntax or semantic support.</summary>
public enum NativeSourceNodeKind
{
    /// <summary>One original token, including trivia and unknown values.</summary>
    Token,
    /// <summary>A brace-delimited group, without interpreting block or set semantics.</summary>
    Braces,
    /// <summary>A bracket-delimited group, without interpreting its contents.</summary>
    Brackets,
    /// <summary>A parenthesis-delimited group, without evaluating expressions.</summary>
    Parentheses,
}

/// <summary>An immutable source node with exact token bounds; string formatting omits private values.</summary>
public sealed class NativeSourceNode
{
    private static readonly IReadOnlyList<NativeSourceNode> NoChildren = Array.AsReadOnly(Array.Empty<NativeSourceNode>());
    internal NativeSourceNode(NativeSourceNodeKind kind, int start, int end, NativeSourceSpan span, IEnumerable<NativeSourceNode> children)
    { Kind = kind; StartTokenIndex = start; EndTokenIndex = end; Span = span; Children = kind == NativeSourceNodeKind.Token ? NoChildren : Array.AsReadOnly(children.ToArray()); }

    /// <summary>Gets the structural category, not a semantic classification.</summary>
    public NativeSourceNodeKind Kind { get; }
    /// <summary>Gets the inclusive first token index in the owning document.</summary>
    public int StartTokenIndex { get; }
    /// <summary>Gets the exclusive final token index; groups include both delimiters.</summary>
    public int EndTokenIndex { get; }
    /// <summary>Gets the exact original UTF-16 span, starting at the first token's physical position.</summary>
    public NativeSourceSpan Span { get; }
    /// <summary>Gets ordered group contents, excluding the two delimiters; empty for a token node.</summary>
    public IReadOnlyList<NativeSourceNode> Children { get; }
    /// <summary>Returns category and position only.</summary>
    public override string ToString() => $"{Kind} at {Span.Line}:{Span.Column}";
}

/// <summary>A complete immutable tree over the same private lexical document, with no semantic interpretation.</summary>
public sealed class NativeSourceStructure
{
    internal NativeSourceStructure(NativeSourceDocument document, IEnumerable<NativeSourceNode> nodes, int groups, int depth)
    { Document = document; Nodes = Array.AsReadOnly(nodes.ToArray()); GroupCount = groups; MaximumDepth = depth; }

    /// <summary>Gets the exact original document, including potentially private source values.</summary>
    public NativeSourceDocument Document { get; }
    /// <summary>Gets ordered top-level nodes covering every original token exactly once.</summary>
    public IReadOnlyList<NativeSourceNode> Nodes { get; }
    /// <summary>Gets the total number of nested delimiter groups.</summary>
    public int GroupCount { get; }
    /// <summary>Gets the deepest group nesting, or zero when no group exists.</summary>
    public int MaximumDepth { get; }
    /// <summary>Returns counts only, never private source values.</summary>
    public override string ToString() => $"Native source structure ({GroupCount} groups)";
}

/// <summary>A stable value-free structural or propagated lexical failure.</summary>
public sealed record NativeSourceStructureDiagnostic(string Code, NativeSourceSpan Span);

/// <summary>Value-free metadata safe for an authorized source-bound report; it never grants conversion authority.</summary>
public sealed class NativeSourceStructureSummary
{
    internal NativeSourceStructureSummary(NativeSourceStructure? tree, NativeSourceStructureDiagnostic? diagnostic)
    { IsComplete = tree is not null; TokenCount = tree?.Document.Tokens.Count ?? 0; GroupCount = tree?.GroupCount ?? 0; MaximumDepth = tree?.MaximumDepth ?? 0; Diagnostic = diagnostic; }

    /// <summary>Gets whether complete structural parsing succeeded, not native syntax validity.</summary>
    public bool IsComplete { get; }
    /// <summary>Gets the complete original token count including trivia; zero on failure.</summary>
    public int TokenCount { get; }
    /// <summary>Gets the complete delimiter-group count; zero on failure.</summary>
    public int GroupCount { get; }
    /// <summary>Gets the complete maximum nesting depth; zero on failure.</summary>
    public int MaximumDepth { get; }
    /// <summary>Gets the failure code/position, or null on success; no source values are copied.</summary>
    public NativeSourceStructureDiagnostic? Diagnostic { get; }
}

/// <summary>A complete tree or stable failure, never partially parsed output.</summary>
public sealed class NativeSourceStructureResult
{
    internal NativeSourceStructureResult(NativeSourceStructure? tree, NativeSourceStructureDiagnostic? diagnostic)
    { Tree = tree; Summary = new(tree, diagnostic); }

    /// <summary>Gets the complete private tree, or null on failure.</summary>
    public NativeSourceStructure? Tree { get; }
    /// <summary>Gets the value-free complete/failure summary used by viewer and report.</summary>
    public NativeSourceStructureSummary Summary { get; }
}

/// <summary>Groups the existing lossless token document without executing, resolving or translating source.</summary>
public static class NativeSourceStructureParser
{
    /// <summary>Inclusive maximum group nesting; work and storage are also bounded by lexical token limits.</summary>
    public const int MaximumDepth = 64;

    /// <summary>Parses one existing lexical result; lexical failures propagate without re-tokenization or partial output.</summary>
    /// <exception cref="ArgumentNullException">The lexical result is null.</exception>
    public static NativeSourceStructureResult Parse(NativeSourceLexingResult lexical)
    {
        ArgumentNullException.ThrowIfNull(lexical);
        if (lexical.Document is not { } document) { return new(null, new(lexical.Diagnostic!.Code, lexical.Diagnostic.Span)); }
        var parser = new Parser(document);
        var nodes = parser.ReadNodes(null, 0, 0);
        return parser.Diagnostic is { } diagnostic ? new(null, diagnostic) : new(new(document, nodes, parser.Groups, parser.Depth), null);
    }

    private sealed class Parser(NativeSourceDocument document)
    {
        private int _index;
        internal int Groups { get; private set; }
        internal int Depth { get; private set; }
        internal NativeSourceStructureDiagnostic? Diagnostic { get; private set; }

        internal List<NativeSourceNode> ReadNodes(char? expectedClose, int opener, int depth)
        {
            var nodes = new List<NativeSourceNode>();
            while (_index < document.Tokens.Count && Diagnostic is null)
            {
                var start = _index;
                var token = document.Tokens[_index];
                var symbol = token.Kind == NativeSourceTokenKind.Symbol && token.Span.Length == 1 ? document.Source[token.Span.Offset] : '\0';
                if (symbol is '}' or ']' or ')')
                {
                    if (expectedClose == symbol) { _index++; return nodes; }
                    Fail(expectedClose is null ? Unbalanced(symbol) : "source.mismatchedDelimiter", token.Span);
                    return nodes;
                }
                _index++;
                if (symbol is '{' or '[' or '(')
                {
                    if (depth == MaximumDepth) { Fail("source.nestingTooDeep", token.Span); return nodes; }
                    Groups++; Depth = Math.Max(Depth, depth + 1);
                    var close = symbol switch { '{' => '}', '[' => ']', _ => ')' };
                    var children = ReadNodes(close, start, depth + 1);
                    if (Diagnostic is not null) { return nodes; }
                    var last = document.Tokens[_index - 1].Span;
                    var span = token.Span with { Length = last.Offset + last.Length - token.Span.Offset };
                    var kind = symbol switch { '{' => NativeSourceNodeKind.Braces, '[' => NativeSourceNodeKind.Brackets, _ => NativeSourceNodeKind.Parentheses };
                    nodes.Add(new(kind, start, _index, span, children));
                }
                else { nodes.Add(new(NativeSourceNodeKind.Token, start, _index, token.Span, [])); }
            }
            if (expectedClose is { } missing && Diagnostic is null) { Fail(Unbalanced(missing), document.Tokens[opener].Span); }
            return nodes;
        }

        private void Fail(string code, NativeSourceSpan span) => Diagnostic = new(code, span);
        private static string Unbalanced(char closer) => closer == '}' ? "source.unbalancedBraces" : "source.unbalancedDelimiter";
    }
}
