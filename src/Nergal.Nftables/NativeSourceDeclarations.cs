namespace Nergal.Nftables;

/// <summary>Source-head categories only; expressions and enforcement semantics remain unparsed.</summary>
public enum NativeSourceStatementKind
{
    /// <summary>Separators or trivia retained without enforcement meaning.</summary>
    Trivia,
    /// <summary>A declarative table block.</summary>
    Table,
    /// <summary>A table-local chain block.</summary>
    Chain,
    /// <summary>A named set block whose body remains unparsed.</summary>
    Set,
    /// <summary>A named map block whose body remains unparsed.</summary>
    Map,
    /// <summary>A named counter block whose body remains unparsed.</summary>
    Counter,
    /// <summary>A named quota block whose body remains unparsed.</summary>
    Quota,
    /// <summary>A named flowtable block whose body remains unparsed.</summary>
    Flowtable,
    /// <summary>A definition retaining its raw expression and scope.</summary>
    Define,
    /// <summary>A redefinition retaining its raw expression and scope.</summary>
    Redefine,
    /// <summary>An undefinition retaining its raw name token.</summary>
    Undefine,
    /// <summary>An include retaining its raw target without filesystem lookup.</summary>
    Include,
    /// <summary>Table metadata with unvalidated arguments.</summary>
    TableProperty,
    /// <summary>Chain metadata with unvalidated arguments.</summary>
    ChainProperty,
    /// <summary>An ordered chain statement requiring complete rule-expression parsing.</summary>
    Rule,
    /// <summary>A native command retained as data, never execution authority.</summary>
    Command,
    /// <summary>An unclassified statement retained for explicit gap handling.</summary>
    Unknown,
}

/// <summary>An immutable statement over original structural nodes; no private value is copied into metadata.</summary>
public sealed class NativeSourceStatement
{
    internal NativeSourceStatement(NativeSourceStatementKind kind, IEnumerable<NativeSourceNode> nodes, NativeSourceSpan head,
        int? name, int? family, NativeSourceNode? body, IEnumerable<NativeSourceStatement> children)
    {
        Kind = kind; Nodes = Array.AsReadOnly(nodes.ToArray()); HeadSpan = head;
        NameTokenIndex = name; FamilyTokenIndex = family; Body = body; Children = Array.AsReadOnly(children.ToArray());
        var first = Nodes[0].Span; var last = Nodes[^1].Span;
        Span = first with { Length = last.Offset + last.Length - first.Offset };
    }

    /// <summary>Gets the recognized head category, not native syntax validity or semantic support.</summary>
    public NativeSourceStatementKind Kind { get; }
    /// <summary>Gets every original node in this statement, including its retained separators/trivia.</summary>
    public IReadOnlyList<NativeSourceNode> Nodes { get; }
    /// <summary>Gets the exact complete source span, including any leading trivia.</summary>
    public NativeSourceSpan Span { get; }
    /// <summary>Gets the first meaningful node's position, or the trivia span start.</summary>
    public NativeSourceSpan HeadSpan { get; }
    /// <summary>Gets the raw name token's index, when recognized; names are not decoded or validated.</summary>
    public int? NameTokenIndex { get; }
    /// <summary>Gets the explicit family token index for a table; null when omitted or inapplicable.</summary>
    public int? FamilyTokenIndex { get; }
    /// <summary>Gets the original block body when recognized; named-object body expressions remain unparsed.</summary>
    public NativeSourceNode? Body { get; }
    /// <summary>Gets contextually partitioned table/chain body statements; empty for other bodies.</summary>
    public IReadOnlyList<NativeSourceStatement> Children { get; }
    /// <summary>Returns only kind and position, never source values.</summary>
    public override string ToString() => $"{Kind} at {HeadSpan.Line}:{HeadSpan.Column}";
}

/// <summary>A value-free unclassified-head diagnostic; unknown contents remain in the private statement tree.</summary>
public sealed record NativeSourceDeclarationDiagnostic(string Code, NativeSourceSpan Span);

/// <summary>A complete ordered partition of a private structural document; not a converted policy.</summary>
public sealed class NativeSourceDeclarations
{
    internal NativeSourceDeclarations(NativeSourceStructure structure, IEnumerable<NativeSourceStatement> statements)
    {
        Structure = structure; Statements = Array.AsReadOnly(statements.ToArray());
        var all = Enumerate(Statements).ToArray();
        TableCount = all.Count(n => n.Kind == NativeSourceStatementKind.Table);
        ChainCount = all.Count(n => n.Kind == NativeSourceStatementKind.Chain);
        Diagnostics = Array.AsReadOnly(all.Where(n => n.Kind == NativeSourceStatementKind.Unknown)
            .Select(n => new NativeSourceDeclarationDiagnostic("source.statementUnclassified", n.HeadSpan)).ToArray());
    }

    /// <summary>Gets the exact original structural tree; it contains private source values.</summary>
    public NativeSourceStructure Structure { get; }
    /// <summary>Gets ordered top-level source statements, including trivia and unknown content.</summary>
    public IReadOnlyList<NativeSourceStatement> Statements { get; }
    /// <summary>Gets contextually recognized declarative table headers, without implying valid native syntax.</summary>
    public int TableCount { get; }
    /// <summary>Gets contextually recognized table-local chain headers.</summary>
    public int ChainCount { get; }
    /// <summary>Gets unclassified statement positions, in source order, with no private values.</summary>
    public IReadOnlyList<NativeSourceDeclarationDiagnostic> Diagnostics { get; }
    /// <summary>Returns counts only, never source values.</summary>
    public override string ToString() => $"Native declarations ({TableCount} tables, {ChainCount} chains)";

    private static IEnumerable<NativeSourceStatement> Enumerate(IEnumerable<NativeSourceStatement> statements)
    {
        foreach (var statement in statements)
        {
            yield return statement;
            foreach (var child in Enumerate(statement.Children)) { yield return child; }
        }
    }
}

/// <summary>Partitions original nodes into contextual head shapes without interpreting or executing raw expressions.</summary>
public static class NativeSourceDeclarationParser
{
    /// <summary>Partitions a complete structural tree, retaining unknown statements for explicit later mapping.</summary>
    /// <exception cref="ArgumentNullException">The structural tree is null.</exception>
    public static NativeSourceDeclarations Parse(NativeSourceStructure structure)
    {
        ArgumentNullException.ThrowIfNull(structure);
        return new(structure, new Parser(structure.Document).Read(structure.Nodes, Context.Root));
    }

    // Includes and command bodies reuse the original partitioner in their actual lexical context.
    internal static IReadOnlyList<NativeSourceStatement> Partition(NativeSourceDocument document, IReadOnlyList<NativeSourceNode> nodes, bool chain) =>
        new Parser(document).Read(nodes, chain ? Context.Chain : Context.Table).AsReadOnly();

    private enum Context { Root, Table, Chain }

    private sealed class Parser(NativeSourceDocument document)
    {
        internal List<NativeSourceStatement> Read(IReadOnlyList<NativeSourceNode> nodes, Context context)
        {
            var result = new List<NativeSourceStatement>();
            var current = new List<NativeSourceNode>(); var heads = new List<NativeSourceNode>();
            var next = new int[nodes.Count + 1]; next[^1] = nodes.Count;
            for (var i = nodes.Count - 1; i >= 0; i--) { next[i] = Ignorable(nodes[i]) ? next[i + 1] : i; }
            for (var i = 0; i < nodes.Count; i++)
            {
                var node = nodes[i]; current.Add(node);
                if (Separator(node))
                {
                    if (heads.Count == 0) { continue; }
                    // A physical newline may separate a complete block head from its body.
                    var following = next[i + 1];
                    if (Text(node) != ";" && following < nodes.Count && nodes[following].Kind == NativeSourceNodeKind.Braces && BlockKind(heads, context) is not null) { continue; }
                    Flush();
                }
                else if (!Ignorable(node))
                {
                    if (node.Kind == NativeSourceNodeKind.Braces && BlockKind(heads, context) is not null)
                    { heads.Add(node); Flush(); }
                    else { heads.Add(node); }
                }
            }
            Flush(); return result;

            void Flush()
            {
                if (current.Count == 0) { return; }
                result.Add(Classify(current, heads, context));
                current = []; heads = [];
            }
        }

        private NativeSourceStatement Classify(List<NativeSourceNode> nodes, List<NativeSourceNode> heads, Context context)
        {
            var head = heads.FirstOrDefault()?.Span ?? nodes[0].Span;
            NativeSourceStatement Statement(NativeSourceStatementKind kind, int? name = null, int? family = null,
                NativeSourceNode? body = null, IEnumerable<NativeSourceStatement>? children = null) => new(kind, nodes, head, name, family, body, children ?? []);
            if (heads.Count == 0) { return Statement(NativeSourceStatementKind.Trivia); }
            if (heads[^1].Kind == NativeSourceNodeKind.Braces && BlockKind(heads, context, heads.Count - 1) is { } block)
            {
                var body = heads[^1];
                var name = heads[^2].StartTokenIndex;
                int? family = block == NativeSourceStatementKind.Table && heads.Count == 4 ? heads[1].StartTokenIndex : null;
                var children = block is NativeSourceStatementKind.Table or NativeSourceStatementKind.Chain
                    ? Read(body.Children, block == NativeSourceStatementKind.Table ? Context.Table : Context.Chain) : [];
                return Statement(block, name, family, body, children);
            }
            var word = Word(heads[0]);
            if (word is "define" or "redefine" && heads.Count >= 4 && Name(heads[1]) && Text(heads[2]) == "=")
            { return Statement(word == "define" ? NativeSourceStatementKind.Define : NativeSourceStatementKind.Redefine, heads[1].StartTokenIndex); }
            if (word == "undefine" && heads.Count == 2 && Name(heads[1])) { return Statement(NativeSourceStatementKind.Undefine, heads[1].StartTokenIndex); }
            if (word == "include" && heads.Count == 2 && Name(heads[1])) { return Statement(NativeSourceStatementKind.Include, heads[1].StartTokenIndex); }
            if (context == Context.Root && word is "add" or "create" or "insert" or "replace" or "delete" or "destroy" or "flush" or "list" or "reset" or "rename" or "monitor" or "describe")
            { return Statement(NativeSourceStatementKind.Command); }
            if (context == Context.Table && word is "comment" or "flags") { return Statement(NativeSourceStatementKind.TableProperty); }
            if (context == Context.Chain)
            { return Statement(word is "type" or "policy" or "comment" or "flags" ? NativeSourceStatementKind.ChainProperty : NativeSourceStatementKind.Rule); }
            return Statement(NativeSourceStatementKind.Unknown);
        }

        private NativeSourceStatementKind? BlockKind(IReadOnlyList<NativeSourceNode> heads, Context context, int? length = null)
        {
            var count = length ?? heads.Count;
            if (count is < 2 or > 3) { return null; }
            var word = Word(heads[0]);
            if (context == Context.Root && word == "table")
            {
                if (count == 2 && Name(heads[1])) { return NativeSourceStatementKind.Table; }
                if (count == 3 && Word(heads[1]) is "ip" or "ip6" or "inet" or "arp" or "bridge" or "netdev" && Name(heads[2])) { return NativeSourceStatementKind.Table; }
            }
            if (context != Context.Table || count != 2 || !Name(heads[1])) { return null; }
            return word switch
            {
                "chain" => NativeSourceStatementKind.Chain,
                "set" => NativeSourceStatementKind.Set,
                "map" => NativeSourceStatementKind.Map,
                "counter" => NativeSourceStatementKind.Counter,
                "quota" => NativeSourceStatementKind.Quota,
                "flowtable" => NativeSourceStatementKind.Flowtable,
                _ => null
            };
        }

        private bool Ignorable(NativeSourceNode node) => node.Kind == NativeSourceNodeKind.Token &&
            (document.Tokens[node.StartTokenIndex].IsTrivia || document.Tokens[node.StartTokenIndex].Kind == NativeSourceTokenKind.NewLine);
        private bool Separator(NativeSourceNode node) => node.Kind == NativeSourceNodeKind.Token &&
            (document.Tokens[node.StartTokenIndex].Kind == NativeSourceTokenKind.NewLine || Text(node) == ";");
        private string Text(NativeSourceNode node) => node.Kind == NativeSourceNodeKind.Token ? document.GetText(node.StartTokenIndex) : "";
        private string Word(NativeSourceNode node) => node.Kind == NativeSourceNodeKind.Token && document.Tokens[node.StartTokenIndex].Kind == NativeSourceTokenKind.Bare ? Text(node) : "";
        private bool Name(NativeSourceNode node) => node.Kind == NativeSourceNodeKind.Token && document.Tokens[node.StartTokenIndex].Kind is NativeSourceTokenKind.Bare or NativeSourceTokenKind.DoubleQuoted;
    }
}
