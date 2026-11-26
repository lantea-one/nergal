using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Nergal.Core.Controller;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

/// <summary>Exhaustively maps an explicitly scoped native snapshot to typed intent without host access.</summary>
public static partial class NativeImportPlanner
{
    /// <summary>Maximum distinct input snapshots and include depth; expansion is independently token-bounded.</summary>
    public const int MaximumSources = 32;
    /// <summary>Maximum include recursion, excluding the root.</summary>
    public const int MaximumIncludeDepth = 8;
    /// <summary>Maximum expanded significant terms, including repeated uses of definitions/includes.</summary>
    public const int MaximumExpandedTerms = 131_072;

    /// <summary>Builds one deterministic review with no candidate on any gap; provided sources are immutable database snapshots.</summary>
    /// <exception cref="ArgumentNullException">A required argument is null.</exception>
    public static NativeImportPlan Plan(NativeImportRequest request, IEnumerable<NativeSourceSnapshot> sources)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(sources);
        return new Planner(request, sources).Run();
    }

    private sealed class ImportFailure(string code, Term term) : Exception(code)
    { internal string Code { get; } = code; internal Term Term { get; } = term; }
    private sealed record Unit(NativeSourceSnapshot Source, NativeSourceAnalysis Analysis);
    private sealed record Term(Unit Unit, NativeSourceNode Node, Term[]? ResolvedChildren = null, NativeSourceSpan? StatementSpan = null)
    {
        internal string Text => Node.Kind == NativeSourceNodeKind.Token ? Unit.Analysis.Lexical.Document!.GetText(Node.StartTokenIndex) : "";
        internal NativeSourceTokenKind Kind => Unit.Analysis.Lexical.Document!.Tokens[Node.StartTokenIndex].Kind;
        internal NativeSourceSpan Span => Node.Span;
        internal Guid SourceId => Unit.Source.Summary.Id;
        internal Term[] Children => ResolvedChildren ?? Planner.Terms(Unit, Node.Children, false);
    }
    private sealed class Scope(Scope? parent = null)
    { internal Dictionary<string, Term[]> Values { get; } = parent is null ? new(StringComparer.Ordinal) : new(parent.Values, StringComparer.Ordinal); }
    private sealed class Table(string family, string name, Term origin, NativeImportTableRole role)
    {
        internal string Family { get; } = family;
        internal string Name { get; } = name;
        internal Term Origin { get; } = origin;
        internal NativeImportTableRole Role { get; } = role;
        internal Dictionary<string, Chain> Chains { get; } = new(StringComparer.Ordinal);
        internal Dictionary<string, NamedSet> Sets { get; } = new(StringComparer.Ordinal);
        internal Dictionary<string, StaticTranslationMap> TranslationMaps { get; } = new(StringComparer.Ordinal);
        internal HashSet<string> Meters { get; } = new(StringComparer.Ordinal);
    }
    private sealed class Chain(string name, Term origin, Scope scope)
    {
        internal string Name { get; } = name;
        internal Term Origin { get; } = origin;
        internal Scope Scope { get; } = scope;
        internal string? Type; internal string? Hook; internal int? Priority; internal string Policy = "accept";
        internal bool HasPolicy;
        internal List<(Term Origin, Term[] Terms)> Rules { get; } = [];
    }
    private sealed class NamedSet(PolicyObjectReference? reference, string? dynamicFamily)
    { internal PolicyObjectReference? Reference { get; } = reference; internal string? DynamicFamily { get; } = dynamicFamily; internal bool Used; }

    private sealed partial class Planner
    {
        private readonly NativeImportRequest request;
        private readonly Dictionary<Guid, Unit> units = [];
        private readonly Dictionary<string, Table> tables = new(StringComparer.Ordinal);
        private readonly List<NativeImportSourceBinding> used = [];
        private readonly List<NativeImportMapping> mappings = [];
        private readonly List<NativeImportGap> gaps = [];
        private readonly HashSet<string> includeBindingsUsed = new(StringComparer.Ordinal);
        private readonly HashSet<Guid> stack = [];
        private int expanded;
        private readonly List<Term> obligations = [];
        private readonly HashSet<Term> completed = new(ReferenceEqualityComparer.Instance);
        private Term? root;

        internal Planner(NativeImportRequest request, IEnumerable<NativeSourceSnapshot> sources)
        {
            this.request = request;
            var totalBytes = 0; var totalTokens = 0;
            foreach (var source in sources.Take(MaximumSources + 1))
            {
                var analysis = NativeSourceAnalyzer.Analyze(source.Content.Text);
                totalBytes += source.Content.ByteLength; totalTokens += analysis.Lexical.Document?.Tokens.Count ?? 0;
                if (units.Count == MaximumSources || totalBytes > 2_097_152 || totalTokens > MaximumExpandedTerms || source.Summary.Id == Guid.Empty || source.Summary.Digest != source.Content.Digest || source.Summary.ByteLength != source.Content.ByteLength || !units.TryAdd(source.Summary.Id, new(source, analysis)))
                { gaps.Add(new(request.RootSourceId, new(0, 0, 1, 1), "import.sourcesInvalid")); break; }
            }
        }

        internal NativeImportPlan Run()
        {
            if (units.TryGetValue(request.RootSourceId, out var initial)) { used.Add(new(initial.Source.Summary.Id, initial.Source.Content.Digest)); }
            if (!units.TryGetValue(request.RootSourceId, out var unit) || unit.Analysis.Structure.Tree is not { } tree)
            { gaps.Add(new(request.RootSourceId, new(0, 0, 1, 1), "import.rootInvalid")); return Result(null, null, []); }
            root = Terms(unit, tree.Nodes).FirstOrDefault();
            if (request.Tables.Count is < 1 or > 4 || request.Tables.Any(t => !Enum.IsDefined(t.Role)) ||
                request.Tables.Select(t => t.Role).Distinct().Count() != request.Tables.Count ||
                request.Tables.Select(t => Key(t.Family, t.Name)).Distinct().Count() != request.Tables.Count ||
                request.Includes.Count > MaximumSources || request.Includes.Select(b => IncludeKey(b.SourceId, b.Path)).Distinct(StringComparer.Ordinal).Count() != request.Includes.Count)
            { AddGap(root, "import.choicesInvalid"); return Result(null, null, []); }
            Visit(unit, new Scope(), null, null, 0);
            foreach (var binding in request.Tables)
            { if (!tables.ContainsKey(Key(binding.Family, binding.Name))) { AddGap(root, "import.tableMappingUnused"); } }
            foreach (var binding in request.Includes)
            { if (!includeBindingsUsed.Contains(IncludeKey(binding.SourceId, binding.Path))) { AddGap(root, "import.includeBindingUnused"); } }
            JsonObject? bundle = null;
            Attempt(root, () => bundle = Lower());
            foreach (var obligation in obligations.Where(t => !completed.Contains(t))) { AddGap(obligation, "import.statementUnmapped"); }
            var objects = tables.Values.SelectMany(t => t.Sets.Values).Where(s => s.Reference is not null && s.Used).Select(s => s.Reference!).ToArray();
            foreach (var table in tables.Values)
            {
                if (table.Sets.Values.Any(s => !s.Used) || table.TranslationMaps.Values.Any(m => !m.Used))
                { AddGap(table.Origin, "import.unusedObjectUnsupported"); }
            }
            if (gaps.Count != 0 || bundle is null) { return Result(null, null, []); }
            var decoded = PolicyBundleJsonCodec.DecodeBundle(bundle.ToJsonString());
            if (decoded.Value is not { } policy) { foreach (var diagnostic in decoded.Diagnostics) { AddGap(root, "import.policy." + diagnostic.Code); } return Result(null, null, []); }
            var compiled = NftPolicyBundleCompiler.Compile(policy);
            if (!compiled.IsSuccess) { foreach (var diagnostic in compiled.Diagnostics) { AddGap(root, "import.policy." + diagnostic.Code); } return Result(null, null, []); }
            return Result(PolicyBundleJsonCodec.EncodeBundle(policy), compiled.Digest!.Value, objects);
        }

        private string IncludeKey(Guid id, string path) => (id == Guid.Empty ? request.RootSourceId : id).ToString("D") + "\0" + path;

        private NativeImportPlan Result(string? json, string? digest, IEnumerable<PolicyObjectReference> objects) => new(request, used, mappings, gaps, json, digest, objects);
        private void AddGap(Term? term, string code) => gaps.Add(new(term?.SourceId ?? request.RootSourceId, term?.Span ?? new(0, 0, 1, 1), code));
        private void Map(Term term, string disposition, string target)
        { completed.Add(term); mappings.Add(new(term.SourceId, term.StatementSpan ?? term.Span, disposition, target)); }
        private void Attempt(Term? origin, Action action)
        { try { action(); } catch (ImportFailure failure) { if (origin is not null) { completed.Add(origin); } AddGap(failure.Term, failure.Code); } catch (ArgumentException) { if (origin is not null) { completed.Add(origin); } AddGap(origin, "import.valueInvalid"); } }
        internal static void Require(bool condition, Term term, string code = "import.syntaxUnsupported")
        { if (!condition) { throw new ImportFailure(code, term); } }

        private void Visit(Unit unit, Scope scope, Table? table, Chain? chain, int depth)
        {
            if (used.All(s => s.SourceId != unit.Source.Summary.Id)) { used.Add(new(unit.Source.Summary.Id, unit.Source.Content.Digest)); }
            var tree = unit.Analysis.Structure.Tree;
            if (tree is null) { gaps.Add(new(unit.Source.Summary.Id, unit.Analysis.Structure.Summary.Diagnostic!.Span, "import.sourceInvalid")); return; }
            if (depth > MaximumIncludeDepth || !stack.Add(unit.Source.Summary.Id))
            { gaps.Add(new(unit.Source.Summary.Id, new(0, 0, 1, 1), "import.includeCycleOrDepth")); return; }
            var statements = table is null ? unit.Analysis.Declarations!.Statements : NativeSourceDeclarationParser.Partition(tree.Document, tree.Nodes, chain is not null);
            Read(unit, statements, scope, table, chain, depth);
            stack.Remove(unit.Source.Summary.Id);
        }

        private void Read(Unit unit, IReadOnlyList<NativeSourceStatement> statements, Scope scope, Table? table, Chain? chain, int depth)
        {
            foreach (var statement in statements)
            {
                var terms = Terms(unit, statement.Nodes); if (terms.Length == 0) { continue; }
                var start = terms[0].Span; var end = terms[^1].Span;
                var first = terms[0] with { StatementSpan = new(start.Offset, end.Offset + end.Length - start.Offset, start.Line, start.Column) }; terms[0] = first; obligations.Add(first);
                Attempt(first, () =>
                {
                    expanded += terms.Length; Require(expanded <= MaximumExpandedTerms, first, "import.expansionLimit");
                    switch (first.Text)
                    {
                        case "define":
                        case "redefine":
                            Require(terms.Length >= 4 && terms[2].Text == "=", first);
                            var name = Name(terms[1]);
                            Require(first.Text != "redefine" || scope.Values.ContainsKey(name), first, "import.definitionMissing");
                            Require(first.Text != "define" || !scope.Values.ContainsKey(name), first, "import.definitionDuplicate");
                            var definition = Expand(terms[3..], scope, 0);
                            ValidateDefinition(definition, first); scope.Values[name] = definition; Map(first, "definition", "source"); return;
                        case "undefine":
                            Require(terms.Length == 2 && scope.Values.Remove(Name(terms[1])), first, "import.definitionMissing"); Map(first, "definition", "source"); return;
                        case "include":
                            Require(terms.Length == 2, first);
                            var path = String(terms[1]); Require(path.Length <= 1024, first, "import.includePathTooLong"); var binding = request.Includes.SingleOrDefault(b => (b.SourceId == Guid.Empty ? request.RootSourceId : b.SourceId) == unit.Source.Summary.Id && b.Path == path);
                            Require(binding is not null, first, "import.includeBindingRequired");
                            Require(binding!.Sources.Count <= MaximumSources && (binding.Sources.Count != 0 || path.IndexOfAny(['*', '?', '[']) >= 0), first, "import.includeBindingInvalid");
                            includeBindingsUsed.Add(IncludeKey(binding.SourceId, path)); Map(first, "include", "source");
                            foreach (var id in binding.Sources)
                            { Require(units.ContainsKey(id), first, "import.includeSourceMissing"); Visit(units[id], scope, table, chain, depth + 1); }
                            return;
                        case "flush":
                            Require(table is null && terms.Length == 2 && terms[1].Text == "ruleset" && request.RestrictGlobalOperations, first, "import.scopeDecisionRequired");
                            Require(tables.Count == 0, first, "import.flushOrderUnsupported");
                            Map(first, "scope-restricted", "managed-resources-only"); return;
                        case "comment":
                            Require(table is not null && terms.Length == 2, first); _ = String(terms[1]); Map(first, "metadata-original", "source"); return;
                    }
                    if (chain is not null) { ReadChain(terms, scope, table!, chain); return; }
                    if (table is not null) { ReadTable(unit, terms, scope, table, depth); return; }
                    ReadRoot(unit, terms, scope, depth);
                });
            }
        }

        private static void ValidateDefinition(Term[] values, Term origin)
        {
            if (values.Length == 1 && values[0].Node.Kind == NativeSourceNodeKind.Braces)
            { values = Comma(values[0].Children, origin); }
            else if (values.Length > 1) { values = Comma(values, origin); }
            Require(values.Length is >= 1 and <= 64 && values.All(t => t.Node.Kind == NativeSourceNodeKind.Token && t.Kind is NativeSourceTokenKind.Bare or NativeSourceTokenKind.DoubleQuoted or NativeSourceTokenKind.AtReference), origin, "import.definitionExpressionUnsupported");
        }

        private Term[] Expand(IEnumerable<Term> input, Scope scope, int depth)
        {
            var result = new List<Term>();
            foreach (var term in input)
            {
                Require(depth <= 16 && ++expanded <= MaximumExpandedTerms, term, "import.expansionLimit");
                if (term.Kind == NativeSourceTokenKind.VariableReference && term.Node.Kind == NativeSourceNodeKind.Token)
                {
                    Require(scope.Values.TryGetValue(term.Text[1..], out var value), term, "import.definitionUnresolved");
                    result.AddRange(Expand(value!, scope, depth + 1));
                }
                else { result.Add(term.Node.Kind == NativeSourceNodeKind.Token ? term : term with { ResolvedChildren = Expand(term.Children, scope, depth + 1) }); }
            }
            return result.ToArray();
        }

        internal static Term[] Terms(Unit unit, IEnumerable<NativeSourceNode> nodes, bool separators = true) => nodes
            .Where(n => n.Kind != NativeSourceNodeKind.Token || (!unit.Analysis.Lexical.Document!.Tokens[n.StartTokenIndex].IsTrivia &&
                unit.Analysis.Lexical.Document.Tokens[n.StartTokenIndex].Kind != NativeSourceTokenKind.NewLine && (!separators || unit.Analysis.Lexical.Document.GetText(n.StartTokenIndex) != ";")))
            .Select(n => new Term(unit, n)).ToArray();
        private static string Key(string family, string name) => family + "\0" + name;
        private static string Name(Term term)
        {
            var name = String(term);
            Require(name.Length is >= 1 and <= 120 && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.'), term, "import.identifierUnsupported");
            Require(term.Kind == NativeSourceTokenKind.DoubleQuoted || char.IsAsciiLetter(name[0]) && !name.Contains('-'), term, "import.identifierUnsupported");
            return name;
        }
        private static string String(Term term)
        {
            Require(term.Node.Kind == NativeSourceNodeKind.Token && term.Kind is NativeSourceTokenKind.Bare or NativeSourceTokenKind.DoubleQuoted, term, "import.literalUnsupported");
            var value = term.Kind == NativeSourceTokenKind.DoubleQuoted ? term.Text[1..^1] : term.Text;
            Require(!value.Contains('\\') && !value.Any(char.IsControl), term, "import.escapeUnsupported"); return value;
        }
        private static int Integer(Term term)
        { Require(int.TryParse(term.Text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var value), term, "import.integerRequired"); return value; }
    }
}
