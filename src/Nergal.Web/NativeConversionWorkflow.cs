using System.Text.Json;
using System.Runtime.Versioning;
using System.Text.Json.Serialization;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;
using Nergal.Nftables;

namespace Nergal.Web;

/// <summary>Guided table mapping input; source names are private data, never executable text.</summary>
public sealed class NativeConversionTableForm
{
    /// <summary>Source address family.</summary>
    public string Family { get; set; } = "";
    /// <summary>Original source table name.</summary>
    public string Name { get; set; } = "";
    /// <summary>Explicit destination role, blank until selected.</summary>
    public string Role { get; set; } = "";
}
/// <summary>Ordered uploaded include selection; no server path is opened.</summary>
public sealed class NativeConversionIncludeForm
{
    /// <summary>Identity of the including snapshot; empty denotes the root.</summary>
    public Guid SourceId { get; set; }
    /// <summary>Exact source include literal.</summary>
    public string Path { get; set; } = "";
    /// <summary>Selected immutable IDs in submitted expansion order.</summary>
    public List<Guid> Sources { get; set; } = [];
    /// <summary>Explicit empty wildcard binding; not an unsupported-content bypass.</summary>
    public bool EmptyWildcard { get; set; }
}
/// <summary>Guided conversion choices without raw JSON or source execution.</summary>
public sealed class NativeConversionForm
{
    /// <summary>Immutable root source.</summary>
    public Guid SourceId { get; set; }
    /// <summary>Explicit table roles.</summary>
    public List<NativeConversionTableForm> Tables { get; set; } = [];
    /// <summary>Ordered include dependencies.</summary>
    public List<NativeConversionIncludeForm> Includes { get; set; } = [];
    /// <summary>Explicit source-wide flush restriction.</summary>
    public bool RestrictGlobalOperations { get; set; }
}
/// <summary>One source's guided conversion view, durable review history and optional selected result.</summary>
public sealed record NativeConversionPage(NativeConversionForm Form, IReadOnlyList<NativeSourceSummary> AvailableSources,
    IReadOnlyList<NativeConversionPlanRecord> History, NativeConversionPlanRecord? Selected, IReadOnlyList<NativeImportGap> Gaps,
    IReadOnlyList<NativeImportMapping> Mappings, string? Candidate, string? Error = null);

/// <summary>Coordinates pure conversion with immutable database originals; never dispatches an agent operation.</summary>
[SupportedOSPlatform("linux")]
internal sealed class NativeConversionWorkflow(ControllerStateStore store)
{
    internal static JsonSerializerOptions Json { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter() },
    };

    internal NativeConversionPage Page(Guid sourceId, Guid? planId = null, NativeConversionForm? input = null, string? error = null)
    {
        var selected = planId.HasValue ? store.ReadNativeConversionPlan(planId.Value) : null;
        if (selected is not null && selected.Content.RootSourceId != sourceId) { throw new ArgumentException("conversion.sourceMismatch"); }
        var form = input ?? (selected is null ? new NativeConversionForm { SourceId = sourceId } : Form(Deserialize(selected.Content.RequestJson)));
        var sources = Load(Choices(form)); Discover(form, sources);
        using var report = selected is null ? null : JsonDocument.Parse(selected.Content.ReportJson);
        var gaps = report is null ? [] : JsonSerializer.Deserialize<NativeImportGap[]>(report.RootElement.GetProperty("gaps").GetRawText(), Json)!;
        var mappings = report is null ? [] : JsonSerializer.Deserialize<NativeImportMapping[]>(report.RootElement.GetProperty("mappings").GetRawText(), Json)!;
        string? candidate = null;
        if (selected?.Content.PolicyJson is { } policy)
        { candidate = NftPolicyBundleCompiler.Compile(Nergal.Core.Policy.PolicyBundleJsonCodec.DecodeBundle(policy).Value!).Candidate; }
        return new(form, store.ListNativeSources(), store.ListNativeConversionPlans(sourceId), selected, gaps, mappings, candidate, error);
    }

    internal NativeConversionPlanRecord Review(NativeConversionForm form, string actor)
    {
        var request = Choices(form); var content = Build(request);
        return store.SaveNativeConversionPlan(content, actor, NergalRoles.Administrator);
    }
    internal PolicyRevisionRecord Commit(Guid id, string digest, string actor)
    {
        var saved = store.ReadNativeConversionPlan(id) ?? throw new ArgumentException("conversion.notFound");
        return store.CommitNativeConversionPlan(id, digest, Build(Deserialize(saved.Content.RequestJson)), actor, NergalRoles.Administrator);
    }
    private NativeConversionPlanContent Build(NativeImportRequest request)
    {
        var plan = NativeImportPlanner.Plan(request, Load(request));
        var report = JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            sourceBindings = plan.Sources.Select(s => new NativeConversionSource(s.SourceId, s.Digest)),
            plan.Mappings,
            plan.Gaps
        }, Json);
        return new(request.RootSourceId, JsonSerializer.Serialize(request, Json), report, plan.PolicyJson, plan.CandidateDigest);
    }
    private NativeSourceSnapshot[] Load(NativeImportRequest request)
    {
        var ids = request.Includes.SelectMany(i => i.Sources.Append(i.SourceId == Guid.Empty ? request.RootSourceId : i.SourceId)).Prepend(request.RootSourceId).Distinct().Take(33).ToArray();
        if (ids.Length > NativeImportPlanner.MaximumSources) { throw new ArgumentException("conversion.sourceLimit"); }
        return ids.Select(id => store.ReadNativeSource(id) ?? throw new ArgumentException("conversion.sourceMissing")).ToArray();
    }
    private static NativeImportRequest Deserialize(string json) => JsonSerializer.Deserialize<NativeImportRequest>(json, Json) ?? throw new ArgumentException("conversion.corrupt");
    private static NativeImportRequest Choices(NativeConversionForm form)
    {
        if (form.Tables.Count > 16 || form.Includes.Count > 32 || form.Includes.Any(i => i.Sources.Count > 32)) { throw new ArgumentException("conversion.choiceLimit"); }
        if (form.Tables.Any(t => t.Role.Length != 0 && (!Enum.TryParse<NativeImportTableRole>(t.Role, out var r) || !Enum.IsDefined(r))) ||
            form.Includes.Any(i => i.EmptyWildcard && i.Sources.Any(id => id != Guid.Empty))) { throw new ArgumentException("conversion.choiceInvalid"); }
        var tables = form.Tables.Where(t => Enum.TryParse<NativeImportTableRole>(t.Role, out var role) && Enum.IsDefined(role))
            .Select(t => new NativeImportTableBinding(t.Family, t.Name, Enum.Parse<NativeImportTableRole>(t.Role))).ToArray();
        var includes = form.Includes.Where(i => i.Sources.Any(id => id != Guid.Empty) || i.EmptyWildcard).Select(i => new NativeImportIncludeBinding(i.Path, i.Sources.Where(id => id != Guid.Empty).ToArray(), i.SourceId)).ToArray();
        return new(form.SourceId, tables, includes, form.RestrictGlobalOperations);
    }
    private static NativeConversionForm Form(NativeImportRequest request) => new()
    {
        SourceId = request.RootSourceId,
        RestrictGlobalOperations = request.RestrictGlobalOperations,
        Tables = request.Tables.Select(t => new NativeConversionTableForm { Family = t.Family, Name = t.Name, Role = t.Role.ToString() }).ToList(),
        Includes = request.Includes.Select(i => new NativeConversionIncludeForm { SourceId = i.SourceId, Path = i.Path, Sources = i.Sources.ToList(), EmptyWildcard = i.Sources.Count == 0 }).ToList(),
    };

    private static void Discover(NativeConversionForm form, IEnumerable<NativeSourceSnapshot> sources)
    {
        // This populates guided choices only. The planner alone validates actual context and complete consumption.
        foreach (var source in sources)
        {
            var analysis = NativeSourceAnalyzer.Analyze(source.Content.Text);
            if (analysis.Lexical.Document is not { } document) { continue; }
            var tokens = document.Tokens.Select((token, index) => (token, index)).Where(t => !t.token.IsTrivia && t.token.Kind != NativeSourceTokenKind.NewLine).ToArray();
            for (var i = 0; i + 1 < tokens.Length; i++)
            {
                if (tokens[i].token.Kind != NativeSourceTokenKind.Bare || document.GetText(tokens[i].index) != "include") { continue; }
                var next = tokens[i + 1]; if (next.token.Kind is not (NativeSourceTokenKind.DoubleQuoted or NativeSourceTokenKind.Bare)) { continue; }
                var path = document.GetText(next.index); if (next.token.Kind == NativeSourceTokenKind.DoubleQuoted) { path = path[1..^1]; }
                if (path.Length <= 1024 && form.Includes.All(b => (b.SourceId == Guid.Empty ? form.SourceId : b.SourceId) != source.Summary.Id || b.Path != path) && form.Includes.Count < 32) { form.Includes.Add(new() { SourceId = source.Summary.Id, Path = path }); }
            }
            if (analysis.Declarations is not { } declarations) { continue; }
            foreach (var statement in declarations.Statements)
            {
                string? family = null; string? name = null;
                if (statement.Kind == NativeSourceStatementKind.Table)
                { family = statement.FamilyTokenIndex is { } f ? document.GetText(f) : "ip"; name = document.GetText(statement.NameTokenIndex!.Value); }
                else if (statement.Kind == NativeSourceStatementKind.Command)
                {
                    var head = statement.Nodes.Where(n => n.Kind == NativeSourceNodeKind.Token && !document.Tokens[n.StartTokenIndex].IsTrivia).Select(n => document.GetText(n.StartTokenIndex)).ToArray();
                    if (head.Length >= 4 && head[0] is "create" or "add" && head[1] == "table") { family = head[2]; name = head[3]; }
                }
                if (family is null || name is null) { continue; }
                if (name.StartsWith('"') && name.EndsWith('"')) { name = name[1..^1]; }
                if (form.Tables.All(t => t.Family != family || t.Name != name) && form.Tables.Count < 16) { form.Tables.Add(new() { Family = family, Name = name }); }
            }
        }
    }
}
