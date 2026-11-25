using Nergal.Core.Policy;

namespace Nergal.Nftables;

/// <summary>Explicit destination resource roles; source names never confer ownership.</summary>
public enum NativeImportTableRole
{
    /// <summary>Primary inet filter, including supported raw prerouting and MSS rules.</summary>
    Filter,
    /// <summary>Dual-stack inet NAT.</summary>
    Nat,
    /// <summary>Independent early inet filtering.</summary>
    Auxiliary,
    /// <summary>Bridge forward filtering and regular subchains.</summary>
    Bridge,
}

/// <summary>An explicit private source table mapping, without adoption or execution authority.</summary>
public sealed record NativeImportTableBinding(string Family, string Name, NativeImportTableRole Role)
{
    /// <summary>Omits private table identifiers.</summary>
    public override string ToString() => "Native table binding";
}

/// <summary>An exact include literal bound to ordered immutable uploaded snapshots; never a filesystem lookup.</summary>
public sealed class NativeImportIncludeBinding
{
    /// <summary>Snapshots the selected IDs in the declared expansion order.</summary>
    public NativeImportIncludeBinding(string path, IReadOnlyList<Guid> sources, Guid sourceId = default)
    { ArgumentNullException.ThrowIfNull(path); ArgumentNullException.ThrowIfNull(sources); Path = path; Sources = Array.AsReadOnly(sources.ToArray()); SourceId = sourceId; }
    /// <summary>Gets the private original include literal.</summary>
    public string Path { get; }
    /// <summary>Gets the including snapshot identity; empty explicitly denotes the request root.</summary>
    public Guid SourceId { get; }
    /// <summary>Gets ordered source identities, empty only for an explicitly empty wildcard include.</summary>
    public IReadOnlyList<Guid> Sources { get; }
    /// <summary>Omits private include paths.</summary>
    public override string ToString() => "Native include binding";
}

/// <summary>Immutable operator conversion choices; no option permits dropping an unsupported rule.</summary>
public sealed class NativeImportRequest
{
    /// <summary>Snapshots source, resource and include choices for deterministic review.</summary>
    public NativeImportRequest(Guid rootSourceId, IReadOnlyList<NativeImportTableBinding> tables,
        IReadOnlyList<NativeImportIncludeBinding> includes, bool restrictGlobalOperations = false)
    {
        ArgumentNullException.ThrowIfNull(tables); ArgumentNullException.ThrowIfNull(includes);
        if (tables.Any(t => t is null) || includes.Any(i => i is null)) { throw new ArgumentException("import.choicesInvalid"); }
        RootSourceId = rootSourceId; Tables = Array.AsReadOnly(tables.ToArray()); Includes = Array.AsReadOnly(includes.ToArray()); RestrictGlobalOperations = restrictGlobalOperations;
    }
    /// <summary>Gets the immutable root source identity.</summary>
    public Guid RootSourceId { get; }
    /// <summary>Gets explicit unique table mappings.</summary>
    public IReadOnlyList<NativeImportTableBinding> Tables { get; }
    /// <summary>Gets exact include bindings; no ambient search is allowed.</summary>
    public IReadOnlyList<NativeImportIncludeBinding> Includes { get; }
    /// <summary>Gets explicit consent to replace a source-wide flush with selected managed-resource scope only.</summary>
    public bool RestrictGlobalOperations { get; }
    /// <summary>Omits private source identifiers and mapping contents.</summary>
    public override string ToString() => "Native import request";
}

/// <summary>An immutable input identity/digest used in a plan.</summary>
public sealed record NativeImportSourceBinding(Guid SourceId, string Digest);
/// <summary>One accounted-for source statement and its intended target; no source values are copied.</summary>
public sealed record NativeImportMapping(Guid SourceId, NativeSourceSpan Span, string Disposition, string Target);
/// <summary>A blocking, value-free conversion gap at original source coordinates.</summary>
public sealed record NativeImportGap(Guid SourceId, NativeSourceSpan Span, string Code);

/// <summary>A complete source-bound conversion review, with no candidate whenever any gap remains.</summary>
public sealed class NativeImportPlan
{
    internal NativeImportPlan(NativeImportRequest request, IEnumerable<NativeImportSourceBinding> sources,
        IEnumerable<NativeImportMapping> mappings, IEnumerable<NativeImportGap> gaps, string? policyJson, string? candidateDigest,
        IEnumerable<PolicyObjectReference> objects)
    {
        Request = request; Sources = Array.AsReadOnly(sources.ToArray()); Mappings = Array.AsReadOnly(mappings.ToArray());
        Gaps = Array.AsReadOnly(gaps.ToArray()); PolicyJson = policyJson; CandidateDigest = candidateDigest;
        Objects = Array.AsReadOnly(objects.ToArray());
    }
    /// <summary>Gets the exact immutable operator choices.</summary>
    public NativeImportRequest Request { get; }
    /// <summary>Gets all consumed immutable sources in first-use order.</summary>
    public IReadOnlyList<NativeImportSourceBinding> Sources { get; }
    /// <summary>Gets source-bound dispositions in traversal order.</summary>
    public IReadOnlyList<NativeImportMapping> Mappings { get; }
    /// <summary>Gets all discovered blocking gaps; no skip/approve-unsupported option exists.</summary>
    public IReadOnlyList<NativeImportGap> Gaps { get; }
    /// <summary>Gets canonical complete intent only when all statements and compilation succeed.</summary>
    public string? PolicyJson { get; }
    /// <summary>Gets the exact deterministic create-only candidate digest, without ownership authority.</summary>
    public string? CandidateDigest { get; }
    /// <summary>Gets pinned objects to create atomically with a reviewed revision; review itself creates none.</summary>
    public IReadOnlyList<PolicyObjectReference> Objects { get; }
    /// <summary>Gets whether a separate authorized revision-creation step may consider this complete plan.</summary>
    public bool CanCreateRevision => Gaps.Count == 0 && PolicyJson is not null && CandidateDigest is not null;
    /// <summary>Omits all private source and intent values.</summary>
    public override string ToString() => $"Native import plan ({Gaps.Count} gaps; no apply authority)";
}
