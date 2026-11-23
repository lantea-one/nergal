using Nergal.Core.Controller;

namespace Nergal.Web;

/// <summary>A directional comparison of two stored versions of the same list; it never infers traffic or active host usage.</summary>
public sealed class ObjectVersionComparison
{
    private ObjectVersionComparison(ReusableObjectVersion baseline, ReusableObjectVersion target)
    {
        Baseline = baseline;
        Target = target;
        AddedEntries = Array.AsReadOnly(target.Content.Entries.Except(baseline.Content.Entries, StringComparer.Ordinal).ToArray());
        RemovedEntries = Array.AsReadOnly(baseline.Content.Entries.Except(target.Content.Entries, StringComparer.Ordinal).ToArray());
        UnchangedEntryCount = baseline.Content.Entries.Intersect(target.Content.Entries, StringComparer.Ordinal).Count();
    }

    /// <summary>Gets the stored version being compared from.</summary>
    public ReusableObjectVersion Baseline { get; }
    /// <summary>Gets the stored version being compared to; this can be older than the baseline.</summary>
    public ReusableObjectVersion Target { get; }
    /// <summary>Gets canonical entries present only in the target, retaining canonical list order.</summary>
    public IReadOnlyList<string> AddedEntries { get; }
    /// <summary>Gets canonical entries present only in the baseline, retaining canonical list order.</summary>
    public IReadOnlyList<string> RemovedEntries { get; }
    /// <summary>Gets the number of identical canonical entries in both versions, without merging or subtracting networks.</summary>
    public int UnchangedEntryCount { get; }
    /// <summary>Gets whether the plain-text description differs.</summary>
    public bool DescriptionChanged => Baseline.Content.Description != Target.Content.Description;

    /// <summary>Compares immutable snapshots; different identities, names or element types are rejected.</summary>
    /// <exception cref="ArgumentNullException">Either snapshot is null.</exception>
    /// <exception cref="ArgumentException">The snapshots do not represent the same list identity and type.</exception>
    public static ObjectVersionComparison Create(ReusableObjectVersion baseline, ReusableObjectVersion target)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(target);
        if (baseline.Id != target.Id || baseline.Content.Name != target.Content.Name || baseline.Content.Kind != target.Content.Kind)
        { throw new ArgumentException("object.comparisonIdentityMismatch"); }
        return new(baseline, target);
    }
}
