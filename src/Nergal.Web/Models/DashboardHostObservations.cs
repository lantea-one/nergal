using Nergal.Core.Controller;

namespace Nergal.Web;

internal enum DashboardHostState
{
    Matched,
    Drift,
    MissingBaseline,
    ActiveChange,
    Unavailable,
    Unqueried,
    Unknown,
}

internal sealed record DashboardHostCount(DashboardHostState State, int Count)
{
    internal bool IsObserved => State is DashboardHostState.Matched or DashboardHostState.Drift
        or DashboardHostState.MissingBaseline or DashboardHostState.ActiveChange;
}

/// <summary>Counts registered hosts by the result of the current Overview status queries.</summary>
internal sealed record DashboardHostObservations(int RegisteredCount, IReadOnlyList<DashboardHostCount> Counts)
{
    internal int ObservedCount => Counts.Where(count => count.IsObserved).Sum(count => count.Count);

    /// <summary>Uses only current summaries that belong to the registered fleet. Cached revisions cannot fill gaps.</summary>
    internal static DashboardHostObservations From(IReadOnlyList<ManagedHostRecord> hosts, IReadOnlyList<HostHealthSummary> health)
    {
        var summaries = health.ToLookup(summary => summary.Host.Id);
        var registeredIds = hosts.Select(host => host.Id).Distinct().ToArray();
        var counts = registeredIds
            .Select(id => Classify(summaries[id]))
            .GroupBy(state => state)
            .OrderBy(group => group.Key)
            .Select(group => new DashboardHostCount(group.Key, group.Count()))
            .ToArray();

        return new DashboardHostObservations(registeredIds.Length, Array.AsReadOnly(counts));
    }

    private static DashboardHostState Classify(IEnumerable<HostHealthSummary> summaries)
    {
        // An absent or ambiguous summary cannot establish what the agent reported.
        using var entries = summaries.GetEnumerator();
        if (!entries.MoveNext())
        {
            return DashboardHostState.Unknown;
        }

        var health = entries.Current;
        if (entries.MoveNext())
        {
            return DashboardHostState.Unknown;
        }

        return (health.Reachable, health.StateLabel) switch
        {
            (false, "unqueried") => DashboardHostState.Unqueried,
            (false, _) => DashboardHostState.Unavailable,
            (true, "matched") => DashboardHostState.Matched,
            (true, "drift") => DashboardHostState.Drift,
            (true, "missing") => DashboardHostState.MissingBaseline,
            // The existing summary groups multiple active operation phases under "pending".
            (true, "pending") => DashboardHostState.ActiveChange,
            _ => DashboardHostState.Unknown,
        };
    }
}
