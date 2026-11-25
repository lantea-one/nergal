using Nergal.Core.Controller;

namespace Nergal.Web.Tests;

/// <summary>Fleet charts aggregate live agent results while preserving gaps in observation coverage.</summary>
public sealed class DashboardHostObservationsTests
{
    /// <summary>Multiple hosts in one state contribute individually and each reported status retains its meaning.</summary>
    [Fact]
    public void MixedFleet_UsesRegisteredDenominatorAndLiveClassifications()
    {
        var fleet = Enumerable.Range(1, 8).Select(Host).ToArray();
        var chart = DashboardHostObservations.From(fleet,
        [
            Status(fleet[0], "matched"),
            Status(fleet[1], "matched"),
            Status(fleet[2], "drift"),
            Status(fleet[3], "missing"),
            Status(fleet[4], "pending"),
            Status(fleet[5], "unavailable", reachable: false),
            Status(fleet[6], "unqueried", reachable: false),
            Status(fleet[7], "online"),
        ]);

        Assert.Equal(8, chart.RegisteredCount);
        Assert.Equal(5, chart.ObservedCount);
        var bars = chart.Counts.Where(count => count.IsObserved).ToDictionary(count => count.State, count => count.Count);
        Assert.Equal(4, bars.Count);
        Assert.Equal(2, bars[DashboardHostState.Matched]);
        Assert.Equal(1, bars[DashboardHostState.Drift]);
        Assert.Equal(1, bars[DashboardHostState.MissingBaseline]);
        Assert.Equal(1, bars[DashboardHostState.ActiveChange]);
        var gaps = chart.Counts.Where(count => !count.IsObserved).ToDictionary(count => count.State, count => count.Count);
        Assert.Equal(3, gaps.Count);
        Assert.Equal(1, gaps[DashboardHostState.Unavailable]);
        Assert.Equal(1, gaps[DashboardHostState.Unqueried]);
        Assert.Equal(1, gaps[DashboardHostState.Unknown]);
    }

    /// <summary>Cached revisions, failed queries, and missing summaries cannot supply observations.</summary>
    [Fact]
    public void NoUsableStatus_ProducesOnlyExplicitGaps()
    {
        var fleet = Enumerable.Range(1, 4).Select(Host).ToArray();
        var chart = DashboardHostObservations.From(fleet,
        [
            Status(fleet[0], "matched", reachable: false),
            Status(fleet[1], "unqueried", reachable: false),
            Status(fleet[2], "new-agent-state"),
        ]);

        Assert.Equal(4, chart.RegisteredCount);
        Assert.Equal(0, chart.ObservedCount);
        Assert.DoesNotContain(chart.Counts, count => count.IsObserved);
        Assert.Contains(new DashboardHostCount(DashboardHostState.Unavailable, 1), chart.Counts);
        Assert.Contains(new DashboardHostCount(DashboardHostState.Unqueried, 1), chart.Counts);
        Assert.Contains(new DashboardHostCount(DashboardHostState.Unknown, 2), chart.Counts);
    }

    /// <summary>Ambiguous summaries and observations for other registrations cannot inflate the chart.</summary>
    [Fact]
    public void DuplicateOrUnregisteredSummaries_DoNotLookLikeObservedHosts()
    {
        var registered = Host(1);
        var chart = DashboardHostObservations.From([registered],
        [
            Status(registered, "matched"),
            Status(registered, "drift"),
            Status(Host(2), "matched"),
        ]);

        Assert.Equal(1, chart.RegisteredCount);
        Assert.Equal(0, chart.ObservedCount);
        Assert.Equal(new DashboardHostCount(DashboardHostState.Unknown, 1), Assert.Single(chart.Counts));
    }

    /// <summary>Fresh installations have no fleet denominator and no chart measurements.</summary>
    [Fact]
    public void NoHosts_ProducesNoCounts()
    {
        var chart = DashboardHostObservations.From([], []);

        Assert.Equal(0, chart.RegisteredCount);
        Assert.Empty(chart.Counts);
    }

    private static ManagedHostRecord Host(int id) =>
        new(new Guid(id, 0, 0, new byte[8]), $"synthetic-{id}", AgentTransportKind.Unix, $"/run/nergal-fixture/host-{id}.sock",
            expectedServerUserId: 23456, lastKnownRevision: 7);

    private static HostHealthSummary Status(ManagedHostRecord host, string state, bool reachable = true) => new()
    {
        Host = host,
        Reachable = reachable,
        StateLabel = state,
        ReportedRevision = host.LastKnownRevision,
    };
}
