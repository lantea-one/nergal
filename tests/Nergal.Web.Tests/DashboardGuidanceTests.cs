using Nergal.Core.Controller;

namespace Nergal.Web.Tests;

/// <summary>Overview guidance cannot conceal pending recovery, prompt Auditor mutations or claim saved intent is applied.</summary>
public sealed class DashboardGuidanceTests
{
    /// <summary>Pending confirmation and observed drift outrank setup, even for a read-only viewer.</summary>
    [Theory]
    [InlineData(true, "pending")]
    [InlineData(false, "pending")]
    [InlineData(true, "drift")]
    [InlineData(false, "missing")]
    public void PendingOrRecovery_TakesPriorityOverInitialSetup(bool administrator, string state)
    {
        var health = Host(state);
        var next = DashboardGuidance.Describe(administrator, true, false, 1, [health]);
        Assert.Equal(DashboardDestination.Apply, next.Destination);
        Assert.Equal(health.Host.Id, next.HostId);
    }

    /// <summary>Only Administrators receive create/connect guidance; preparing a policy does not require a host.</summary>
    [Fact]
    public void Setup_DependsOnCurrentSavedStateAndRole()
    {
        Assert.Equal(DashboardDestination.Policies, DashboardGuidance.Describe(true, false, false, 0, []).Destination);
        Assert.Equal(DashboardDestination.Hosts, DashboardGuidance.Describe(true, false, true, 0, []).Destination);
        Assert.Equal(DashboardDestination.Audit, DashboardGuidance.Describe(false, false, false, 0, []).Destination);
        Assert.Equal(DashboardDestination.Policies, DashboardGuidance.Describe(false, false, true, 0, []).Destination);
    }

    /// <summary>Unknown, missing and failed queries must not suggest that a host is ready for a change.</summary>
    [Theory]
    [InlineData("unqueried", false)]
    [InlineData("unavailable", false)]
    [InlineData("unknown", true)]
    public void IncompleteObservations_LeadToConnectionInspection(string state, bool reachable)
    {
        Assert.Equal(DashboardDestination.Hosts, DashboardGuidance.Describe(true, true, true, 1, [Host(state, reachable)]).Destination);
        Assert.Equal(DashboardDestination.Hosts, DashboardGuidance.Describe(true, true, true, 2, [Host("matched")]).Destination);
        Assert.Equal(DashboardDestination.Hosts, DashboardGuidance.Describe(true, false, true, 1, [Host("matched")]).Destination);
    }

    /// <summary>A matched baseline leads to revision review, never to an automatic apply or confirmation.</summary>
    [Fact]
    public void MatchedBaseline_StillRequiresPolicyReview()
    {
        var next = DashboardGuidance.Describe(true, true, true, 1, [Host("matched")]);
        Assert.Equal(DashboardDestination.Policies, next.Destination);
        Assert.Null(next.HostId);
    }

    private static HostHealthSummary Host(string state, bool reachable = true) => new()
    {
        Host = new(Guid.Parse("11111111-1111-4111-8111-111111111111"), "synthetic", AgentTransportKind.Unix, "/run/nergal-fixture/control.sock", 0),
        Reachable = reachable,
        StateLabel = state,
    };
}
