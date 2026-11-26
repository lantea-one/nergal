using System.Runtime.Versioning;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Nergal.ControllerState;
using Nergal.Core.Agent;
using Nergal.Core.Controller;
using Nergal.Core.Identity;
using Nergal.Web.Controllers;

namespace Nergal.Web.Tests;

/// <summary>Verifies the authenticated status workflow and Overview's handling of previous observations.</summary>
[SupportedOSPlatform("linux")]
public sealed class DurableHostObservationWorkflowTests
{
    /// <summary>Only settled status replies can synchronize the existing last-known revision.</summary>
    [Theory]
    [InlineData(AgentControlOutcome.Matched, false, HostObservationState.Matched, true)]
    [InlineData(AgentControlOutcome.Matched, true, HostObservationState.Pending, false)]
    [InlineData(AgentControlOutcome.Confirmed, true, HostObservationState.Pending, false)]
    [InlineData(AgentControlOutcome.RolledBack, false, HostObservationState.Online, true)]
    [InlineData(AgentControlOutcome.Drift, false, HostObservationState.Drift, false)]
    [InlineData(AgentControlOutcome.Unbound, false, HostObservationState.Missing, false)]
    [InlineData(AgentControlOutcome.AppliedPendingConfirmation, true, HostObservationState.Pending, false)]
    [InlineData(AgentControlOutcome.Busy, true, HostObservationState.Pending, false)]
    public async Task StatusPersistsClassificationAndReceiptTime(
        AgentControlOutcome outcome, bool activeOperation, HostObservationState state, bool synchronizesRevision)
    {
        using var fixture = new Fixture();
        var receiptTime = fixture.Clock.Now.AddSeconds(1);
        var workflow = fixture.Workflow(() =>
        {
            fixture.Clock.Now = receiptTime;
            return new AgentControlReply(outcome, revision: 7, operationId: activeOperation ? Guid.NewGuid() : null);
        });

        var result = await workflow.QueryHostStatusAsync(fixture.Host.Id, TestContext.Current.CancellationToken);

        var expected = new HostObservation(fixture.Host.Id, state, 7, receiptTime.ToUniversalTime());
        Assert.Equal(expected, result.Observation);
        Assert.Equal(TimeSpan.Zero, result.Observation!.ObservedAtUtc.Offset);
        var reopened = fixture.Reopen();
        Assert.Equal(expected, reopened.ReadHostObservation(fixture.Host.Id));
        Assert.Equal(synchronizesRevision ? 7UL : 9UL, reopened.GetHost(fixture.Host.Id)!.LastKnownRevision);
        Assert.Single(reopened.ListAuditEntries());
    }

    /// <summary>Failed or skipped status checks preserve the saved state without populating the live chart or guidance.</summary>
    [Theory]
    [InlineData(AgentControlOutcome.Unavailable, "transport.tlsUnavailable")]
    [InlineData(AgentControlOutcome.Unavailable, "observation.unavailable")]
    [InlineData(AgentControlOutcome.Denied, null)]
    [InlineData(AgentControlOutcome.InvalidRequest, null)]
    [InlineData(AgentControlOutcome.Rejected, "status.rejected")]
    [InlineData(AgentControlOutcome.Busy, "server.busy")]
    [InlineData(null, null)]
    public async Task OverviewShowsSavedObservationAsPrevious(AgentControlOutcome? failure, string? errorCode)
    {
        using var fixture = new Fixture();
        var live = await fixture.DashboardAsync(fixture.Workflow(() => new AgentControlReply(AgentControlOutcome.Drift, revision: 8)));
        var liveHealth = Assert.Single(live.HostHealth);
        var observation = Assert.IsType<HostObservation>(liveHealth.CurrentObservation);
        Assert.Null(liveHealth.PreviousObservation);
        Assert.Equal(DashboardDestination.Apply, live.NextAction.Destination);
        Assert.Equal(1, DashboardHostObservations.From(live.Hosts, live.HostHealth).ObservedCount);

        fixture.Clock.Now = fixture.Clock.Now.AddMinutes(3);
        var reopened = fixture.Reopen();
        ulong? unavailableRevision = errorCode == "observation.unavailable" ? 99UL : null;
        var workflow = failure is { } outcome
            ? new ApplyWorkflowService(reopened,
                new StatusDispatcher(() => new AgentControlReply(outcome, revision: unavailableRevision, errorCode: errorCode)), fixture.Clock)
            : null;
        var dashboard = await fixture.DashboardAsync(workflow, reopened);

        var health = Assert.Single(dashboard.HostHealth);
        Assert.False(health.Reachable);
        Assert.Equal(failure is null ? "unqueried" : "unavailable", health.StateLabel);
        Assert.Null(health.CurrentObservation);
        Assert.Equal(observation, health.PreviousObservation);
        Assert.Equal(observation, reopened.ReadHostObservation(fixture.Host.Id));
        Assert.Equal(9UL, reopened.GetHost(fixture.Host.Id)!.LastKnownRevision);
        Assert.Equal(DashboardDestination.Audit, dashboard.NextAction.Destination);
        Assert.Equal(0, DashboardHostObservations.From(dashboard.Hosts, dashboard.HostHealth).ObservedCount);
    }

    /// <summary>A status request dispatched before a revision update cannot reverse the new last-known revision.</summary>
    [Fact]
    public async Task InFlightStatusCannotOverwriteChangedLastKnownRevision()
    {
        using var fixture = new Fixture();
        var workflow = fixture.Workflow(() =>
        {
            fixture.Store.UpdateHostLastRevision(fixture.Host.Id, 10);
            return new AgentControlReply(AgentControlOutcome.Matched, revision: 8);
        });

        var result = await workflow.QueryHostStatusAsync(fixture.Host.Id, TestContext.Current.CancellationToken);

        Assert.Equal(10UL, result.Host!.LastKnownRevision);
        Assert.Equal(8UL, result.Observation!.ReportedRevision);
        Assert.Equal(result.Observation, fixture.Store.ReadHostObservation(fixture.Host.Id));
    }

    /// <summary>A reply in flight during removal does not recreate the registration or record an orphan observation.</summary>
    [Fact]
    public async Task InFlightStatusDoesNotRecreateDeletedRegistration()
    {
        using var fixture = new Fixture();
        var workflow = fixture.Workflow(() =>
        {
            Assert.True(fixture.Store.DeleteHost(fixture.Host.Id, fixture.Actor, NergalRoles.Administrator));
            return new AgentControlReply(AgentControlOutcome.Matched, revision: 8);
        });

        var result = await workflow.QueryHostStatusAsync(fixture.Host.Id, TestContext.Current.CancellationToken);

        Assert.False(result.HostFound);
        Assert.Null(result.Observation);
        Assert.Null(fixture.Store.ReadHostObservation(fixture.Host.Id));
    }

    /// <summary>A pending reply that loses the ordering check cannot drive the chart or review guidance.</summary>
    [Fact]
    public async Task SupersededPendingReplyIsShownOnlyAsAGap()
    {
        using var fixture = new Fixture();
        var winner = new HostObservation(fixture.Host.Id, HostObservationState.Matched, 9,
            fixture.Clock.Now.AddSeconds(1).ToUniversalTime());
        var workflow = fixture.Workflow(() =>
        {
            Assert.True(fixture.Store.RecordHostObservation(winner));
            return new AgentControlReply(AgentControlOutcome.AppliedPendingConfirmation, revision: 8,
                operationId: Guid.NewGuid());
        });

        var dashboard = await fixture.DashboardAsync(workflow);
        var health = Assert.Single(dashboard.HostHealth);
        Assert.Equal("Status superseded", health.StateLabel);
        Assert.Null(health.CurrentObservation);
        Assert.Equal(winner, health.PreviousObservation);
        Assert.Equal(winner, fixture.Store.ReadHostObservation(fixture.Host.Id));
        Assert.Equal(DashboardDestination.Audit, dashboard.NextAction.Destination);
        Assert.Equal(0, DashboardHostObservations.From(dashboard.Hosts, dashboard.HostHealth).ObservedCount);
    }

    private sealed class StatusDispatcher(Func<AgentControlReply> reply) : IAgentControlDispatcher
    {
        public Task<AgentControlReply> SendAsync(ManagedHostRecord host, AgentControlRequest request, CancellationToken cancellationToken)
        {
            Assert.Equal(AgentControlCommand.Status, request.Command);
            return Task.FromResult(reply());
        }
    }

    private sealed class FixtureClock : TimeProvider
    {
        internal DateTimeOffset Now { get; set; } = new(2026, 11, 25, 12, 30, 0, TimeSpan.FromHours(3));

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class Fixture : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("nergal-observation-");

        internal Fixture()
        {
            Store = ControllerStateStore.Initialize(new(_directory.FullName));
            Store.RegisterHost(Host, Actor, NergalRoles.Administrator);
        }

        internal string Actor { get; } = ControllerActorIdentity.FromLocalAccount(Guid.NewGuid());

        internal ManagedHostRecord Host { get; } = new(Guid.NewGuid(), "synthetic-host", AgentTransportKind.Unix,
            "/run/nergal-fixture/control.sock", expectedServerUserId: 23456, lastKnownRevision: 9);

        internal FixtureClock Clock { get; } = new();

        internal ControllerStateStore Store { get; }

        internal ControllerStateStore Reopen() => ControllerStateStore.Open(new(_directory.FullName));

        internal ApplyWorkflowService Workflow(Func<AgentControlReply> reply) => new(Store, new StatusDispatcher(reply), Clock);

        internal async Task<FleetDashboardViewModel> DashboardAsync(ApplyWorkflowService? workflow, ControllerStateStore? store = null)
        {
            var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.Role, NergalRoles.Auditor),
                new Claim(ControllerActorIdentity.ActorClaimType, Actor),
            ], "test"));
            var httpContext = new DefaultHttpContext { User = principal, RequestAborted = TestContext.Current.CancellationToken };
            var controller = new ManagementController(store ?? Store, workflow)
            {
                ControllerContext = new ControllerContext { HttpContext = httpContext },
            };
            var view = Assert.IsType<ViewResult>(await controller.Index());
            return Assert.IsType<FleetDashboardViewModel>(view.Model);
        }

        public void Dispose() => _directory.Delete(recursive: true);
    }
}
