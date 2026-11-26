using System.Runtime.Versioning;
using Nergal.ControllerState;
using Nergal.Core.Agent;
using Nergal.Core.Controller;
using Nergal.Core.Identity;

namespace Nergal.Web;

/// <summary>Result of a controller confirmed-apply workflow operation against a managed host.</summary>
public sealed record ApplyWorkflowResult(
    bool HostFound,
    bool RevisionFound,
    ManagedHostRecord? Host,
    PolicyRevisionRecord? RevisionRecord,
    AgentControlReply? Reply)
{
    /// <summary>Gets the observation from this status reply, with the controller's UTC receipt time.</summary>
    public HostObservation? Observation { get; init; }

    /// <summary>Gets whether the store already retained an observation at least as recent as this reply.</summary>
    public bool ObservationSuperseded { get; init; }
}

/// <summary>Mediates two-phase confirmed policy application, rollback, status polling, and audit persistence.</summary>
[SupportedOSPlatform("linux")]
public sealed class ApplyWorkflowService
{
    internal const int DefaultConfirmationTimeoutSeconds = 30;
    internal const int MinimumConfirmationTimeoutSeconds = 1;
    internal const int MaximumConfirmationTimeoutSeconds = 3600;

    private readonly ControllerStateStore _store;
    private readonly IAgentControlDispatcher _dispatcher;
    private readonly TimeProvider _clock;

    /// <summary>Initializes the workflow service with controller persistence and an authenticated transport dispatcher.</summary>
    public ApplyWorkflowService(ControllerStateStore store, IAgentControlDispatcher dispatcher, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(dispatcher);
        _store = store;
        _dispatcher = dispatcher;
        _clock = clock ?? TimeProvider.System;
    }

    /// <summary>Records a usable authenticated status reply and synchronizes the last-known revision when matched or settled.</summary>
    public async Task<ApplyWorkflowResult> QueryHostStatusAsync(Guid hostId, CancellationToken cancellationToken = default)
    {
        if (hostId == Guid.Empty)
        {
            throw new ArgumentException("Host identity cannot be empty.", nameof(hostId));
        }

        var host = _store.GetHost(hostId);
        if (host is null)
        {
            return new ApplyWorkflowResult(false, true, null, null, null);
        }

        var reply = await _dispatcher.SendAsync(host, new AgentControlRequest(AgentControlCommand.Status), cancellationToken).ConfigureAwait(false);
        var observedAtUtc = _clock.GetUtcNow().ToUniversalTime();
        if (ClassifyStatus(reply) is not { } state)
        {
            return new ApplyWorkflowResult(true, true, host, null, reply);
        }

        var observation = new HostObservation(host.Id, state, reply.Revision, observedAtUtc);
        var updateLastKnownRevision = state is HostObservationState.Matched or HostObservationState.Online &&
            reply.Revision is > 0 &&
            reply.Revision.Value != host.LastKnownRevision &&
            reply.Outcome is AgentControlOutcome.Matched or AgentControlOutcome.Confirmed or AgentControlOutcome.RolledBack;
        // An apply can complete while the status request is in flight.
        var recorded = _store.RecordHostObservation(observation, updateLastKnownRevision, expectedLastKnownRevision: host.LastKnownRevision);
        if (!recorded || updateLastKnownRevision)
        {
            host = _store.GetHost(host.Id);
            if (host is null)
            {
                return new ApplyWorkflowResult(false, true, null, null, null);
            }
        }

        return new ApplyWorkflowResult(true, true, host, null, reply)
        {
            Observation = recorded ? observation : null,
            ObservationSuperseded = !recorded,
        };
    }

    private static HostObservationState? ClassifyStatus(AgentControlReply reply)
    {
        // The dispatcher synthesizes Unavailable for failed authentication, transport and decoding.
        // Only these usable status outcomes can carry observation evidence.
        var state = reply.Outcome switch
        {
            AgentControlOutcome.Matched or AgentControlOutcome.Confirmed => HostObservationState.Matched,
            AgentControlOutcome.Drift => HostObservationState.Drift,
            AgentControlOutcome.Unbound => HostObservationState.Missing,
            AgentControlOutcome.AppliedPendingConfirmation => HostObservationState.Pending,
            AgentControlOutcome.Busy when reply.OperationId.HasValue => HostObservationState.Pending,
            AgentControlOutcome.RolledBack => HostObservationState.Online,
            _ => (HostObservationState?)null,
        };
        return state.HasValue && reply.OperationId.HasValue ? HostObservationState.Pending : state;
    }

    /// <summary>Validates saved policy scope, dispatches <c>prepare-apply</c> with confirmation timeout, and records audit outcome.</summary>
    public async Task<ApplyWorkflowResult> StartApplyAsync(
        Guid hostId,
        ulong revision,
        int confirmationTimeoutSeconds,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken = default)
    {
        if (hostId == Guid.Empty)
        {
            throw new ArgumentException("Host identity cannot be empty.", nameof(hostId));
        }

        if (revision == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(revision));
        }

        if (confirmationTimeoutSeconds is < MinimumConfirmationTimeoutSeconds or > MaximumConfirmationTimeoutSeconds)
        {
            throw new ArgumentOutOfRangeException(nameof(confirmationTimeoutSeconds));
        }

        if (actorRole != NergalRoles.Administrator)
        {
            throw new UnauthorizedAccessException("rbac.denied");
        }

        var host = _store.GetHost(hostId);
        if (host is null)
        {
            return new ApplyWorkflowResult(false, false, null, null, null);
        }

        var policyRevision = _store.GetPolicyRevision(revision);
        if (policyRevision is null)
        {
            return new ApplyWorkflowResult(true, false, host, null, null);
        }

        if (!PolicyAuthoringService.TryDecodeBundle(policyRevision.PolicyJson, out var bundle, out _) || bundle is null)
        {
            _ = _store.AppendAudit(actorId, actorRole, "apply.start", host.Name, revision, "rejected", "policy.invalid");
            return new ApplyWorkflowResult(true, true, host, policyRevision,
                new AgentControlReply(AgentControlOutcome.Rejected, errorCode: "policy.invalid"));
        }

        var operationId = Guid.NewGuid();
        var watchdogId = Guid.NewGuid();
        var request = new AgentControlRequest(
            AgentControlCommand.PrepareApply,
            operationId,
            watchdogId,
            confirmationTimeoutSeconds,
            bundle: bundle);

        var reply = await _dispatcher.SendAsync(host, request, cancellationToken).ConfigureAwait(false);
        _ = _store.AppendAudit(actorId, actorRole, "apply.start", host.Name, revision, ToAuditOutcome(reply.Outcome), reply.ErrorCode);
        return new ApplyWorkflowResult(true, true, host, policyRevision, reply);
    }

    /// <summary>Dispatches <c>confirm</c> for an active operation, promotes host revision, and records audit outcome.</summary>
    public async Task<ApplyWorkflowResult> ConfirmApplyAsync(
        Guid hostId,
        Guid operationId,
        Guid watchdogId,
        ulong? targetRevision,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken = default)
    {
        if (hostId == Guid.Empty)
        {
            throw new ArgumentException("Host identity cannot be empty.", nameof(hostId));
        }

        if (operationId == Guid.Empty)
        {
            throw new ArgumentException("Operation identity cannot be empty.", nameof(operationId));
        }

        if (watchdogId == Guid.Empty)
        {
            throw new ArgumentException("Watchdog identity cannot be empty.", nameof(watchdogId));
        }

        if (actorRole != NergalRoles.Administrator)
        {
            throw new UnauthorizedAccessException("rbac.denied");
        }

        var host = _store.GetHost(hostId);
        if (host is null)
        {
            return new ApplyWorkflowResult(false, true, null, null, null);
        }

        var hostName = host.Name;
        var request = new AgentControlRequest(AgentControlCommand.Confirm, operationId, watchdogId);
        var reply = await _dispatcher.SendAsync(host, request, cancellationToken).ConfigureAwait(false);
        if (reply.Outcome == AgentControlOutcome.Confirmed && reply.Revision is > 0)
        {
            _store.UpdateHostLastRevision(host.Id, reply.Revision.Value);
            host = _store.GetHost(host.Id);
        }

        var recordedRevision = reply.Revision ?? targetRevision;
        _ = _store.AppendAudit(actorId, actorRole, "apply.confirm", hostName, recordedRevision, ToAuditOutcome(reply.Outcome), reply.ErrorCode);
        return new ApplyWorkflowResult(true, true, host, null, reply);
    }

    /// <summary>Dispatches immediate <c>rollback</c> for an active unconfirmed operation and records audit outcome.</summary>
    public async Task<ApplyWorkflowResult> RollbackApplyAsync(
        Guid hostId,
        Guid operationId,
        Guid watchdogId,
        string actorId,
        string actorRole,
        CancellationToken cancellationToken = default)
    {
        if (hostId == Guid.Empty)
        {
            throw new ArgumentException("Host identity cannot be empty.", nameof(hostId));
        }

        if (operationId == Guid.Empty)
        {
            throw new ArgumentException("Operation identity cannot be empty.", nameof(operationId));
        }

        if (watchdogId == Guid.Empty)
        {
            throw new ArgumentException("Watchdog identity cannot be empty.", nameof(watchdogId));
        }

        if (actorRole != NergalRoles.Administrator)
        {
            throw new UnauthorizedAccessException("rbac.denied");
        }

        var host = _store.GetHost(hostId);
        if (host is null)
        {
            return new ApplyWorkflowResult(false, true, null, null, null);
        }

        var hostName = host.Name;
        var request = new AgentControlRequest(AgentControlCommand.Rollback, operationId, watchdogId);
        var reply = await _dispatcher.SendAsync(host, request, cancellationToken).ConfigureAwait(false);
        if (reply.Outcome == AgentControlOutcome.RolledBack && reply.Revision is > 0)
        {
            _store.UpdateHostLastRevision(host.Id, reply.Revision.Value);
            host = _store.GetHost(host.Id);
        }

        _ = _store.AppendAudit(actorId, actorRole, "apply.rollback", hostName, reply.Revision, ToAuditOutcome(reply.Outcome), reply.ErrorCode);
        return new ApplyWorkflowResult(true, true, host, null, reply);
    }

    internal static string ToAuditOutcome(AgentControlOutcome outcome) => outcome switch
    {
        AgentControlOutcome.Matched => "matched",
        AgentControlOutcome.Drift => "drift",
        AgentControlOutcome.Unbound => "unbound",
        AgentControlOutcome.AppliedPendingConfirmation => "pending_confirmation",
        AgentControlOutcome.Confirmed => "confirmed",
        AgentControlOutcome.RolledBack => "rolled_back",
        AgentControlOutcome.Rejected => "rejected",
        AgentControlOutcome.Busy => "busy",
        AgentControlOutcome.Unavailable => "unavailable",
        AgentControlOutcome.Denied => "denied",
        AgentControlOutcome.InvalidRequest => "invalid_request",
        _ => "unknown",
    };
}
