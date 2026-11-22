using System.Runtime.Versioning;
using Nergal.Core.Agent;
using Nergal.Core.Deployment;
using Nergal.LocalState;
using Nergal.Nftables;

namespace Nergal.Agent;

/// <summary>Executes authenticated typed agent control requests under the per-resource OS execution lock.</summary>
[SupportedOSPlatform("linux")]
internal sealed class AgentControlHandler
{
    private static readonly TimeSpan LockAcquireTimeout = TimeSpan.FromMilliseconds(500);
    private readonly string _directory;
    private readonly LinuxBootClock _clock = new();

    internal AgentControlHandler(string directory)
    {
        _directory = directory;
    }

    internal async Task<AgentControlReply> HandleAsync(AgentControlRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        return request.Command switch
        {
            AgentControlCommand.Status => await HandleStatusAsync(cancellationToken).ConfigureAwait(false),
            AgentControlCommand.PrepareApply => await HandlePrepareApplyAsync(request, cancellationToken).ConfigureAwait(false),
            AgentControlCommand.Confirm => await HandleConfirmAsync(request, cancellationToken).ConfigureAwait(false),
            AgentControlCommand.Rollback => await HandleRollbackAsync(request, cancellationToken).ConfigureAwait(false),
            _ => new AgentControlReply(AgentControlOutcome.InvalidRequest),
        };
    }

    private async Task<AgentControlReply> HandleStatusAsync(CancellationToken cancellationToken)
    {
        ResourceExecutionLock? executionLock = null;
        try
        {
            executionLock = await ResourceExecutionLock.AcquireAsync(_directory, LockAcquireTimeout, cancellationToken).ConfigureAwait(false);
            var ns = AgentStatusProvider.ReadNetworkNamespace();
            var actual = await NativeNft.TryObserveAsync(cancellationToken).ConfigureAwait(false);
            var journal = ApplyJournal.Open(_directory, _clock);
            var enrollment = journal.ReadEnrollment();
            var expected = journal.ReadExpectedResource();
            var active = journal.ReadActive();

            if (active is not null)
            {
                var remaining = ComputeRemainingSeconds(active);
                var wd = active.Session.WatchdogId == Guid.Empty ? (Guid?)null : active.Session.WatchdogId;
                var outcome = active.Session.Phase == ApplyPhase.AwaitingConfirmation
                    ? AgentControlOutcome.AppliedPendingConfirmation
                    : active.Session.Phase == ApplyPhase.RecoveryRequired
                        ? AgentControlOutcome.Unavailable
                        : AgentControlOutcome.Busy;

                return new AgentControlReply(
                    outcome,
                    revision: enrollment.Ownership.Revision,
                    operationId: active.Session.Plan.OperationId,
                    watchdogId: wd,
                    activePhase: active.Session.Phase,
                    remainingSeconds: remaining,
                    candidateDigest: active.Session.Plan.Candidate.Value);
            }

            var status = journal.ReadResourceStatus(actual, ns);
            if (status.Outcome == AgentStatusOutcome.Matched && expected is not null)
            {
                var aux = await NativeNft.TryInspectAuxiliaryTablesAsync(expected.Identity, cancellationToken).ConfigureAwait(false);
                if (aux is null)
                {
                    return new AgentControlReply(AgentControlOutcome.Unavailable, revision: status.Revision, errorCode: "observation.unavailable");
                }

                if (!AgentCommands.AuxiliaryTablesMatchArtifact(aux, enrollment.Artifact))
                {
                    return new AgentControlReply(AgentControlOutcome.Drift, revision: status.Revision, errorCode: "resource.drift");
                }
            }

            return status.Outcome switch
            {
                AgentStatusOutcome.Matched => new AgentControlReply(AgentControlOutcome.Matched, revision: status.Revision),
                AgentStatusOutcome.Drift => new AgentControlReply(AgentControlOutcome.Drift, revision: status.Revision),
                AgentStatusOutcome.Unbound => new AgentControlReply(AgentControlOutcome.Unbound, revision: status.Revision),
                _ => new AgentControlReply(AgentControlOutcome.Unavailable, errorCode: "status.unavailable"),
            };
        }
        catch (JournalException err)
        {
            return MapJournalException(err);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            return new AgentControlReply(AgentControlOutcome.Unavailable, errorCode: "agent.unavailable");
        }
        finally
        {
            executionLock?.Dispose();
        }
    }

    private async Task<AgentControlReply> HandlePrepareApplyAsync(AgentControlRequest request, CancellationToken cancellationToken)
    {
        var operationId = request.OperationId!.Value;
        var watchdogId = request.WatchdogId ?? Guid.NewGuid();
        var timeoutSeconds = request.ConfirmationTimeoutSeconds!.Value;
        ApplyPlan plan;
        string candidateArtifact;
        Guid bootId;
        ulong ns;
        NftTableIdentity identity;

        ResourceExecutionLock? executionLock = null;
        try
        {
            executionLock = await ResourceExecutionLock.AcquireAsync(_directory, LockAcquireTimeout, cancellationToken).ConfigureAwait(false);
            var journal = ApplyJournal.Open(_directory, _clock);
            var enrollment = journal.ReadEnrollment();
            var expected = journal.ReadExpectedResource();
            if (expected is null)
            {
                return new AgentControlReply(AgentControlOutcome.Unbound, revision: enrollment.Ownership.Revision, errorCode: "resource.unbound");
            }

            if (journal.ReadActive() is { } active)
            {
                return new AgentControlReply(
                    AgentControlOutcome.Busy,
                    revision: enrollment.Ownership.Revision,
                    operationId: active.Session.Plan.OperationId,
                    watchdogId: active.Session.WatchdogId == Guid.Empty ? null : active.Session.WatchdogId,
                    activePhase: active.Session.Phase,
                    remainingSeconds: ComputeRemainingSeconds(active),
                    candidateDigest: active.Session.Plan.Candidate.Value,
                    errorCode: "operation.active");
            }

            ns = AgentStatusProvider.ReadNetworkNamespace();
            var actual = await NativeNft.TryObserveAsync(cancellationToken).ConfigureAwait(false);
            if (actual is null)
            {
                return new AgentControlReply(AgentControlOutcome.Unavailable, revision: enrollment.Ownership.Revision, errorCode: "observation.unavailable");
            }

            var verified = journal.VerifyExpectedResource(actual, ns);
            if (!verified.IsMatch)
            {
                return new AgentControlReply(AgentControlOutcome.Drift, revision: enrollment.Ownership.Revision, errorCode: "resource.drift");
            }

            var beforeAux = await NativeNft.TryInspectAuxiliaryTablesAsync(expected.Identity, cancellationToken).ConfigureAwait(false);
            if (beforeAux is null)
            {
                return new AgentControlReply(AgentControlOutcome.Unavailable, revision: enrollment.Ownership.Revision, errorCode: "observation.unavailable");
            }

            if (!AgentCommands.AuxiliaryTablesMatchArtifact(beforeAux, enrollment.Artifact))
            {
                return new AgentControlReply(AgentControlOutcome.Drift, revision: enrollment.Ownership.Revision, errorCode: "resource.drift");
            }

            var bundle = request.ResolveBundle();
            if (bundle is null)
            {
                return new AgentControlReply(AgentControlOutcome.Rejected, revision: enrollment.Ownership.Revision, errorCode: "policy.invalid");
            }

            var compiled = NftPolicyBundleCompiler.Compile(bundle, expected.Identity);
            if (!compiled.IsSuccess || compiled.Candidate is null)
            {
                var diagnostic = SafeErrorCode(compiled.Diagnostics.FirstOrDefault()?.Code, "policy.invalid");
                return new AgentControlReply(AgentControlOutcome.Rejected, revision: enrollment.Ownership.Revision, errorCode: diagnostic);
            }

            candidateArtifact = compiled.Candidate;
            if (string.Equals(candidateArtifact, enrollment.Artifact, StringComparison.Ordinal))
            {
                return new AgentControlReply(AgentControlOutcome.Rejected, revision: enrollment.Ownership.Revision, errorCode: "candidate.unchanged");
            }

            var checkBatch = AgentCommands.BuildDeletePrefix(beforeAux) + candidateArtifact;
            try
            {
                await NativeNft.Run(["--check", "--file", "-"], checkBatch, cancellationToken).ConfigureAwait(false);
            }
            catch (IOException)
            {
                return new AgentControlReply(AgentControlOutcome.Rejected, revision: enrollment.Ownership.Revision, errorCode: "candidate.invalid");
            }

            plan = new ApplyPlan(
                operationId,
                enrollment.Ownership,
                CandidateDigest.FromText(candidateArtifact),
                CandidateDigest.FromText(enrollment.Artifact),
                TimeSpan.FromSeconds(timeoutSeconds));

            _ = journal.StartBound(plan, candidateArtifact, enrollment.Artifact, actual, ns);
            bootId = _clock.Read().BootId;
            identity = expected.Identity;
        }
        catch (JournalException err)
        {
            return MapJournalException(err);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            return new AgentControlReply(AgentControlOutcome.Unavailable, errorCode: "agent.unavailable");
        }
        finally
        {
            executionLock?.Dispose();
            executionLock = null;
        }

        var armed = await AgentSelfLauncher.StartWatchdogAsync(_directory, operationId, watchdogId, cancellationToken).ConfigureAwait(false);
        if (!armed)
        {
            await InterruptPreparedOperationAsync(operationId, plan, cancellationToken).ConfigureAwait(false);
            return new AgentControlReply(
                AgentControlOutcome.Unavailable,
                operationId: operationId,
                watchdogId: watchdogId,
                errorCode: "watchdog.armFailed");
        }

        try
        {
            executionLock = await ResourceExecutionLock.AcquireAsync(_directory, LockAcquireTimeout, cancellationToken).ConfigureAwait(false);
            var journal = ApplyJournal.Open(_directory, _clock);
            var enrollment = journal.ReadEnrollment();
            var entry = journal.Read(operationId);

            if (entry.Session.Phase != ApplyPhase.RollbackArmed || entry.Session.WatchdogId != watchdogId)
            {
                return new AgentControlReply(
                    AgentControlOutcome.Unavailable,
                    revision: enrollment.Ownership.Revision,
                    operationId: operationId,
                    watchdogId: entry.Session.WatchdogId == Guid.Empty ? null : entry.Session.WatchdogId,
                    activePhase: entry.Session.Phase,
                    errorCode: "watchdog.mismatch");
            }

            (NftTableReceipt EchoReceipt, NftTableObservation Listing) replaced;
            try
            {
                replaced = await AgentCommands.ReplaceAndVerifyAsync(candidateArtifact, bootId, ns, identity).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or InvalidOperationException)
            {
                return await RollbackAfterApplyFailureAsync(journal, entry, watchdogId, bootId, ns, identity).ConfigureAwait(false);
            }

            var applied = journal.RecordCandidateAppliedBound(operationId, plan, watchdogId, replaced.EchoReceipt, replaced.Listing, ns);
            if (!applied.Accepted)
            {
                return await RollbackAfterApplyFailureAsync(journal, applied.Entry, watchdogId, bootId, ns, identity,
                    applied.ErrorCode ?? "apply.denied").ConfigureAwait(false);
            }

            var remaining = ComputeRemainingSeconds(applied.Entry);
            return new AgentControlReply(
                AgentControlOutcome.AppliedPendingConfirmation,
                revision: enrollment.Ownership.Revision,
                operationId: operationId,
                watchdogId: watchdogId,
                activePhase: applied.Entry.Session.Phase,
                remainingSeconds: remaining,
                candidateDigest: plan.Candidate.Value);
        }
        catch (JournalException err)
        {
            return MapJournalException(err);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            return new AgentControlReply(AgentControlOutcome.Unavailable, operationId: operationId, watchdogId: watchdogId, errorCode: "apply.unavailable");
        }
        finally
        {
            executionLock?.Dispose();
        }
    }

    private async Task<AgentControlReply> HandleConfirmAsync(AgentControlRequest request, CancellationToken cancellationToken)
    {
        var operationId = request.OperationId!.Value;
        var watchdogId = request.WatchdogId!.Value;

        ResourceExecutionLock? executionLock = null;
        try
        {
            executionLock = await ResourceExecutionLock.AcquireAsync(_directory, LockAcquireTimeout, cancellationToken).ConfigureAwait(false);
            var journal = ApplyJournal.Open(_directory, _clock);
            var enrollment = journal.ReadEnrollment();
            var active = journal.ReadActive();
            if (active is null)
            {
                return CreateMissingOperationReply(journal, operationId, enrollment.Ownership.Revision);
            }

            if (active.Session.Plan.OperationId != operationId || active.Session.WatchdogId != watchdogId)
            {
                return new AgentControlReply(
                    AgentControlOutcome.Rejected,
                    revision: enrollment.Ownership.Revision,
                    operationId: active.Session.Plan.OperationId,
                    watchdogId: active.Session.WatchdogId == Guid.Empty ? null : active.Session.WatchdogId,
                    activePhase: active.Session.Phase,
                    errorCode: "operation.mismatch");
            }

            var ns = AgentStatusProvider.ReadNetworkNamespace();
            var actual = await NativeNft.TryObserveAsync(cancellationToken).ConfigureAwait(false);
            if (actual is null)
            {
                return new AgentControlReply(
                    AgentControlOutcome.Unavailable,
                    revision: enrollment.Ownership.Revision,
                    operationId: operationId,
                    watchdogId: watchdogId,
                    activePhase: active.Session.Phase,
                    errorCode: "observation.unavailable");
            }

            var expected = journal.ReadExpectedResource();
            if (expected is null)
            {
                return new AgentControlReply(
                    AgentControlOutcome.Unbound,
                    revision: enrollment.Ownership.Revision,
                    operationId: operationId,
                    watchdogId: watchdogId,
                    activePhase: active.Session.Phase,
                    errorCode: "resource.unbound");
            }

            var aux = await NativeNft.TryInspectAuxiliaryTablesAsync(expected.Identity, cancellationToken).ConfigureAwait(false);
            if (aux is null)
            {
                return new AgentControlReply(
                    AgentControlOutcome.Unavailable,
                    revision: enrollment.Ownership.Revision,
                    operationId: operationId,
                    watchdogId: watchdogId,
                    activePhase: active.Session.Phase,
                    errorCode: "observation.unavailable");
            }

            if (!AgentCommands.AuxiliaryTablesMatchArtifact(aux, active.Candidate))
            {
                return new AgentControlReply(
                    AgentControlOutcome.Rejected,
                    revision: enrollment.Ownership.Revision,
                    operationId: operationId,
                    watchdogId: watchdogId,
                    activePhase: active.Session.Phase,
                    errorCode: "resource.drift");
            }

            var confirmed = journal.ConfirmBound(operationId, active.Session.Plan, watchdogId, actual, ns);
            if (!confirmed.Accepted)
            {
                return new AgentControlReply(
                    AgentControlOutcome.Rejected,
                    revision: enrollment.Ownership.Revision,
                    operationId: operationId,
                    watchdogId: watchdogId,
                    activePhase: confirmed.Entry.Session.Phase,
                    errorCode: confirmed.ErrorCode ?? "confirm.denied");
            }

            return new AgentControlReply(
                AgentControlOutcome.Confirmed,
                revision: active.Session.Plan.ConfirmedRevision,
                operationId: operationId,
                watchdogId: watchdogId,
                activePhase: confirmed.Entry.Session.Phase,
                candidateDigest: active.Session.Plan.Candidate.Value);
        }
        catch (JournalException err)
        {
            return MapJournalException(err);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            return new AgentControlReply(AgentControlOutcome.Unavailable, errorCode: "confirm.unavailable");
        }
        finally
        {
            executionLock?.Dispose();
        }
    }

    private async Task<AgentControlReply> HandleRollbackAsync(AgentControlRequest request, CancellationToken cancellationToken)
    {
        var operationId = request.OperationId!.Value;
        var watchdogId = request.WatchdogId!.Value;

        ResourceExecutionLock? executionLock = null;
        try
        {
            executionLock = await ResourceExecutionLock.AcquireAsync(_directory, LockAcquireTimeout, cancellationToken).ConfigureAwait(false);
            var journal = ApplyJournal.Open(_directory, _clock);
            var enrollment = journal.ReadEnrollment();
            var expected = journal.ReadExpectedResource();
            var active = journal.ReadActive();
            if (active is null)
            {
                return CreateMissingOperationReply(journal, operationId, enrollment.Ownership.Revision);
            }

            if (active.Session.Plan.OperationId != operationId || active.Session.WatchdogId != watchdogId)
            {
                return new AgentControlReply(
                    AgentControlOutcome.Rejected,
                    revision: enrollment.Ownership.Revision,
                    operationId: active.Session.Plan.OperationId,
                    watchdogId: active.Session.WatchdogId == Guid.Empty ? null : active.Session.WatchdogId,
                    activePhase: active.Session.Phase,
                    errorCode: "operation.mismatch");
            }

            if (expected is null)
            {
                return new AgentControlReply(AgentControlOutcome.Unbound, revision: enrollment.Ownership.Revision, errorCode: "resource.unbound");
            }

            var trigger = active.Session.Phase == ApplyPhase.AwaitingConfirmation
                ? ApplyEvent.VerificationFailed
                : ApplyEvent.ApplyFailed;
            var requested = journal.Advance(operationId, trigger, active.Session.Plan, watchdogId);
            if (!requested.Accepted || requested.Entry.Session.Phase != ApplyPhase.RollbackRequired)
            {
                return new AgentControlReply(
                    AgentControlOutcome.Rejected,
                    revision: enrollment.Ownership.Revision,
                    operationId: operationId,
                    watchdogId: watchdogId,
                    activePhase: requested.Entry.Session.Phase,
                    errorCode: requested.ErrorCode ?? "rollback.denied");
            }

            var ns = AgentStatusProvider.ReadNetworkNamespace();
            var bootId = _clock.Read().BootId;
            (NftTableReceipt EchoReceipt, NftTableObservation Listing) restored;
            try
            {
                restored = await AgentCommands.ReplaceAndVerifyAsync(active.Rollback, bootId, ns, expected.Identity).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or InvalidOperationException)
            {
                _ = journal.Advance(operationId, ApplyEvent.RollbackFailed, active.Session.Plan, watchdogId);
                return new AgentControlReply(
                    AgentControlOutcome.Unavailable,
                    revision: enrollment.Ownership.Revision,
                    operationId: operationId,
                    watchdogId: watchdogId,
                    activePhase: ApplyPhase.RecoveryRequired,
                    errorCode: "rollback.failed");
            }

            var completed = journal.RecordRollbackSucceededBound(operationId, active.Session.Plan, watchdogId, restored.EchoReceipt, restored.Listing, ns);
            if (!completed.Accepted)
            {
                _ = journal.Advance(operationId, ApplyEvent.RollbackFailed, active.Session.Plan, watchdogId);
                return new AgentControlReply(
                    AgentControlOutcome.Unavailable,
                    revision: enrollment.Ownership.Revision,
                    operationId: operationId,
                    watchdogId: watchdogId,
                    activePhase: ApplyPhase.RecoveryRequired,
                    errorCode: completed.ErrorCode ?? "rollback.failed");
            }

            return new AgentControlReply(
                AgentControlOutcome.RolledBack,
                revision: enrollment.Ownership.Revision,
                operationId: operationId,
                watchdogId: watchdogId,
                activePhase: completed.Entry.Session.Phase);
        }
        catch (JournalException err)
        {
            return MapJournalException(err);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            return new AgentControlReply(AgentControlOutcome.Unavailable, errorCode: "rollback.unavailable");
        }
        finally
        {
            executionLock?.Dispose();
        }
    }

    private async Task<AgentControlReply> RollbackAfterApplyFailureAsync(
        ApplyJournal journal,
        JournalEntry entry,
        Guid watchdogId,
        Guid bootId,
        ulong ns,
        NftTableIdentity identity,
        string errorCode = "apply.failed")
    {
        var req = journal.Advance(entry.Session.Plan.OperationId, ApplyEvent.ApplyFailed, entry.Session.Plan, watchdogId);
        if (req.Accepted && req.Entry.Session.Phase == ApplyPhase.RollbackRequired)
        {
            try
            {
                var restored = await AgentCommands.ReplaceAndVerifyAsync(entry.Rollback, bootId, ns, identity).ConfigureAwait(false);
                _ = journal.RecordRollbackSucceededBound(entry.Session.Plan.OperationId, entry.Session.Plan, watchdogId, restored.EchoReceipt, restored.Listing, ns);
                return new AgentControlReply(
                    AgentControlOutcome.RolledBack,
                    revision: entry.Session.Plan.Ownership.Revision,
                    operationId: entry.Session.Plan.OperationId,
                    watchdogId: watchdogId,
                    activePhase: ApplyPhase.RolledBack,
                    errorCode: errorCode);
            }
            catch (Exception)
            {
                _ = journal.Advance(entry.Session.Plan.OperationId, ApplyEvent.RollbackFailed, entry.Session.Plan, watchdogId);
            }
        }

        return new AgentControlReply(
            AgentControlOutcome.Unavailable,
            revision: entry.Session.Plan.Ownership.Revision,
            operationId: entry.Session.Plan.OperationId,
            watchdogId: watchdogId,
            activePhase: ApplyPhase.RecoveryRequired,
            errorCode: "rollback.failed");
    }

    private async Task InterruptPreparedOperationAsync(Guid operationId, ApplyPlan plan, CancellationToken cancellationToken)
    {
        try
        {
            using var executionLock = await ResourceExecutionLock.AcquireAsync(_directory, LockAcquireTimeout, cancellationToken).ConfigureAwait(false);
            var journal = ApplyJournal.Open(_directory, _clock);
            var entry = journal.Read(operationId);
            if (!entry.Session.IsTerminal)
            {
                _ = journal.Advance(operationId, ApplyEvent.Interrupted, plan, Guid.Empty);
            }
        }
        catch (Exception)
        {
        }
    }

    private int? ComputeRemainingSeconds(JournalEntry entry)
    {
        if (entry.Session.Phase is not (ApplyPhase.RollbackArmed or ApplyPhase.AwaitingConfirmation) ||
            entry.Session.Deadline is not { } deadline)
        {
            return null;
        }

        var now = _clock.Read();
        if (now.BootId != entry.Started.BootId)
        {
            return 0;
        }

        var elapsed = now.SinceBoot - entry.Started.SinceBoot;
        var remaining = deadline - elapsed;
        if (remaining <= TimeSpan.Zero)
        {
            return 0;
        }

        return Math.Clamp((int)Math.Ceiling(remaining.TotalSeconds), 0, 3600);
    }

    private static AgentControlReply CreateMissingOperationReply(ApplyJournal journal, Guid operationId, ulong revision)
    {
        try
        {
            var recorded = journal.Read(operationId);
            var code = recorded.Session.Phase == ApplyPhase.RolledBack ? "deadline.expired" : "operation.notActive";
            return new AgentControlReply(
                AgentControlOutcome.Rejected,
                revision: revision,
                operationId: operationId,
                watchdogId: recorded.Session.WatchdogId == Guid.Empty ? null : recorded.Session.WatchdogId,
                activePhase: recorded.Session.Phase,
                errorCode: code);
        }
        catch (JournalException)
        {
            return new AgentControlReply(AgentControlOutcome.Rejected, revision: revision, errorCode: "operation.missing");
        }
    }

    private static string SafeErrorCode(string? raw, string fallback)
    {
        if (string.IsNullOrEmpty(raw) || raw.Length > 64)
        {
            return fallback;
        }

        foreach (var ch in raw)
        {
            if (ch is not ((>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '.' or '_' or '-'))
            {
                return fallback;
            }
        }

        return raw;
    }

    private static AgentControlReply MapJournalException(JournalException err)
    {
        var code = SafeErrorCode(err.Code, "journal.error");
        var outcome = err.Code switch
        {
            "resource.busy" or "resource.lockTimeout" => AgentControlOutcome.Busy,
            "resource.unbound" => AgentControlOutcome.Unbound,
            "resource.drift" or "resource.receiptMismatch" or "resource.baselineMismatch" => AgentControlOutcome.Drift,
            "operation.reused" or "candidate.unchanged" or "candidate.invalid" => AgentControlOutcome.Rejected,
            _ => AgentControlOutcome.Unavailable,
        };
        return new AgentControlReply(outcome, errorCode: code);
    }
}
