namespace Nergal.Core.Deployment;

/// <summary>Modeled confirmed-apply phases; none executes or schedules host operations.</summary>
/// <remarks>Numeric identifiers are persisted in local journals. Do not renumber existing values.</remarks>
public enum ApplyPhase
{
    /// <summary>No rollback arming has been acknowledged.</summary>
    Prepared = 0,
    /// <summary>The coordinator asserts that independent local rollback is durably armed.</summary>
    RollbackArmed = 1,
    /// <summary>Apply success was acknowledged; timely confirmation is still required.</summary>
    AwaitingConfirmation = 2,
    /// <summary>Timely confirmation was acknowledged; the operation is terminal.</summary>
    Confirmed = 3,
    /// <summary>Rollback must complete before new work is considered.</summary>
    RollbackRequired = 4,
    /// <summary>Successful rollback was acknowledged; the operation is terminal.</summary>
    RolledBack = 5,
    /// <summary>Uncertain state or failed rollback requires external reconciliation; terminal in this model.</summary>
    RecoveryRequired = 6,
}

/// <summary>Trusted coordinator acknowledgments, not commands or independently verified proofs.</summary>
/// <remarks>Numeric identifiers are persisted in local journals. Append deliberately; never renumber existing events.</remarks>
public enum ApplyEvent
{
    /// <summary>Complete validation, snapshot and independent durable rollback arming have finished.</summary>
    RollbackArmed = 0,
    /// <summary>The complete candidate was atomically installed.</summary>
    CandidateApplied = 1,
    /// <summary>Apply failed or its outcome cannot be established; rollback is required.</summary>
    ApplyFailed = 2,
    /// <summary>Post-apply verification failed; restore the prior owned state immediately.</summary>
    VerificationFailed = 3,
    /// <summary>The matching operation was authorized, verified and durably confirmed before expiry.</summary>
    Confirm = 4,
    /// <summary>Evaluate the monotonic deadline; this event does not run automatically.</summary>
    CheckDeadline = 5,
    /// <summary>The exact rollback artifact was restored and verified.</summary>
    RollbackSucceeded = 6,
    /// <summary>Rollback failed or restoration cannot be verified.</summary>
    RollbackFailed = 7,
    /// <summary>Execution was interrupted; protected journal and kernel reconciliation are required.</summary>
    Interrupted = 8,
}

/// <summary>A pure immutable confirmed-apply model, with no persistence, timers or host access.</summary>
/// <remarks>The caller must serialize and persist transitions, verify evidence and retain returned sessions.</remarks>
public sealed class ApplySession
{
    private ApplySession(ApplyPlan plan, ApplyPhase phase, TimeSpan elapsed, TimeSpan? deadline, Guid watchdogId)
    {
        Plan = plan;
        Phase = phase;
        Elapsed = elapsed;
        Deadline = deadline;
        WatchdogId = watchdogId;
    }

    /// <summary>Begins modeling an operation at monotonic elapsed time zero.</summary>
    /// <exception cref="ArgumentNullException">The plan is null.</exception>
    public static ApplySession Prepare(ApplyPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        return new(plan, ApplyPhase.Prepared, TimeSpan.Zero, null, Guid.Empty);
    }

    /// <summary>Gets the exact immutable content, identity and revision binding.</summary>
    public ApplyPlan Plan { get; }
    /// <summary>Gets the current modeled phase.</summary>
    public ApplyPhase Phase { get; }
    /// <summary>Gets the last incorporated monotonic elapsed time since operation creation.</summary>
    public TimeSpan Elapsed { get; }
    /// <summary>Gets the exclusive confirmation deadline, assigned only when rollback is armed.</summary>
    public TimeSpan? Deadline { get; }
    /// <summary>Gets the asserted independent watchdog identity, or empty before arming.</summary>
    public Guid WatchdogId { get; }
    /// <summary>Gets whether this model can no longer advance the operation.</summary>
    public bool IsTerminal => Phase is ApplyPhase.Confirmed or ApplyPhase.RolledBack or ApplyPhase.RecoveryRequired;

    /// <summary>Evaluates a bound acknowledgment without executing its claimed side effects.</summary>
    /// <param name="kind">Known event; unknown values fail closed.</param>
    /// <param name="evidence">Must equal the entire plan, including ownership, revision and artifact digests.</param>
    /// <param name="watchdogId">Nonempty on arming; must match the armed watchdog on later events.</param>
    /// <param name="elapsed">Monotonic elapsed time from operation creation; cannot be negative or decrease.</param>
    /// <returns>A new session on acceptance. Expiration can require rollback even when the event is denied.</returns>
    /// <exception cref="ArgumentNullException">Evidence is null.</exception>
    public ApplyTransition Advance(ApplyEvent kind, ApplyPlan evidence, Guid watchdogId, TimeSpan elapsed)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (!Enum.IsDefined(kind))
        {
            return Deny("event.unknown");
        }

        if (elapsed < TimeSpan.Zero)
        {
            return Deny("time.invalid");
        }

        if (elapsed < Elapsed)
        {
            return Deny("time.regressed");
        }

        if (evidence != Plan)
        {
            return Deny("binding.mismatch");
        }

        if (kind == ApplyEvent.RollbackArmed && Phase == ApplyPhase.Prepared)
        {
            if (watchdogId == Guid.Empty)
            {
                return Deny("watchdog.required");
            }
        }
        else if (watchdogId != WatchdogId)
        {
            return Deny("watchdog.mismatch");
        }

        if (IsTerminal)
        {
            return Deny("phase.terminal");
        }

        var current = this;
        var expired = (Phase is ApplyPhase.RollbackArmed or ApplyPhase.AwaitingConfirmation) && elapsed >= Deadline!.Value;
        if (expired)
        {
            current = Move(ApplyPhase.RollbackRequired, elapsed);
        }

        if (expired && kind is not (ApplyEvent.CheckDeadline or ApplyEvent.RollbackSucceeded or ApplyEvent.RollbackFailed or ApplyEvent.Interrupted))
        {
            return new(current, "deadline.expired");
        }

        switch (kind)
        {
            case ApplyEvent.RollbackArmed when current.Phase == ApplyPhase.Prepared:
                if (elapsed > TimeSpan.MaxValue - Plan.ConfirmationTimeout)
                {
                    return Deny("time.overflow");
                }

                return new(new(Plan, ApplyPhase.RollbackArmed, elapsed, elapsed + Plan.ConfirmationTimeout, watchdogId), null);
            case ApplyEvent.CandidateApplied when current.Phase == ApplyPhase.RollbackArmed:
                return new(current.Move(ApplyPhase.AwaitingConfirmation, elapsed), null);
            case ApplyEvent.ApplyFailed when current.Phase == ApplyPhase.RollbackArmed:
                return new(current.Move(ApplyPhase.RollbackRequired, elapsed), null);
            case ApplyEvent.VerificationFailed when current.Phase == ApplyPhase.AwaitingConfirmation:
                return new(current.Move(ApplyPhase.RollbackRequired, elapsed), null);
            case ApplyEvent.Confirm when current.Phase == ApplyPhase.AwaitingConfirmation:
                return new(current.Move(ApplyPhase.Confirmed, elapsed), null);
            case ApplyEvent.RollbackSucceeded when current.Phase == ApplyPhase.RollbackRequired:
                return new(current.Move(ApplyPhase.RolledBack, elapsed), null);
            case ApplyEvent.RollbackFailed when current.Phase == ApplyPhase.RollbackRequired:
                return new(current.Move(ApplyPhase.RecoveryRequired, elapsed), null);
            case ApplyEvent.Interrupted:
                return new(current.Move(ApplyPhase.RecoveryRequired, elapsed), null);
            case ApplyEvent.CheckDeadline:
                return new(current.Move(current.Phase, elapsed), null);
            default:
                return new(current, "phase.invalid");
        }
    }

    private ApplySession Move(ApplyPhase phase, TimeSpan elapsed) => new(Plan, phase, elapsed, Deadline, WatchdogId);
    private ApplyTransition Deny(string errorCode) => new(this, errorCode);
}

/// <summary>Transition outcome; always retain Session, including when a late confirmation is denied.</summary>
public sealed class ApplyTransition
{
    internal ApplyTransition(ApplySession session, string? errorCode)
    {
        Session = session;
        ErrorCode = errorCode;
    }

    /// <summary>Gets the resulting session, potentially requiring rollback even after event denial.</summary>
    public ApplySession Session { get; }
    /// <summary>Gets the stable denial code, or null when the acknowledgment was accepted.</summary>
    public string? ErrorCode { get; }
    /// <summary>Gets whether the requested acknowledgment was accepted.</summary>
    public bool Accepted => ErrorCode is null;
}
