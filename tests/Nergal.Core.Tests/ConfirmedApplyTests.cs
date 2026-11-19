using System.Text;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Tests the modeled safety contract; these tests do not establish a working watchdog or rollback executor.</summary>
public sealed class ConfirmedApplyTests
{
    private static readonly Guid Operation = Guid.Parse("00000000-0000-0000-0000-000000000001");
    private static readonly Guid Agent = Guid.Parse("00000000-0000-0000-0000-000000000002");
    private static readonly Guid Owner = Guid.Parse("00000000-0000-0000-0000-000000000003");
    private static readonly Guid Watchdog = Guid.Parse("00000000-0000-0000-0000-000000000004");
    private static readonly Guid Other = Guid.Parse("00000000-0000-0000-0000-000000000005");
    private static readonly CandidateDigest Candidate = CandidateDigest.FromText("synthetic candidate\n");
    private static readonly CandidateDigest Rollback = CandidateDigest.FromText("synthetic rollback\n");

    /// <summary>Published SHA-256 vectors establish byte identity independently of the compiler.</summary>
    [Theory]
    [InlineData("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    [InlineData("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
    public void Digest_KnownUtf8Vector(string text, string expected)
        => Assert.Equal(new CandidateDigest(expected), CandidateDigest.FromText(text));

    /// <summary>Visually similar artifacts cannot share approval through normalization or replacement encoding.</summary>
    [Fact]
    public void Digest_PreservesExactTextAndRejectsMalformedUtf16()
    {
        Assert.NotEqual(CandidateDigest.FromText("x\n"), CandidateDigest.FromText("x\r\n"));
        Assert.NotEqual(CandidateDigest.FromText("x"), CandidateDigest.FromText("x "));
        Assert.NotEqual(CandidateDigest.FromText("é"), CandidateDigest.FromText("e\u0301"));
        Assert.Throws<EncoderFallbackException>(() => CandidateDigest.FromText("\ud800"));
        Assert.Throws<ArgumentNullException>(() => CandidateDigest.FromText(null!));
    }

    /// <summary>Digest spellings are canonical, so identity comparison has a single representation.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")]
    public void Digest_Invalid_Throws(string? text)
        => Assert.Throws<ArgumentException>(() => new CandidateDigest(text!));

    /// <summary>Compiler success binds exact output; a rejected policy provides neither artifact nor digest.</summary>
    [Fact]
    public void Compiler_ProvidesDigestOnlyForCompleteCandidate()
    {
        var result = NftFilterCompiler.Compile(new(1, FilterVerdict.Drop, []));
        Assert.Equal(CandidateDigest.FromText(result.Candidate!), result.Digest);
        var denied = NftFilterCompiler.Compile(new(99, FilterVerdict.Drop, []));
        Assert.Null(denied.Candidate);
        Assert.Null(denied.Digest);
    }

    /// <summary>Unenrolled or revisionless claims cannot enter a plan.</summary>
    [Fact]
    public void Ownership_RequiresExplicitIdentityAndRevision()
    {
        Assert.Throws<ArgumentException>(() => new ResourceOwnership(Guid.Empty, Owner, 1));
        Assert.Throws<ArgumentException>(() => new ResourceOwnership(Agent, Guid.Empty, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ResourceOwnership(Agent, Owner, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => Plan(revision: ulong.MaxValue));
        Assert.Equal(ulong.MaxValue, Plan(revision: ulong.MaxValue - 1).ConfirmedRevision);
    }

    /// <summary>Every plan has a meaningful bounded confirmation window.</summary>
    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(3601)]
    public void Plan_InvalidTimeout_Throws(int seconds)
        => Assert.Throws<ArgumentOutOfRangeException>(() => Plan(timeout: TimeSpan.FromSeconds(seconds)));

    /// <summary>Missing or ambiguous operation/artifact bindings cannot be approved.</summary>
    [Fact]
    public void Plan_RejectsMissingAndIdenticalBindings()
    {
        Assert.Throws<ArgumentException>(() => Plan(operation: Guid.Empty));
        Assert.Throws<ArgumentException>(() => Plan(candidate: Rollback));
        Assert.Throws<ArgumentNullException>(() => new ApplyPlan(Operation, null!, Candidate, Rollback, TimeSpan.FromSeconds(30)));
        Assert.Throws<ArgumentNullException>(() => new ApplyPlan(Operation, new(Agent, Owner, 1), null!, Rollback, TimeSpan.FromSeconds(30)));
        Assert.Throws<ArgumentNullException>(() => new ApplyPlan(Operation, new(Agent, Owner, 1), Candidate, null!, TimeSpan.FromSeconds(30)));
        Assert.Throws<ArgumentNullException>(() => ApplySession.Prepare(null!));
        var session = ApplySession.Prepare(Plan());
        Assert.Throws<ArgumentNullException>(() => session.Advance(ApplyEvent.CheckDeadline, null!, Guid.Empty, TimeSpan.Zero));
    }

    /// <summary>Only matching armed, applied and timely confirmed acknowledgments complete the success path.</summary>
    [Fact]
    public void Session_SuccessPathPreservesOriginalSnapshots()
    {
        var initial = ApplySession.Prepare(Plan());
        var armed = Accept(initial, ApplyEvent.RollbackArmed, 5);
        var applied = Accept(armed, ApplyEvent.CandidateApplied, 6);
        var confirmed = Accept(applied, ApplyEvent.Confirm, 34);
        Assert.Equal(ApplyPhase.Prepared, initial.Phase);
        Assert.Null(initial.Deadline);
        Assert.Equal(Guid.Empty, initial.WatchdogId);
        Assert.Equal(ApplyPhase.RollbackArmed, armed.Phase);
        Assert.Equal(TimeSpan.FromSeconds(35), armed.Deadline);
        Assert.Equal(ApplyPhase.AwaitingConfirmation, applied.Phase);
        Assert.Equal(ApplyPhase.Confirmed, confirmed.Phase);
        Assert.True(confirmed.IsTerminal);
        Assert.Equal(8UL, confirmed.Plan.ConfirmedRevision);
        Assert.Equal(7UL, confirmed.Plan.Ownership.Revision);
    }

    /// <summary>Unarmed or unverified work cannot be acknowledged as applied, confirmed or restored.</summary>
    [Theory]
    [InlineData(ApplyEvent.CandidateApplied)]
    [InlineData(ApplyEvent.ApplyFailed)]
    [InlineData(ApplyEvent.Confirm)]
    [InlineData(ApplyEvent.VerificationFailed)]
    [InlineData(ApplyEvent.RollbackSucceeded)]
    [InlineData(ApplyEvent.RollbackFailed)]
    public void Session_OutOfOrderEvent_Denies(ApplyEvent kind)
    {
        var session = ApplySession.Prepare(Plan());
        var result = session.Advance(kind, session.Plan, Guid.Empty, TimeSpan.Zero);
        DeniedUnchanged(session, result, "phase.invalid");
    }

    /// <summary>Every part of the ownership/operation/artifact binding participates in stale-evidence denial.</summary>
    [Fact]
    public void Session_MismatchedBindings_CannotConfirm()
    {
        var session = Accept(Armed(), ApplyEvent.CandidateApplied, 6);
        ApplyPlan[] mismatches =
        [
            Plan(operation: Other), Plan(agent: Other), Plan(owner: Other), Plan(revision: 8),
            Plan(candidate: CandidateDigest.FromText("different candidate")),
            Plan(rollback: CandidateDigest.FromText("different rollback")),
            Plan(timeout: TimeSpan.FromSeconds(31)),
        ];
        foreach (var evidence in mismatches)
        {
            DeniedUnchanged(session, session.Advance(ApplyEvent.Confirm, evidence, Watchdog, TimeSpan.FromSeconds(7)), "binding.mismatch");
        }
        // Structural equality allows a faithfully reconstructed binding, not only the same object reference.
        Assert.True(session.Advance(ApplyEvent.Confirm, Plan(), Watchdog, TimeSpan.FromSeconds(7)).Accepted);
    }

    /// <summary>Arming cannot omit a watchdog; later events cannot substitute another watchdog.</summary>
    [Fact]
    public void Session_WatchdogIdentityIsMandatoryAndBound()
    {
        var session = ApplySession.Prepare(Plan());
        DeniedUnchanged(session, session.Advance(ApplyEvent.RollbackArmed, session.Plan, Guid.Empty, TimeSpan.Zero), "watchdog.required");
        var armed = Armed();
        foreach (var wrong in new[] { Guid.Empty, Other })
        {
            DeniedUnchanged(armed, armed.Advance(ApplyEvent.CandidateApplied, armed.Plan, wrong, TimeSpan.FromSeconds(6)), "watchdog.mismatch");
        }
    }

    /// <summary>Clock regression and unknown event values cannot bypass deadlines or transitions.</summary>
    [Fact]
    public void Session_RejectsInvalidTimeAndUnknownEvents()
    {
        var session = Armed();
        DeniedUnchanged(session, session.Advance(ApplyEvent.CheckDeadline, session.Plan, Watchdog, TimeSpan.FromTicks(-1)), "time.invalid");
        DeniedUnchanged(session, session.Advance(ApplyEvent.CheckDeadline, session.Plan, Watchdog, TimeSpan.FromSeconds(4)), "time.regressed");
        DeniedUnchanged(session, session.Advance((ApplyEvent)99, session.Plan, Watchdog, TimeSpan.FromSeconds(6)), "event.unknown");
        var prepared = ApplySession.Prepare(Plan());
        DeniedUnchanged(prepared, prepared.Advance(ApplyEvent.RollbackArmed, prepared.Plan, Watchdog, TimeSpan.MaxValue), "time.overflow");
    }

    /// <summary>Acknowledgments at or after the deadline cannot revive the confirmation window.</summary>
    [Theory]
    [InlineData(ApplyEvent.CandidateApplied, 35)]
    [InlineData(ApplyEvent.CandidateApplied, 36)]
    [InlineData(ApplyEvent.Confirm, 35)]
    [InlineData(ApplyEvent.Confirm, 36)]
    public void Session_DeadlineDeniesLateSuccessAndRequiresRollback(ApplyEvent kind, int seconds)
    {
        var session = Armed();
        if (kind == ApplyEvent.Confirm)
        {
            session = Accept(session, ApplyEvent.CandidateApplied, 6);
        }

        var result = session.Advance(kind, session.Plan, Watchdog, TimeSpan.FromSeconds(seconds));
        Assert.False(result.Accepted);
        Assert.Equal("deadline.expired", result.ErrorCode);
        Assert.Equal(ApplyPhase.RollbackRequired, result.Session.Phase);
        Assert.Equal(TimeSpan.FromSeconds(seconds), result.Session.Elapsed);
        Assert.NotEqual(ApplyPhase.RollbackRequired, session.Phase);
    }

    /// <summary>The final tick before expiration still permits confirmation; expiration itself requires rollback.</summary>
    [Fact]
    public void Session_ExactDeadlineBoundary()
    {
        var applied = Accept(Armed(), ApplyEvent.CandidateApplied, 6);
        var before = applied.Advance(ApplyEvent.Confirm, applied.Plan, Watchdog, applied.Deadline!.Value - TimeSpan.FromTicks(1));
        Assert.True(before.Accepted);
        Assert.Equal(ApplyPhase.Confirmed, before.Session.Phase);
        var expired = Accept(applied, ApplyEvent.CheckDeadline, 35);
        Assert.Equal(ApplyPhase.RollbackRequired, expired.Phase);
        Assert.Equal(ApplyPhase.RolledBack, Accept(expired, ApplyEvent.RollbackSucceeded, 36).Phase);
    }

    /// <summary>Failure cannot be treated as unchanged state; rollback and failed restoration remain visible.</summary>
    [Theory]
    [InlineData(ApplyEvent.RollbackSucceeded, ApplyPhase.RolledBack)]
    [InlineData(ApplyEvent.RollbackFailed, ApplyPhase.RecoveryRequired)]
    public void Session_ApplyFailureRequiresRollback(ApplyEvent outcome, ApplyPhase terminal)
    {
        var failed = Accept(Armed(), ApplyEvent.ApplyFailed, 6);
        Assert.Equal(ApplyPhase.RollbackRequired, failed.Phase);
        DeniedUnchanged(failed, failed.Advance(ApplyEvent.Confirm, failed.Plan, Watchdog, TimeSpan.FromSeconds(7)), "phase.invalid");
        var restored = Accept(failed, outcome, 7);
        Assert.Equal(terminal, restored.Phase);
        Assert.True(restored.IsTerminal);
    }

    /// <summary>Loss of execution context never becomes an implicit confirmation or successful rollback.</summary>
    [Theory]
    [InlineData(ApplyPhase.Prepared)]
    [InlineData(ApplyPhase.RollbackArmed)]
    [InlineData(ApplyPhase.AwaitingConfirmation)]
    [InlineData(ApplyPhase.RollbackRequired)]
    public void Session_InterruptionRequiresRecovery(ApplyPhase phase)
    {
        var session = ApplySession.Prepare(Plan());
        if (phase != ApplyPhase.Prepared)
        {
            session = Accept(session, ApplyEvent.RollbackArmed, 5);
        }

        if (phase == ApplyPhase.AwaitingConfirmation)
        {
            session = Accept(session, ApplyEvent.CandidateApplied, 6);
        }

        if (phase == ApplyPhase.RollbackRequired)
        {
            session = Accept(session, ApplyEvent.ApplyFailed, 6);
        }

        Assert.Equal(ApplyPhase.RecoveryRequired, Accept(session, ApplyEvent.Interrupted, 7).Phase);
    }

    /// <summary>Terminal results cannot be overwritten by delayed, repeated or conflicting acknowledgments.</summary>
    [Fact]
    public void Session_TerminalStatesCannotReopen()
    {
        var confirmed = Accept(Accept(Armed(), ApplyEvent.CandidateApplied, 6), ApplyEvent.Confirm, 7);
        var failed = Accept(Armed(), ApplyEvent.ApplyFailed, 6);
        ApplySession[] terminal = [confirmed, Accept(failed, ApplyEvent.RollbackSucceeded, 7), Accept(failed, ApplyEvent.RollbackFailed, 7)];
        foreach (var session in terminal)
        {
            foreach (var kind in Enum.GetValues<ApplyEvent>())
            {
                DeniedUnchanged(session, session.Advance(kind, session.Plan, Watchdog, TimeSpan.FromHours(2)), "phase.terminal");
            }
        }
    }

    /// <summary>Failed verification after apply requires immediate rollback without waiting for timeout.</summary>
    [Fact]
    public void Session_VerificationFailureRequiresImmediateRollback()
    {
        var applied = Accept(Armed(), ApplyEvent.CandidateApplied, 6);
        var failed = Accept(applied, ApplyEvent.VerificationFailed, 7);
        Assert.Equal(ApplyPhase.RollbackRequired, failed.Phase);
        Assert.Equal(ApplyPhase.RolledBack, Accept(failed, ApplyEvent.RollbackSucceeded, 8).Phase);
    }

    /// <summary>Polling cannot extend a deadline or let repeated arming replace an existing watchdog.</summary>
    [Fact]
    public void Session_PollingAndRepeatedArmingDoNotRenewLease()
    {
        var armed = Armed();
        var polled = Accept(armed, ApplyEvent.CheckDeadline, 10);
        Assert.Equal(armed.Deadline, polled.Deadline);
        Assert.Equal(TimeSpan.FromSeconds(10), polled.Elapsed);
        DeniedUnchanged(polled, polled.Advance(ApplyEvent.RollbackArmed, polled.Plan, Watchdog, TimeSpan.FromSeconds(11)), "phase.invalid");
        DeniedUnchanged(polled, polled.Advance(ApplyEvent.Confirm, polled.Plan, Watchdog, TimeSpan.FromSeconds(11)), "phase.invalid");
        var applied = Accept(polled, ApplyEvent.CandidateApplied, 11);
        DeniedUnchanged(applied, applied.Advance(ApplyEvent.CandidateApplied, applied.Plan, Watchdog, TimeSpan.FromSeconds(12)), "phase.invalid");
        DeniedUnchanged(applied, applied.Advance(ApplyEvent.RollbackSucceeded, applied.Plan, Watchdog, TimeSpan.FromSeconds(12)), "phase.invalid");
        var expired = Accept(applied, ApplyEvent.CheckDeadline, 35);
        Assert.Equal(armed.Deadline, expired.Deadline);
        Assert.Equal(ApplyPhase.RollbackRequired, expired.Phase);
    }

    /// <summary>Timeout limits are inclusive and elapsed arithmetic is checked before arming.</summary>
    [Fact]
    public void Session_ArmingSupportsExactTimeoutBoundsWithoutOverflow()
    {
        Assert.Equal(TimeSpan.FromTicks(1), Plan(timeout: TimeSpan.FromTicks(1)).ConfirmationTimeout);
        var plan = Plan(timeout: TimeSpan.FromHours(1));
        var session = ApplySession.Prepare(plan);
        var result = session.Advance(ApplyEvent.RollbackArmed, plan, Watchdog, TimeSpan.MaxValue - plan.ConfirmationTimeout);
        Assert.True(result.Accepted);
        Assert.Equal(TimeSpan.MaxValue, result.Session.Deadline);
        var expired = result.Session.Advance(ApplyEvent.CheckDeadline, plan, Watchdog, TimeSpan.MaxValue);
        Assert.True(expired.Accepted);
        Assert.Equal(ApplyPhase.RollbackRequired, expired.Session.Phase);
    }

    private static ApplyPlan Plan(Guid? operation = null, Guid? agent = null, Guid? owner = null,
        ulong revision = 7, CandidateDigest? candidate = null, CandidateDigest? rollback = null, TimeSpan? timeout = null)
        => new(operation ?? Operation, new(agent ?? Agent, owner ?? Owner, revision),
            candidate ?? Candidate, rollback ?? Rollback, timeout ?? TimeSpan.FromSeconds(30));

    private static ApplySession Armed() => Accept(ApplySession.Prepare(Plan()), ApplyEvent.RollbackArmed, 5);

    private static ApplySession Accept(ApplySession session, ApplyEvent kind, int seconds)
    {
        var watchdog = kind == ApplyEvent.RollbackArmed ? Watchdog : session.WatchdogId;
        var result = session.Advance(kind, session.Plan, watchdog, TimeSpan.FromSeconds(seconds));
        Assert.True(result.Accepted, result.ErrorCode);
        return result.Session;
    }

    private static void DeniedUnchanged(ApplySession original, ApplyTransition result, string code)
    {
        Assert.False(result.Accepted);
        Assert.Equal(code, result.ErrorCode);
        Assert.Same(original, result.Session);
    }
}
