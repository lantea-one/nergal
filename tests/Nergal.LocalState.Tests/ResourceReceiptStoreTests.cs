using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Nergal.Core.Agent;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;
using Nergal.LocalState;
using Nergal.Nftables;

namespace Nergal.LocalState.Tests;

/// <summary>Verifies protected expected state never follows a rejected observation or silently re-enables legacy apply.</summary>
[SupportedOSPlatform("linux")]
public sealed class ResourceReceiptStoreTests
{
    private static readonly Guid Agent = Guid.Parse("00000000-0000-0000-0000-000000000001");
    private static readonly Guid Owner = Guid.Parse("00000000-0000-0000-0000-000000000002");
    private static readonly Guid Resource = Guid.Parse("00000000-0000-0000-0000-000000000003");
    private static readonly Guid Boot = Guid.Parse("00000000-0000-0000-0000-000000000004");
    private static readonly Guid Other = Guid.Parse("00000000-0000-0000-0000-000000000005");
    private static readonly Guid Watchdog = Guid.Parse("00000000-0000-0000-0000-000000000006");
    private static readonly ResourceOwnership Ownership = new(Agent, Owner, 1);
    private static string Artifact(FilterVerdict verdict) => NftFilterCompiler.Compile(new(1, verdict, []), new(Owner, Resource)).Candidate!;

    /// <summary>Receipt-aware bound apply records candidate evidence and atomically advances revision and expected receipt on confirmation.</summary>
    [Fact]
    public void BoundApply_ConfirmAdvancesRevisionAndReceiptAtomically()
    {
        using var fixture = new Fixture(resourceIntent: true);
        var baseline = Observe(handle: 7, verdict: FilterVerdict.Accept);
        fixture.Store.BindExpectedResource(Ownership, Receipt(baseline), baseline, 42);

        var plan = fixture.Plan();
        var entry = fixture.Store.StartBound(plan, Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept), baseline, 42);
        Assert.Equal(ApplyPhase.Prepared, entry.Session.Phase);
        Assert.True(fixture.Store.Advance(plan.OperationId, ApplyEvent.RollbackArmed, plan, Watchdog).Accepted);

        Reject("resource.boundReceiptRequired", () => fixture.Store.Advance(plan.OperationId, ApplyEvent.CandidateApplied, plan, Watchdog));
        Reject("resource.boundReceiptRequired", () => fixture.Store.Advance(plan.OperationId, ApplyEvent.Confirm, plan, Watchdog));
        Reject("resource.boundReceiptRequired", () => fixture.Store.Advance(plan.OperationId, ApplyEvent.RollbackSucceeded, plan, Watchdog));

        var candidateObs = Observe(handle: 12, verdict: FilterVerdict.Drop);
        fixture.Clock.Seconds = 105;
        var applied = fixture.Store.RecordCandidateAppliedBound(plan.OperationId, plan, Watchdog, Receipt(candidateObs), candidateObs, 42);
        Assert.True(applied.Accepted);
        Assert.Equal(ApplyPhase.AwaitingConfirmation, applied.Entry.Session.Phase);

        fixture.Clock.Seconds = 110;
        var confirmed = fixture.Store.ConfirmBound(plan.OperationId, plan, Watchdog, candidateObs, 42);
        Assert.True(confirmed.Accepted);
        Assert.Equal(ApplyPhase.Confirmed, confirmed.Entry.Session.Phase);
        Assert.Null(fixture.Store.ReadActive());
        Assert.Equal(2UL, fixture.Store.ReadEnrollment().Ownership.Revision);
        Assert.Equal(Artifact(FilterVerdict.Drop), fixture.Store.ReadEnrollment().Artifact);
        var stored = fixture.Store.ReadExpectedResource()!;
        Assert.Equal(12UL, stored.TableHandle);
        Assert.True(fixture.Store.VerifyExpectedResource(candidateObs, 42).IsMatch);
    }

    /// <summary>Bound rollback updates the expected receipt handle without advancing revision and enables subsequent bound applies.</summary>
    [Fact]
    public void BoundApply_RollbackUpdatesReceiptHandleWithoutAdvancingRevision()
    {
        using var fixture = new Fixture(resourceIntent: true);
        var baseline = Observe(handle: 7, verdict: FilterVerdict.Accept);
        fixture.Store.BindExpectedResource(Ownership, Receipt(baseline), baseline, 42);

        var plan = fixture.Plan();
        fixture.Store.StartBound(plan, Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept), baseline, 42);
        Assert.True(fixture.Store.Advance(plan.OperationId, ApplyEvent.RollbackArmed, plan, Watchdog).Accepted);
        var candidateObs = Observe(handle: 12, verdict: FilterVerdict.Drop);
        Assert.True(fixture.Store.RecordCandidateAppliedBound(plan.OperationId, plan, Watchdog, Receipt(candidateObs), candidateObs, 42).Accepted);

        fixture.Clock.Seconds = 131;
        var expired = fixture.Store.ConfirmBound(plan.OperationId, plan, Watchdog, candidateObs, 42);
        Assert.False(expired.Accepted);
        Assert.Equal("deadline.expired", expired.ErrorCode);
        Assert.Equal(ApplyPhase.RollbackRequired, expired.Entry.Session.Phase);

        Reject("rollback.mismatch", () => fixture.Store.RecordRollbackSucceededBound(plan.OperationId, plan, Watchdog, Receipt(candidateObs), candidateObs, 42));

        var restored = Observe(handle: 15, verdict: FilterVerdict.Accept);
        var rolledBack = fixture.Store.RecordRollbackSucceededBound(plan.OperationId, plan, Watchdog, Receipt(restored), restored, 42);
        Assert.True(rolledBack.Accepted);
        Assert.Equal(ApplyPhase.RolledBack, rolledBack.Entry.Session.Phase);
        Assert.Null(fixture.Store.ReadActive());
        Assert.Equal(1UL, fixture.Store.ReadEnrollment().Ownership.Revision);
        Assert.Equal(15UL, fixture.Store.ReadExpectedResource()!.TableHandle);

        var nextPlan = fixture.Plan();
        Assert.Equal(ApplyPhase.Prepared, fixture.Store.StartBound(nextPlan, Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept), restored, 42).Session.Phase);
    }

    /// <summary>Bound apply operations fail closed on unbound journals, drifted observations, and mismatched candidate evidence.</summary>
    [Fact]
    public void BoundApply_RejectsDriftStaleAndMismatchedEvidence()
    {
        using var fixture = new Fixture();
        Reject("resource.unbound", () => fixture.Store.StartBound(fixture.Plan(), Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept), Observe(), 42));

        var baseline = Observe(handle: 7, verdict: FilterVerdict.Accept);
        fixture.Store.BindExpectedResource(Ownership, Receipt(baseline), baseline, 42);

        Reject("resource.receiptMismatch", () => fixture.Store.StartBound(fixture.Plan(), Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept), Observe(handle: 99), 42));
        Reject("resource.receiptMismatch", () => fixture.Store.StartBound(fixture.Plan(), Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept), baseline, 43));

        var plan = fixture.Plan();
        fixture.Store.StartBound(plan, Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept), baseline, 42);
        Assert.True(fixture.Store.Advance(plan.OperationId, ApplyEvent.RollbackArmed, plan, Watchdog).Accepted);

        var candidateObs = Observe(handle: 12, verdict: FilterVerdict.Drop);
        Reject("resource.receiptMismatch", () => fixture.Store.RecordCandidateAppliedBound(plan.OperationId, plan, Watchdog, Receipt(Observe(handle: 13, verdict: FilterVerdict.Drop)), candidateObs, 42));
        Reject("resource.candidateMismatch", () => fixture.Store.RecordCandidateAppliedBound(plan.OperationId, plan, Watchdog, Receipt(Observe(handle: 12, verdict: FilterVerdict.Accept)), Observe(handle: 12, verdict: FilterVerdict.Accept), 42));

        Assert.True(fixture.Store.RecordCandidateAppliedBound(plan.OperationId, plan, Watchdog, Receipt(candidateObs), candidateObs, 42).Accepted);
        Reject("resource.receiptMismatch", () => fixture.Store.ConfirmBound(plan.OperationId, plan, Watchdog, Observe(handle: 13, verdict: FilterVerdict.Drop), 42));
        Assert.Equal(ApplyPhase.AwaitingConfirmation, fixture.Store.ReadActive()!.Session.Phase);
    }

    /// <summary>Quiescent schema-2 migration preserves bound receipts and history while enabling schema-3 bound operations.</summary>
    [Fact]
    public void MigrationFromVersion2_PreservesBoundReceiptAndEnablesBoundApply()
    {
        using var fixture = new Fixture();
        var baseline = Observe(handle: 7, verdict: FilterVerdict.Accept);
        fixture.Store.BindExpectedResource(Ownership, Receipt(baseline), baseline, 42);
        fixture.MakeVersion2();

        var before = File.ReadAllBytes(fixture.Database);
        Reject("journal.schemaOrIntegrity", () => ApplyJournal.Open(fixture.Path, fixture.Clock));
        Assert.Equal(before, File.ReadAllBytes(fixture.Database));

        var upgraded = ApplyJournal.UpgradeFromVersion2(fixture.Path, fixture.Clock);
        Assert.Equal(Receipt(baseline), upgraded.ReadExpectedResource());
        var plan = fixture.Plan();
        upgraded.StartBound(plan, Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept), baseline, 42);
        Assert.True(upgraded.Advance(plan.OperationId, ApplyEvent.RollbackArmed, plan, Watchdog).Accepted);
        var candidateObs = Observe(handle: 20, verdict: FilterVerdict.Drop);
        Assert.True(upgraded.RecordCandidateAppliedBound(plan.OperationId, plan, Watchdog, Receipt(candidateObs), candidateObs, 42).Accepted);
        Assert.True(upgraded.ConfirmBound(plan.OperationId, plan, Watchdog, candidateObs, 42).Accepted);
        Assert.Equal(2UL, upgraded.ReadEnrollment().Ownership.Revision);

        using var activeFixture = new Fixture();
        var activePlan = activeFixture.Plan();
        activeFixture.Store.Start(activePlan, Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept));
        activeFixture.MakeVersion2();
        var activeBefore = File.ReadAllBytes(activeFixture.Database);
        Reject("migration.activeOperation", () => ApplyJournal.UpgradeFromVersion2(activeFixture.Path, activeFixture.Clock));
        Assert.Equal(activeBefore, File.ReadAllBytes(activeFixture.Database));
    }

    /// <summary>Explicit new-boot reconciliation updates boot/namespace/handle receipts, marks prior active work interrupted, and rejects same-boot calls.</summary>
    [Fact]
    public void ReconcileBoot_UpdatesContextAndClearsPriorBootWorkOnlyAfterBootChange()
    {
        using var fixture = new Fixture(resourceIntent: true);
        var baseline = Observe(handle: 7, verdict: FilterVerdict.Accept);
        fixture.Store.BindExpectedResource(Ownership, Receipt(baseline), baseline, 42);

        Reject("reconcile.sameBoot", () => fixture.Store.ReconcileBoot(Ownership, Receipt(baseline), baseline, 42));

        var plan = fixture.Plan();
        fixture.Store.StartBound(plan, Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept), baseline, 42);
        Assert.True(fixture.Store.Advance(plan.OperationId, ApplyEvent.RollbackArmed, plan, Watchdog).Accepted);

        var newBoot = Guid.NewGuid();
        fixture.Clock.BootId = newBoot;
        fixture.Clock.Seconds = 5;
        var recreated = Observe(handle: 18, verdict: FilterVerdict.Accept);
        var newReceipt = new NftTableReceipt(newBoot, 99UL, recreated.Identity, recreated.TableHandle, recreated.StateDigest);

        Reject("resource.baselineMismatch", () =>
        {
            var wrongPolicy = Observe(handle: 18, verdict: FilterVerdict.Drop);
            fixture.Store.ReconcileBoot(Ownership, new(newBoot, 99UL, wrongPolicy.Identity, wrongPolicy.TableHandle, wrongPolicy.StateDigest), wrongPolicy, 99UL);
        });

        var reconciled = fixture.Store.ReconcileBoot(Ownership, newReceipt, recreated, 99UL);
        Assert.Equal(newReceipt, reconciled);
        Assert.Null(fixture.Store.ReadActive());
        Assert.Equal(ApplyPhase.RecoveryRequired, fixture.Store.Read(plan.OperationId).Session.Phase);
        Assert.Equal(1UL, fixture.Store.ReadEnrollment().Ownership.Revision);
        Assert.Equal(newReceipt, fixture.Store.ReadExpectedResource());
        Assert.True(fixture.Store.VerifyExpectedResource(recreated, 99UL).IsMatch);
    }

    /// <summary>A crash between intent and receipt cannot enable legacy operations or permit a second initializer.</summary>
    [Fact]
    public void FreshResourceIntent_DeniesReplayAndLegacyStartBeforeBinding()
    {
        using var fixture = new Fixture(resourceIntent: true);
        var journal = ApplyJournal.Open(fixture.Path, fixture.Clock);
        Reject("journal.exists", () => ApplyJournal.InitializeResourceIntent(fixture.Path, Ownership, Artifact(FilterVerdict.Accept), fixture.Clock));
        Reject("database.error", () => journal.Start(fixture.Plan(), Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept)));
        Assert.Null(journal.ReadActive());
        Assert.Null(journal.ReadExpectedResource());
        journal.BindExpectedResource(Ownership, Receipt(Observe()), Observe(), 42);
        Assert.True(journal.VerifyExpectedResource(Observe(), 42).IsMatch);
    }

    /// <summary>Only explicit binding establishes expected state, and reopening/retry preserves the same receipt.</summary>
    [Fact]
    public void Binding_IsExplicitPersistentAndIdempotent()
    {
        using var fixture = new Fixture();
        var actual = Observe();
        Assert.Null(fixture.Store.ReadExpectedResource());
        Reject("resource.unbound", () => fixture.Store.VerifyExpectedResource(actual, 42));
        var expected = Receipt(actual);
        Assert.Equal(expected, fixture.Store.BindExpectedResource(Ownership, expected, actual, 42));
        var bytes = File.ReadAllBytes(fixture.Database);
        var reopened = ApplyJournal.Open(fixture.Path, fixture.Clock);
        Assert.Equal(expected, reopened.ReadExpectedResource());
        Assert.True(reopened.VerifyExpectedResource(actual, 42).IsMatch);
        Assert.Equal(expected, reopened.BindExpectedResource(Ownership, expected, actual, 42));
        Assert.Equal(bytes, File.ReadAllBytes(fixture.Database));
    }

    /// <summary>One read-only classification uses the protected snapshot revision and never substitutes observed state as authority.</summary>
    [Fact]
    public void Status_UsesProtectedBindingAndPreservesDatabaseBytes()
    {
        using var fixture = new Fixture();
        var unbound = File.ReadAllBytes(fixture.Database);
        Assert.Equal(new(AgentStatusOutcome.Unbound, 1), fixture.Store.ReadResourceStatus(null, 42));
        Assert.Equal(new(AgentStatusOutcome.Unbound, 1), fixture.Store.ReadResourceStatus(Observe(handle: 8), 42));
        Assert.Equal(unbound, File.ReadAllBytes(fixture.Database));

        fixture.Store.BindExpectedResource(Ownership, Receipt(Observe()), Observe(), 42);
        var bound = File.ReadAllBytes(fixture.Database);
        Assert.Equal(new(AgentStatusOutcome.Matched, 1), fixture.Store.ReadResourceStatus(Observe(), 42));
        Assert.Equal(new(AgentStatusOutcome.Drift, 1), fixture.Store.ReadResourceStatus(Observe(verdict: FilterVerdict.Drop), 42));
        Assert.Equal(new(AgentStatusOutcome.Drift, 1), fixture.Store.ReadResourceStatus(Observe(handle: 8), 42));
        Assert.Equal(new(AgentStatusOutcome.Drift, 1), fixture.Store.ReadResourceStatus(Observe(), 43));
        Assert.Equal(new(AgentStatusOutcome.Unavailable), fixture.Store.ReadResourceStatus(null, 42));
        fixture.Clock.BootId = Other;
        Assert.Equal(new(AgentStatusOutcome.Drift, 1), fixture.Store.ReadResourceStatus(Observe(), 42));
        Assert.Equal(bound, File.ReadAllBytes(fixture.Database));
    }

    /// <summary>Pending and recovery-blocked work cannot be described as an idle unbound resource.</summary>
    [Fact]
    public void Status_ActiveAndRecoveryBlockedWorkDiscloseNoRevision()
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan();
        fixture.Store.Start(plan, Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept));
        Assert.Equal(new(AgentStatusOutcome.Unavailable), fixture.Store.ReadResourceStatus(null, 42));
        Assert.True(fixture.Store.Advance(plan.OperationId, ApplyEvent.Interrupted, plan, Guid.Empty).Accepted);
        var before = File.ReadAllBytes(fixture.Database);
        Assert.Equal(new(AgentStatusOutcome.Unavailable), fixture.Store.ReadResourceStatus(Observe(), 42));
        Assert.Equal(before, File.ReadAllBytes(fixture.Database));
    }

    /// <summary>Classification follows committed revisions after legacy confirmation rather than retaining an earlier enrollment read.</summary>
    [Fact]
    public void Status_ReportsCommittedRevisionAndRejectsInvalidContext()
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan();
        fixture.Store.Start(plan, Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept));
        foreach (var kind in new[] { ApplyEvent.RollbackArmed, ApplyEvent.CandidateApplied, ApplyEvent.Confirm })
        {
            Assert.True(fixture.Store.Advance(plan.OperationId, kind, plan, Other).Accepted);
        }

        Assert.Equal(new(AgentStatusOutcome.Unbound, 2), fixture.Store.ReadResourceStatus(null, 42));
        Assert.Throws<ArgumentOutOfRangeException>(() => fixture.Store.ReadResourceStatus(null, 0));
        fixture.Clock.BootId = Other;
        Assert.Equal(new(AgentStatusOutcome.Unavailable), fixture.Store.ReadResourceStatus(null, 42));
    }

    /// <summary>Policy drift and table recreation are classification failures, never new expected state.</summary>
    [Fact]
    public void Reconciliation_DriftDoesNotRewriteExpectedReceipt()
    {
        using var fixture = new Fixture();
        var original = Observe();
        var expected = Receipt(original);
        fixture.Store.BindExpectedResource(Ownership, expected, original, 42);
        var before = File.ReadAllBytes(fixture.Database);
        Assert.Equal(["state.drift"], fixture.Store.VerifyExpectedResource(Observe(verdict: FilterVerdict.Drop), 42).ErrorCodes);
        var replacement = Observe(handle: 8);
        Assert.Equal(["handle.mismatch", "state.drift"], fixture.Store.VerifyExpectedResource(replacement, 42).ErrorCodes);
        Reject("resource.alreadyBound", () => fixture.Store.BindExpectedResource(Ownership, Receipt(replacement), replacement, 42));
        Assert.Equal(expected, fixture.Store.ReadExpectedResource());
        Assert.Equal(before, File.ReadAllBytes(fixture.Database));
    }

    /// <summary>Protected owner/revision/boot and artifact intent must agree before a receipt can be bound.</summary>
    [Fact]
    public void Binding_RejectsStaleContextAndBaselineClaims()
    {
        using var fixture = new Fixture();
        var actual = Observe();
        Reject("ownership.stale", () => fixture.Store.BindExpectedResource(new(Agent, Owner, 2), Receipt(actual), actual, 42));
        Reject("resource.receiptMismatch", () => fixture.Store.BindExpectedResource(Ownership, Receipt(actual), actual, 43));
        Reject("resource.receiptMismatch", () => fixture.Store.BindExpectedResource(Ownership,
            new(Boot, 42, actual.Identity, 8, actual.StateDigest), actual, 42));
        var wrongPolicy = Observe(verdict: FilterVerdict.Drop);
        Reject("resource.baselineMismatch", () => fixture.Store.BindExpectedResource(Ownership, Receipt(wrongPolicy), wrongPolicy, 42));
        var wrongBirth = Observe(resource: Other);
        Reject("resource.baselineMismatch", () => fixture.Store.BindExpectedResource(Ownership, Receipt(wrongBirth), wrongBirth, 42));
        fixture.Clock.BootId = Other;
        Reject("clock.bootChanged", () => fixture.Store.BindExpectedResource(Ownership, Receipt(actual), actual, 42));
        Assert.Null(fixture.Store.ReadExpectedResource());
    }

    /// <summary>Active legacy work and receipt-aware work cannot be mixed or converted by binding.</summary>
    [Fact]
    public void Binding_DeniesActiveOperationsAndBoundLegacyStarts()
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan();
        fixture.Store.Start(plan, Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept));
        Reject("resource.busy", () => fixture.Store.BindExpectedResource(Ownership, Receipt(Observe()), Observe(), 42));
        fixture.Rollback(plan);
        fixture.Store.BindExpectedResource(Ownership, Receipt(Observe()), Observe(), 42);
        Reject("resource.boundApplyUnavailable", () => fixture.Store.Start(fixture.Plan(), Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept)));
        Assert.Null(fixture.Store.ReadActive());
        // An older queued writer must also encounter a database-level barrier, not only the current API guard.
        var error = Assert.Throws<SqliteException>(() => fixture.Sql("INSERT INTO operations SELECT * FROM operations"));
        Assert.Equal(1811, error.SqliteExtendedErrorCode); // SQLITE_CONSTRAINT_TRIGGER, not a duplicate primary key.
    }

    /// <summary>Missing receipt data on a marked resource is corruption, never a fallback to legacy authority.</summary>
    [Fact]
    public void MissingBoundReceipt_CannotReenableLegacyStart()
    {
        using var fixture = new Fixture();
        fixture.Store.BindExpectedResource(Ownership, Receipt(Observe()), Observe(), 42);
        fixture.Sql("DELETE FROM resource_receipt");
        Reject("journal.corrupt", () => fixture.Store.ReadExpectedResource());
        Reject("journal.corrupt", () => fixture.Store.ReadResourceStatus(null, 42));
        Reject("journal.corrupt", () => fixture.Store.Start(fixture.Plan(), Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept)));
    }

    /// <summary>Malformed protected receipt fields do not become valid expected state through permissive decoding.</summary>
    [Theory]
    [InlineData("UPDATE resource_receipt SET revision='2'")]
    [InlineData("UPDATE resource_receipt SET namespace='0'")]
    [InlineData("UPDATE resource_receipt SET handle='0'")]
    [InlineData("UPDATE resource_receipt SET digest='invalid'")]
    [InlineData("UPDATE resource_receipt SET resource='00000000-0000-0000-0000-000000000000'")]
    [InlineData("UPDATE enrollment SET resource_bound=0")]
    public void ReceiptCorruption_IsRejected(string damage)
    {
        using var fixture = new Fixture();
        fixture.Store.BindExpectedResource(Ownership, Receipt(Observe()), Observe(), 42);
        fixture.Sql(damage);
        Reject("journal.corrupt", () => fixture.Store.ReadExpectedResource());
        Reject("journal.corrupt", () => fixture.Store.ReadResourceStatus(null, 42));
    }

    /// <summary>Changed boot or namespace denies reconciliation without rebinding or clearing the receipt.</summary>
    [Fact]
    public void Reconciliation_RejectsNewContextWithoutStateMutation()
    {
        using var fixture = new Fixture();
        var expected = fixture.Store.BindExpectedResource(Ownership, Receipt(Observe()), Observe(), 42);
        Assert.Contains("context.namespaceChanged", fixture.Store.VerifyExpectedResource(Observe(), 43).ErrorCodes);
        fixture.Clock.BootId = Other;
        Assert.Contains("context.bootChanged", fixture.Store.VerifyExpectedResource(Observe(), 42).ErrorCodes);
        Assert.Equal(expected, fixture.Store.ReadExpectedResource());
    }

    /// <summary>Explicit quiescent migration preserves confirmed enrollment/history and does not invent a binding.</summary>
    [Fact]
    public void Migration_PreservesLegacyHistoryAndEnrollment()
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan();
        fixture.Store.Start(plan, Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept));
        fixture.Rollback(plan);
        fixture.MakeLegacy();
        // Literal schema-1 identifiers make this fixture independent of today's enum declarations.
        fixture.Sql("UPDATE events SET kind=CASE sequence WHEN 1 THEN 0 WHEN 2 THEN 2 WHEN 3 THEN 6 END,phase=CASE sequence WHEN 1 THEN 1 WHEN 2 THEN 4 WHEN 3 THEN 5 END; UPDATE operations SET phase=5");
        var before = File.ReadAllBytes(fixture.Database);
        Reject("journal.schemaOrIntegrity", () => ApplyJournal.Open(fixture.Path, fixture.Clock));
        Assert.Equal(before, File.ReadAllBytes(fixture.Database));
        var upgraded = ApplyJournal.UpgradeFromVersion1(fixture.Path, fixture.Clock);
        Assert.Null(upgraded.ReadExpectedResource());
        Assert.Equal(Artifact(FilterVerdict.Accept), upgraded.ReadEnrollment().Artifact);
        Assert.Equal(Ownership, upgraded.ReadEnrollment().Ownership);
        Assert.Equal(ApplyPhase.RolledBack, upgraded.Read(plan.OperationId).Session.Phase);
        upgraded.BindExpectedResource(Ownership, Receipt(Observe()), Observe(), 42);
        Assert.True(upgraded.VerifyExpectedResource(Observe(), 42).IsMatch);
    }

    /// <summary>Migration must never strand an active older watchdog or reset recovery-blocked state.</summary>
    [Fact]
    public void Migration_ActiveOperationRejectsWithoutChangingLegacyBytes()
    {
        using var fixture = new Fixture();
        fixture.Store.Start(fixture.Plan(), Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept));
        fixture.MakeLegacy();
        var before = File.ReadAllBytes(fixture.Database);
        Reject("migration.activeOperation", () => ApplyJournal.UpgradeFromVersion1(fixture.Path, fixture.Clock));
        Assert.Equal(before, File.ReadAllBytes(fixture.Database));
    }

    /// <summary>Invalid retained history aborts before schema changes; it cannot be repaired by migration.</summary>
    [Fact]
    public void Migration_DamagedHistoryLeavesLegacyStateUnchanged()
    {
        using var fixture = new Fixture();
        var plan = fixture.Plan();
        fixture.Store.Start(plan, Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept));
        fixture.Rollback(plan);
        fixture.MakeLegacy();
        fixture.Sql("UPDATE events SET kind=99");
        var before = File.ReadAllBytes(fixture.Database);
        Reject("journal.corrupt", () => ApplyJournal.UpgradeFromVersion1(fixture.Path, fixture.Clock));
        Assert.Equal(before, File.ReadAllBytes(fixture.Database));
    }

    /// <summary>Complete auxiliary intent is checked at binding and confirmation; identical primary policy cannot hide auxiliary drift.</summary>
    [Fact]
    public void CompleteBundle_RejectsMissingBaselineAndChangedAuxiliaryCandidate()
    {
        var assembly = typeof(ResourceReceiptStoreTests).Assembly;
        using var stream = assembly.GetManifestResourceStream(assembly.GetManifestResourceNames().Single(n => n.EndsWith("bundle-echo.json", StringComparison.Ordinal)))!;
        using var reader = new StreamReader(stream);
        var json = reader.ReadToEnd().Replace(new NftTableIdentity(
            Guid.Parse("00000000-0000-0000-0000-000000000010"), Guid.Parse("00000000-0000-0000-0000-000000000020")).Comment,
            new NftTableIdentity(Owner, Resource).Comment, StringComparison.Ordinal);
        NftTableObservation Parse(string text) => NftTableObservation.ParseBundleReplacementEcho(text, new(Owner, Resource), true, true, true).Observation!;
        var baseline = Parse(json);
        var artifact = NftPolicyBundleCompiler.Compile(baseline.Bundle, baseline.Identity).Candidate!;
        using var fixture = new Fixture(resourceIntent: true, artifact: artifact);
        var primary = NftTableObservation.ParseReplacementEcho(new System.Text.Json.Nodes.JsonObject
        {
            ["nftables"] = new System.Text.Json.Nodes.JsonArray(System.Text.Json.Nodes.JsonNode.Parse(json)!["nftables"]!.AsArray()
                .TakeWhile(i => i?["create"]?["table"]?["name"]?.GetValue<string>() != "nergal_nat").Select(i => i!.DeepClone()).ToArray()),
        }.ToJsonString()).Observation!;
        Reject("resource.baselineMismatch", () => fixture.Store.BindExpectedResource(Ownership, Receipt(primary), primary, 42));
        fixture.Store.BindExpectedResource(Ownership, Receipt(baseline), baseline, 42);
        var changed = System.Text.Json.Nodes.JsonNode.Parse(json)!;
        var rule = changed["nftables"]!.AsArray().Select(i => i?["add"]?["rule"]).First(i => (string?)i?["table"] == "nergal_aux")!;
        rule["expr"]!.AsArray()[^1] = new System.Text.Json.Nodes.JsonObject { ["accept"] = null };
        var candidate = Parse(changed.ToJsonString());
        var candidateArtifact = NftPolicyBundleCompiler.Compile(candidate.Bundle, candidate.Identity).Candidate!;
        var plan = new ApplyPlan(Guid.NewGuid(), Ownership, CandidateDigest.FromText(candidateArtifact), CandidateDigest.FromText(artifact), TimeSpan.FromSeconds(30));
        fixture.Store.StartBound(plan, candidateArtifact, artifact, baseline, 42);
        Assert.True(fixture.Store.Advance(plan.OperationId, ApplyEvent.RollbackArmed, plan, Watchdog).Accepted);
        Reject("resource.candidateMismatch", () => fixture.Store.RecordCandidateAppliedBound(plan.OperationId, plan, Watchdog, Receipt(baseline), baseline, 42));
        Assert.True(fixture.Store.RecordCandidateAppliedBound(plan.OperationId, plan, Watchdog, Receipt(candidate), candidate, 42).Accepted);
        Reject("resource.receiptMismatch", () => fixture.Store.ConfirmBound(plan.OperationId, plan, Watchdog, baseline, 42));
        Assert.Equal(1UL, fixture.Store.ReadEnrollment().Ownership.Revision);
        Assert.True(fixture.Store.ConfirmBound(plan.OperationId, plan, Watchdog, candidate, 42).Accepted);
    }

    private static NftTableObservation Observe(ulong handle = 7, FilterVerdict verdict = FilterVerdict.Accept, Guid? resource = null)
    {
        var text = JsonSerializer.Serialize(new
        {
            nftables = new object[]
        {
            new { metainfo = new { version = "fixture", release_name = "fixture", json_schema_version = 1 } },
            new { table = new { family = "inet", name = "nergal_filter", handle, comment = new NftTableIdentity(Owner, resource ?? Resource).Comment } },
            new { chain = new { family = "inet", table = "nergal_filter", name = "input", handle = 9, type = "filter", hook = "input", prio = 0,
                policy = verdict == FilterVerdict.Accept ? "accept" : "drop" } },
        }
        });
        return NftTableObservation.Parse(text).Observation!;
    }
    private static NftTableReceipt Receipt(NftTableObservation observation) => new(Boot, 42, observation.Identity, observation.TableHandle, observation.StateDigest);
    private static void Reject(string code, Action action) => Assert.Equal(code, Assert.Throws<JournalException>(action).Code);
    private sealed class TestClock : IJournalClock
    {
        internal Guid BootId { get; set; } = Boot;
        internal int Seconds { get; set; } = 100;
        public JournalTime Read() => new(BootId, TimeSpan.FromSeconds(Seconds));
    }
    private sealed class Fixture : IDisposable
    {
        internal string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "nergal-receipt-" + Guid.NewGuid().ToString("N"));
        internal string Database => System.IO.Path.Combine(Path, "journal.db");
        internal TestClock Clock { get; } = new();
        internal ApplyJournal Store { get; }
        internal Fixture(bool resourceIntent = false, string? artifact = null)
        {
            Directory.CreateDirectory(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Store = resourceIntent ? ApplyJournal.InitializeResourceIntent(Path, Ownership, artifact ?? Artifact(FilterVerdict.Accept), Clock) :
                ApplyJournal.Initialize(Path, Ownership, Artifact(FilterVerdict.Accept), Clock);
        }
        internal ApplyPlan Plan() => new(Guid.NewGuid(), Ownership, CandidateDigest.FromText(Artifact(FilterVerdict.Drop)),
            CandidateDigest.FromText(Artifact(FilterVerdict.Accept)), TimeSpan.FromSeconds(30));
        internal void Rollback(ApplyPlan plan)
        {
            foreach (var kind in new[] { ApplyEvent.RollbackArmed, ApplyEvent.ApplyFailed, ApplyEvent.RollbackSucceeded })
            {
                Assert.True(Store.Advance(plan.OperationId, kind, plan, Other).Accepted);
            }
        }
        internal void MakeLegacy() => Sql("DROP TRIGGER bound_resource_no_legacy_start; DROP TABLE bound_operations; DROP TABLE resource_receipt; ALTER TABLE enrollment DROP COLUMN resource_bound; PRAGMA user_version=1");
        internal void MakeVersion2() => Sql("""
            DROP TRIGGER bound_resource_no_legacy_start;
            DROP TABLE bound_operations;
            CREATE TRIGGER bound_resource_no_legacy_start BEFORE INSERT ON operations
              WHEN (SELECT resource_bound FROM enrollment WHERE singleton=1)=1
              BEGIN SELECT RAISE(ABORT,'bound resource apply is unavailable'); END;
            PRAGMA user_version=2
            """);
        internal void Sql(string sql)
        {
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Database, Pooling = false }.ToString());
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            command.ExecuteNonQuery();
        }
        public void Dispose() => Directory.Delete(Path, true);
    }
}
