using Microsoft.Data.Sqlite;
using Nergal.Core.Agent;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.LocalState;

public sealed partial class ApplyJournal
{
    /// <summary>Classifies a complete local observation using enrollment and expected receipt from one protected read transaction.</summary>
    /// <param name="actual">Complete locally collected observation, or null when unavailable/unrecognized.</param>
    /// <param name="currentNamespace">Nonzero trusted current namespace inode, never request data.</param>
    /// <remarks>Caller authenticates first and holds its resource lock across collection/query. This advisory snapshot is not authority to mutate a resource. No repair or adoption occurs.</remarks>
    /// <exception cref="ArgumentOutOfRangeException">Current namespace is zero.</exception>
    /// <exception cref="JournalException">Protected state, local clock or database validation fails; no partial status is returned.</exception>
    public AgentStatusReply ReadResourceStatus(NftTableObservation? actual, ulong currentNamespace)
    {
        if (currentNamespace == 0) { throw new ArgumentOutOfRangeException(nameof(currentNamespace)); }
        return Inspect<AgentStatusReply>((connection, transaction) =>
        {
            var enrollment = Enrollment(connection, transaction);
            var receipt = LoadReceipt(connection, transaction, enrollment.Value, enrollment.Boot, enrollment.ResourceBound);
            var now = Now();
            if (enrollment.Active is not null || (receipt is null && now.BootId != enrollment.Boot))
            {
                return new(AgentStatusOutcome.Unavailable);
            }

            if (receipt is null)
            {
                return new(AgentStatusOutcome.Unbound, enrollment.Value.Ownership.Revision);
            }

            if (actual is null)
            {
                return new(AgentStatusOutcome.Unavailable);
            }

            var comparison = NftReceiptVerifier.Verify(receipt, actual, now.BootId, currentNamespace);
            return new(comparison.IsMatch ? AgentStatusOutcome.Matched : AgentStatusOutcome.Drift, enrollment.Value.Ownership.Revision);
        });
    }

    /// <summary>Explicitly upgrades a quiescent schema-1 journal to schema 3 without resetting enrollment or history.</summary>
    /// <remarks>Caller must stop all older writers first. Active/recovery-blocked operations forbid migration; this API cannot prove process quiescence.</remarks>
    /// <exception cref="JournalException">State is active, corrupt, unsupported or cannot be atomically upgraded.</exception>
    public static ApplyJournal UpgradeFromVersion1(string directory, IJournalClock? clock = null)
    {
        var journal = new ApplyJournal(directory, clock ?? new LinuxBootClock());
        try
        {
            using var connection = journal.Connect(expectedVersion: 1);
            using var transaction = connection.BeginTransaction(deferred: false);
            if (!Equals(Scalar(connection, transaction, "PRAGMA user_version"), 1L))
            {
                throw new JournalException("journal.schemaOrIntegrity");
            }

            var enrollment = Enrollment(connection, transaction, legacy: true);
            if (enrollment.Active is not null)
            {
                throw new JournalException("migration.activeOperation");
            }

            VerifyTerminalOperations(connection, transaction);
            Execute(connection, transaction, "ALTER TABLE enrollment ADD COLUMN resource_bound INTEGER NOT NULL DEFAULT 0 CHECK(resource_bound IN(0,1))");
            Execute(connection, transaction, ReceiptSchema);
            Execute(connection, transaction, "PRAGMA user_version=3");
            transaction.Commit();
            return journal;
        }
        catch (SqliteException) { throw new JournalException("database.error"); }
    }

    /// <summary>Explicitly upgrades a quiescent schema-2 journal to schema 3 without resetting enrollment, receipts or history.</summary>
    /// <remarks>Caller must stop all older writers first. Active/recovery-blocked operations forbid migration; this API cannot prove process quiescence.</remarks>
    /// <exception cref="JournalException">State is active, corrupt, unsupported or cannot be atomically upgraded.</exception>
    public static ApplyJournal UpgradeFromVersion2(string directory, IJournalClock? clock = null)
    {
        var journal = new ApplyJournal(directory, clock ?? new LinuxBootClock());
        try
        {
            using var connection = journal.Connect(expectedVersion: 2);
            using var transaction = connection.BeginTransaction(deferred: false);
            if (!Equals(Scalar(connection, transaction, "PRAGMA user_version"), 2L))
            {
                throw new JournalException("journal.schemaOrIntegrity");
            }

            var enrollment = Enrollment(connection, transaction);
            _ = LoadReceipt(connection, transaction, enrollment.Value, enrollment.Boot, enrollment.ResourceBound);
            if (enrollment.Active is not null)
            {
                throw new JournalException("migration.activeOperation");
            }

            VerifyTerminalOperations(connection, transaction);
            var hasEnrollmentTrigger = Scalar(connection, transaction,
                "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name='enrollment_no_legacy_start'") is long count && count == 1;
            Execute(connection, transaction, "DROP TRIGGER IF EXISTS bound_resource_no_legacy_start");
            Execute(connection, transaction, BoundOperationsSchema);
            if (hasEnrollmentTrigger)
            {
                Execute(connection, transaction, "DROP TRIGGER enrollment_no_legacy_start");
                Execute(connection, transaction, EnrollmentNoLegacyStartTrigger);
            }

            Execute(connection, transaction, "PRAGMA user_version=3");
            transaction.Commit();
            return journal;
        }
        catch (SqliteException) { throw new JournalException("database.error"); }
    }

    private static void VerifyTerminalOperations(SqliteConnection connection, SqliteTransaction transaction)
    {
        var operations = new List<Guid>();
        using (var command = Command(connection, transaction, "SELECT id FROM operations ORDER BY id"))
        using (var rows = command.ExecuteReader())
        {
            while (rows.Read())
            {
                operations.Add(ParseId(rows.GetString(0)));
            }
        }

        foreach (var operation in operations)
        {
            var entry = Load(connection, transaction, operation);
            if (entry.Session.Phase is not (ApplyPhase.Confirmed or ApplyPhase.RolledBack))
            {
                throw new JournalException("journal.corrupt");
            }
        }
    }

    /// <summary>Reads a protected expected receipt, or null when no explicit binding has been recorded.</summary>
    /// <remarks>A missing binding is not permission to adopt an observed resource.</remarks>
    public NftTableReceipt? ReadExpectedResource()
    {
        return Inspect((connection, transaction) =>
        {
            var enrollment = Enrollment(connection, transaction);
            return LoadReceipt(connection, transaction, enrollment.Value, enrollment.Boot, enrollment.ResourceBound);
        });
    }

    /// <summary>Persists an explicit trusted expected receipt only when enrolled intent and a complete observation agree.</summary>
    /// <param name="ownership">Expected enrolled agent/owner/revision.</param>
    /// <param name="expected">Expected receipt from trusted exclusive-creation/bootstrap evidence, never browser claims.</param>
    /// <param name="actual">Complete observation collected locally under the resource execution lock.</param>
    /// <param name="currentNamespace">Trusted current namespace inode, not request data.</param>
    /// <remarks>Does not establish exclusive creation or perform kernel operations. A different existing receipt is never replaced.</remarks>
    /// <exception cref="ArgumentNullException">Ownership, expected receipt or actual observation is null.</exception>
    /// <exception cref="JournalException">Enrollment, content, context or existing binding disagrees, or an operation is active.</exception>
    public NftTableReceipt BindExpectedResource(ResourceOwnership ownership, NftTableReceipt expected, NftTableObservation actual, ulong currentNamespace)
    {
        ArgumentNullException.ThrowIfNull(ownership);
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(actual);
        return Write((connection, transaction) =>
        {
            var enrollment = Enrollment(connection, transaction);
            if (enrollment.Active is not null)
            {
                throw new JournalException("resource.busy");
            }

            if (ownership != enrollment.Value.Ownership || expected.Identity.OwnerId != ownership.OwnerId)
            {
                throw new JournalException("ownership.stale");
            }

            var now = Now();
            if (now.BootId != enrollment.Boot)
            {
                throw new JournalException("clock.bootChanged");
            }

            if (!NftReceiptVerifier.Verify(expected, actual, now.BootId, currentNamespace).IsMatch)
            {
                throw new JournalException("resource.receiptMismatch");
            }

            var reconstructed = NftPolicyBundleCompiler.Compile(actual.Bundle, actual.Identity);
            if (reconstructed.Candidate != enrollment.Value.Artifact)
            {
                throw new JournalException("resource.baselineMismatch");
            }

            var prior = LoadReceipt(connection, transaction, enrollment.Value, enrollment.Boot, enrollment.ResourceBound);
            if (prior is not null)
            {
                if (prior != expected)
                {
                    throw new JournalException("resource.alreadyBound");
                }

                return prior;
            }
            Execute(connection, transaction,
                "INSERT INTO resource_receipt VALUES(1,$revision,$boot,$namespace,$owner,$resource,$handle,$digest)",
                ("$revision", Revision(ownership.Revision)), ("$boot", Id(expected.BootId)),
                ("$namespace", Revision(expected.NetworkNamespace)), ("$owner", Id(expected.Identity.OwnerId)),
                ("$resource", Id(expected.Identity.ResourceId)), ("$handle", Revision(expected.TableHandle)), ("$digest", expected.StateDigest.Value));
            Execute(connection, transaction, "UPDATE enrollment SET resource_bound=1 WHERE singleton=1");
            return expected;
        });
    }

    /// <summary>Atomically reserves a bound-resource operation after verifying the protected expected receipt against live observation.</summary>
    /// <exception cref="ArgumentNullException">Plan, candidate, rollback, or observation is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Current namespace is zero.</exception>
    /// <exception cref="JournalException">Resource is unbound, busy, drifted, stale, from another boot, or artifacts disagree.</exception>
    public JournalEntry StartBound(ApplyPlan plan, string candidate, string rollback, NftTableObservation currentObservation, ulong currentNamespace)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(currentObservation);
        if (currentNamespace == 0) { throw new ArgumentOutOfRangeException(nameof(currentNamespace)); }
        CheckArtifact(candidate);
        CheckArtifact(rollback);
        if (CandidateDigest.FromText(candidate) != plan.Candidate || CandidateDigest.FromText(rollback) != plan.Rollback)
        {
            throw new JournalException("artifact.mismatch");
        }

        return Write((connection, transaction) =>
        {
            var enrollment = Enrollment(connection, transaction);
            var now = Now();
            if (now.BootId != enrollment.Boot)
            {
                throw new JournalException("clock.bootChanged");
            }

            if (enrollment.Active is not null)
            {
                throw new JournalException("resource.busy");
            }

            if (enrollment.Value.Ownership != plan.Ownership)
            {
                throw new JournalException("ownership.stale");
            }

            if (enrollment.Value.Artifact != rollback)
            {
                throw new JournalException("rollback.mismatch");
            }

            var receipt = LoadReceipt(connection, transaction, enrollment.Value, enrollment.Boot, enrollment.ResourceBound)
                ?? throw new JournalException("resource.unbound");
            if (!NftReceiptVerifier.Verify(receipt, currentObservation, now.BootId, currentNamespace).IsMatch)
            {
                throw new JournalException("resource.receiptMismatch");
            }

            var reconstructed = NftPolicyBundleCompiler.Compile(currentObservation.Bundle, currentObservation.Identity);
            if (reconstructed.Candidate != rollback)
            {
                throw new JournalException("resource.baselineMismatch");
            }

            if (Scalar(connection, transaction, "SELECT count(*) FROM operations WHERE id=$id", ("$id", Id(plan.OperationId))) is long opCount && opCount != 0 ||
                IsBoundOperation(connection, transaction, plan.OperationId))
            {
                throw new JournalException("operation.reused");
            }

            Execute(connection, transaction,
                "INSERT INTO bound_operations VALUES($id,$baselineHandle,$baselineDigest,NULL,NULL,1)",
                ("$id", Id(plan.OperationId)), ("$baselineHandle", Revision(receipt.TableHandle)),
                ("$baselineDigest", receipt.StateDigest.Value));
            Execute(connection, transaction,
                "INSERT INTO operations VALUES($id,$agent,$owner,$revision,$candidate,$rollback,$candidateHash,$rollbackHash,$timeout,$boot,$started,0)",
                ("$id", Id(plan.OperationId)), ("$agent", Id(plan.Ownership.AgentId)), ("$owner", Id(plan.Ownership.OwnerId)),
                ("$revision", Revision(plan.Ownership.Revision)), ("$candidate", candidate), ("$rollback", rollback),
                ("$candidateHash", plan.Candidate.Value), ("$rollbackHash", plan.Rollback.Value),
                ("$timeout", plan.ConfirmationTimeout.Ticks), ("$boot", Id(now.BootId)), ("$started", now.SinceBoot.Ticks));
            Execute(connection, transaction, "UPDATE bound_operations SET allow_insert=0 WHERE operation=$id", ("$id", Id(plan.OperationId)));
            Execute(connection, transaction, "UPDATE enrollment SET active=$id WHERE singleton=1", ("$id", Id(plan.OperationId)));
            return new JournalEntry(ApplySession.Prepare(plan), candidate, rollback, now);
        });
    }

    /// <summary>Verifies candidate creation-echo and full listing evidence before recording <see cref="ApplyPhase.AwaitingConfirmation"/>.</summary>
    /// <exception cref="ArgumentNullException">Evidence, candidate echo receipt, or candidate listing is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Current namespace is zero.</exception>
    /// <exception cref="JournalException">Operation is unbound, receipt/candidate evidence mismatches, or storage fails.</exception>
    public JournalUpdate RecordCandidateAppliedBound(Guid operationId, ApplyPlan evidence, Guid watchdogId,
        NftTableReceipt candidateEchoReceipt, NftTableObservation candidateListing, ulong currentNamespace)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        ArgumentNullException.ThrowIfNull(candidateEchoReceipt);
        ArgumentNullException.ThrowIfNull(candidateListing);
        if (currentNamespace == 0) { throw new ArgumentOutOfRangeException(nameof(currentNamespace)); }
        return Write((connection, transaction) =>
        {
            if (!IsBoundOperation(connection, transaction, operationId))
            {
                throw new JournalException("resource.unboundOperation");
            }

            var enrollment = Enrollment(connection, transaction);
            var receipt = LoadReceipt(connection, transaction, enrollment.Value, enrollment.Boot, enrollment.ResourceBound)
                ?? throw new JournalException("resource.unbound");
            return AdvanceCore(connection, transaction, operationId, ApplyEvent.CandidateApplied, evidence, watchdogId, (entry, now) =>
            {
                if (currentNamespace != receipt.NetworkNamespace || candidateEchoReceipt.Identity != receipt.Identity ||
                    !NftReceiptVerifier.Verify(candidateEchoReceipt, candidateListing, now.BootId, currentNamespace).IsMatch)
                {
                    throw new JournalException("resource.receiptMismatch");
                }

                var reconstructed = NftPolicyBundleCompiler.Compile(candidateListing.Bundle, candidateListing.Identity);
                if (reconstructed.Candidate != entry.Candidate)
                {
                    throw new JournalException("resource.candidateMismatch");
                }

                Execute(connection, transaction,
                    "UPDATE bound_operations SET candidate_handle=$handle,candidate_digest=$digest WHERE operation=$id",
                    ("$handle", Revision(candidateListing.TableHandle)), ("$digest", candidateListing.StateDigest.Value),
                    ("$id", Id(operationId)));
            });
        });
    }

    /// <summary>Verifies live candidate kernel state against recorded operation evidence and atomically commits confirmed revision and receipt.</summary>
    /// <exception cref="ArgumentNullException">Evidence or current listing is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Current namespace is zero.</exception>
    /// <exception cref="JournalException">Operation is unbound, live candidate state disagrees, or storage is corrupt.</exception>
    public JournalUpdate ConfirmBound(Guid operationId, ApplyPlan evidence, Guid watchdogId,
        NftTableObservation currentListing, ulong currentNamespace)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        ArgumentNullException.ThrowIfNull(currentListing);
        if (currentNamespace == 0) { throw new ArgumentOutOfRangeException(nameof(currentNamespace)); }
        return Write((connection, transaction) =>
        {
            if (!IsBoundOperation(connection, transaction, operationId))
            {
                throw new JournalException("resource.unboundOperation");
            }

            var enrollment = Enrollment(connection, transaction);
            var receipt = LoadReceipt(connection, transaction, enrollment.Value, enrollment.Boot, enrollment.ResourceBound)
                ?? throw new JournalException("resource.unbound");
            return AdvanceCore(connection, transaction, operationId, ApplyEvent.Confirm, evidence, watchdogId, (entry, now) =>
            {
                var (candidateHandle, candidateDigest) = ReadBoundCandidate(connection, transaction, operationId);
                var expectedCandidate = new NftTableReceipt(enrollment.Boot, receipt.NetworkNamespace, receipt.Identity,
                    candidateHandle, candidateDigest);
                if (!NftReceiptVerifier.Verify(expectedCandidate, currentListing, now.BootId, currentNamespace).IsMatch)
                {
                    throw new JournalException("resource.receiptMismatch");
                }

                var reconstructed = NftPolicyBundleCompiler.Compile(currentListing.Bundle, currentListing.Identity);
                if (reconstructed.Candidate != entry.Candidate)
                {
                    throw new JournalException("resource.candidateMismatch");
                }

                Execute(connection, transaction,
                    "UPDATE resource_receipt SET revision=$revision,handle=$handle,digest=$digest WHERE singleton=1",
                    ("$revision", Revision(evidence.ConfirmedRevision)), ("$handle", Revision(currentListing.TableHandle)),
                    ("$digest", currentListing.StateDigest.Value));
            });
        });
    }

    /// <summary>Verifies restored baseline creation/replacement echo and full listing before updating the receipt handle without advancing revision.</summary>
    /// <exception cref="ArgumentNullException">Evidence, restored echo receipt, or restored listing is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Current namespace is zero.</exception>
    /// <exception cref="JournalException">Operation is unbound, restored state mismatches rollback artifact, or storage fails.</exception>
    public JournalUpdate RecordRollbackSucceededBound(Guid operationId, ApplyPlan evidence, Guid watchdogId,
        NftTableReceipt restoredEchoReceipt, NftTableObservation restoredListing, ulong currentNamespace)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        ArgumentNullException.ThrowIfNull(restoredEchoReceipt);
        ArgumentNullException.ThrowIfNull(restoredListing);
        if (currentNamespace == 0) { throw new ArgumentOutOfRangeException(nameof(currentNamespace)); }
        return Write((connection, transaction) =>
        {
            if (!IsBoundOperation(connection, transaction, operationId))
            {
                throw new JournalException("resource.unboundOperation");
            }

            var enrollment = Enrollment(connection, transaction);
            var receipt = LoadReceipt(connection, transaction, enrollment.Value, enrollment.Boot, enrollment.ResourceBound)
                ?? throw new JournalException("resource.unbound");
            return AdvanceCore(connection, transaction, operationId, ApplyEvent.RollbackSucceeded, evidence, watchdogId, (entry, now) =>
            {
                if (currentNamespace != receipt.NetworkNamespace || restoredEchoReceipt.Identity != receipt.Identity ||
                    !NftReceiptVerifier.Verify(restoredEchoReceipt, restoredListing, now.BootId, currentNamespace).IsMatch)
                {
                    throw new JournalException("resource.receiptMismatch");
                }

                var reconstructed = NftPolicyBundleCompiler.Compile(restoredListing.Bundle, restoredListing.Identity);
                if (reconstructed.Candidate != entry.Rollback)
                {
                    throw new JournalException("rollback.mismatch");
                }

                Execute(connection, transaction,
                    "UPDATE resource_receipt SET handle=$handle,digest=$digest WHERE singleton=1",
                    ("$handle", Revision(restoredListing.TableHandle)), ("$digest", restoredListing.StateDigest.Value));
            });
        });
    }

    /// <summary>Explicitly reconciles an enrolled bound resource on a new Linux boot after exclusive kernel baseline re-creation.</summary>
    /// <remarks>Never adopts preexisting kernel tables or runs on the same boot. Nonterminal operations from the prior boot are recorded as interrupted.</remarks>
    /// <exception cref="ArgumentNullException">Ownership, expected receipt, or actual observation is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Current namespace is zero.</exception>
    /// <exception cref="JournalException">Resource is unbound, boot is unchanged, or recreated kernel evidence mismatches confirmed baseline.</exception>
    public NftTableReceipt ReconcileBoot(ResourceOwnership ownership, NftTableReceipt recreatedExpected, NftTableObservation recreatedActual, ulong currentNamespace)
    {
        ArgumentNullException.ThrowIfNull(ownership);
        ArgumentNullException.ThrowIfNull(recreatedExpected);
        ArgumentNullException.ThrowIfNull(recreatedActual);
        if (currentNamespace == 0) { throw new ArgumentOutOfRangeException(nameof(currentNamespace)); }
        return Write((connection, transaction) =>
        {
            var enrollment = Enrollment(connection, transaction);
            var prior = LoadReceipt(connection, transaction, enrollment.Value, enrollment.Boot, enrollment.ResourceBound)
                ?? throw new JournalException("resource.unbound");
            if (ownership != enrollment.Value.Ownership || recreatedExpected.Identity != prior.Identity)
            {
                throw new JournalException("ownership.stale");
            }

            var now = Now();
            if (now.BootId == enrollment.Boot)
            {
                throw new JournalException("reconcile.sameBoot");
            }

            if (!NftReceiptVerifier.Verify(recreatedExpected, recreatedActual, now.BootId, currentNamespace).IsMatch)
            {
                throw new JournalException("resource.receiptMismatch");
            }

            var reconstructed = NftPolicyBundleCompiler.Compile(recreatedActual.Bundle, recreatedActual.Identity);
            if (reconstructed.Candidate != enrollment.Value.Artifact)
            {
                throw new JournalException("resource.baselineMismatch");
            }

            if (enrollment.Active is { } activeId)
            {
                var activeEntry = Load(connection, transaction, activeId);
                if (!activeEntry.Session.IsTerminal)
                {
                    var interrupted = activeEntry.Session.Advance(ApplyEvent.Interrupted, activeEntry.Session.Plan,
                        activeEntry.Session.WatchdogId, activeEntry.Session.Elapsed);
                    if (interrupted.Session.Phase != activeEntry.Session.Phase)
                    {
                        Append(connection, transaction, activeEntry, interrupted.Session, ApplyEvent.Interrupted,
                            activeEntry.Session.WatchdogId, interrupted.ErrorCode);
                    }
                }
            }

            Execute(connection, transaction, "UPDATE enrollment SET boot=$boot,active=NULL WHERE singleton=1",
                ("$boot", Id(now.BootId)));
            Execute(connection, transaction,
                "UPDATE resource_receipt SET boot=$boot,namespace=$namespace,handle=$handle,digest=$digest WHERE singleton=1",
                ("$boot", Id(now.BootId)), ("$namespace", Revision(currentNamespace)),
                ("$handle", Revision(recreatedActual.TableHandle)), ("$digest", recreatedActual.StateDigest.Value));
            return recreatedExpected;
        });
    }

    private static bool IsBoundOperation(SqliteConnection connection, SqliteTransaction transaction, Guid operationId) =>
        Scalar(connection, transaction, "SELECT count(*) FROM bound_operations WHERE operation=$id", ("$id", Id(operationId))) is long count && count == 1;

    private static (ulong Handle, CandidateDigest Digest) ReadBoundCandidate(SqliteConnection connection, SqliteTransaction transaction, Guid operationId)
    {
        using var command = Command(connection, transaction,
            "SELECT candidate_handle,candidate_digest FROM bound_operations WHERE operation=$id", ("$id", Id(operationId)));
        using var row = command.ExecuteReader();
        if (!row.Read() || row.IsDBNull(0) || row.IsDBNull(1))
        {
            throw new JournalException("journal.corrupt");
        }

        try
        {
            return (ParseRevision(row.GetString(0)), new CandidateDigest(row.GetString(1)));
        }
        catch (Exception error) when (error is ArgumentException or FormatException or OverflowException or InvalidCastException)
        {
            throw new JournalException("journal.corrupt");
        }
    }

    /// <summary>Loads the protected expected receipt and classifies a complete locally collected observation without repair or adoption.</summary>
    /// <remarks>Caller must hold its execution lock and supply trusted local context. This comparison is not authorization or a kernel mutation guard.</remarks>
    /// <exception cref="ArgumentNullException">Actual observation is null.</exception>
    /// <exception cref="JournalException">No receipt is bound, stored state is invalid or the database fails.</exception>
    public NftReceiptCheck VerifyExpectedResource(NftTableObservation actual, ulong currentNamespace)
    {
        ArgumentNullException.ThrowIfNull(actual);
        return Inspect((connection, transaction) =>
        {
            var enrollment = Enrollment(connection, transaction);
            var receipt = LoadReceipt(connection, transaction, enrollment.Value, enrollment.Boot, enrollment.ResourceBound) ?? throw new JournalException("resource.unbound");
            return NftReceiptVerifier.Verify(receipt, actual, Now().BootId, currentNamespace);
        });
    }

    private static NftTableReceipt? LoadReceipt(SqliteConnection connection, SqliteTransaction transaction, JournalEnrollment enrollment, Guid boot, bool resourceBound)
    {
        using var command = Command(connection, transaction, "SELECT revision,boot,namespace,owner,resource,handle,digest FROM resource_receipt WHERE singleton=1");
        using var row = command.ExecuteReader();
        if (!row.Read())
        {
            if (resourceBound)
            {
                throw new JournalException("journal.corrupt");
            }

            return null;
        }

        if (!resourceBound)
        {
            throw new JournalException("journal.corrupt");
        }

        try
        {
            var receipt = new NftTableReceipt(ParseId(row.GetString(1)), ParseRevision(row.GetString(2)),
                new(ParseId(row.GetString(3)), ParseId(row.GetString(4))), ParseRevision(row.GetString(5)), new(row.GetString(6)));
            if (ParseRevision(row.GetString(0)) != enrollment.Ownership.Revision || receipt.BootId != boot ||
                receipt.Identity.OwnerId != enrollment.Ownership.OwnerId)
            {
                throw new JournalException("journal.corrupt");
            }

            return receipt;
        }
        catch (Exception error) when (error is ArgumentException or FormatException or OverflowException or InvalidCastException)
        {
            throw new JournalException("journal.corrupt");
        }
    }

    private const string EnrollmentNoLegacyStartTrigger = """
        CREATE TRIGGER enrollment_no_legacy_start BEFORE INSERT ON operations
          WHEN NOT EXISTS(SELECT 1 FROM bound_operations WHERE operation=NEW.id AND allow_insert=1)
          BEGIN SELECT RAISE(ABORT,'local enrollment requires receipt-aware apply'); END;
        """;

    private const string BoundOperationsSchema = """
        CREATE TABLE bound_operations(operation TEXT PRIMARY KEY,
          baseline_handle TEXT NOT NULL,baseline_digest TEXT NOT NULL,
          candidate_handle TEXT,candidate_digest TEXT,
          allow_insert INTEGER NOT NULL DEFAULT 1 CHECK(allow_insert IN(0,1))) STRICT;
        CREATE TRIGGER bound_resource_no_legacy_start BEFORE INSERT ON operations
          WHEN (SELECT resource_bound FROM enrollment WHERE singleton=1)=1
            AND NOT EXISTS(SELECT 1 FROM bound_operations WHERE operation=NEW.id AND allow_insert=1)
          BEGIN SELECT RAISE(ABORT,'bound resource apply is unavailable'); END;
        """;

    private const string ReceiptSchema = """

        CREATE TABLE resource_receipt(singleton INTEGER PRIMARY KEY REFERENCES enrollment(singleton) CHECK(singleton=1),
          revision TEXT NOT NULL,boot TEXT NOT NULL,namespace TEXT NOT NULL,owner TEXT NOT NULL,
          resource TEXT NOT NULL,handle TEXT NOT NULL,digest TEXT NOT NULL) STRICT;
        """ + BoundOperationsSchema;
}
