using Microsoft.Data.Sqlite;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.LocalState;

public sealed partial class ApplyJournal
{
    /// <summary>Explicitly upgrades a quiescent schema-1 journal to schema 2 without resetting enrollment or history.</summary>
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
            Execute(connection, transaction, "ALTER TABLE enrollment ADD COLUMN resource_bound INTEGER NOT NULL DEFAULT 0 CHECK(resource_bound IN(0,1))");
            Execute(connection, transaction, ReceiptSchema);
            Execute(connection, transaction, "PRAGMA user_version=2");
            transaction.Commit();
            return journal;
        }
        catch (SqliteException) { throw new JournalException("database.error"); }
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

            var reconstructed = NftFilterCompiler.Compile(new FilterPolicy(1, actual.DefaultVerdict, []), actual.Identity);
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

    private const string ReceiptSchema = """

        CREATE TABLE resource_receipt(singleton INTEGER PRIMARY KEY REFERENCES enrollment(singleton) CHECK(singleton=1),
          revision TEXT NOT NULL,boot TEXT NOT NULL,namespace TEXT NOT NULL,owner TEXT NOT NULL,
          resource TEXT NOT NULL,handle TEXT NOT NULL,digest TEXT NOT NULL) STRICT;
        CREATE TRIGGER bound_resource_no_legacy_start BEFORE INSERT ON operations
          WHEN (SELECT resource_bound FROM enrollment WHERE singleton=1)=1
          BEGIN SELECT RAISE(ABORT,'bound resource apply is unavailable'); END;
        """;
}
