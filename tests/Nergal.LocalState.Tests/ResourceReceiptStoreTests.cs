using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Data.Sqlite;
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
    private static readonly ResourceOwnership Ownership = new(Agent, Owner, 1);
    private static string Artifact(FilterVerdict verdict) => NftFilterCompiler.Compile(new(1, verdict, []), new(Owner, Resource)).Candidate!;

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
        public JournalTime Read() => new(BootId, TimeSpan.FromSeconds(100));
    }
    private sealed class Fixture : IDisposable
    {
        internal string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "nergal-receipt-" + Guid.NewGuid().ToString("N"));
        internal string Database => System.IO.Path.Combine(Path, "journal.db");
        internal TestClock Clock { get; } = new();
        internal ApplyJournal Store { get; }
        internal Fixture()
        {
            Directory.CreateDirectory(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Store = ApplyJournal.Initialize(Path, Ownership, Artifact(FilterVerdict.Accept), Clock);
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
        internal void MakeLegacy() => Sql("DROP TRIGGER bound_resource_no_legacy_start; DROP TABLE resource_receipt; ALTER TABLE enrollment DROP COLUMN resource_bound; PRAGMA user_version=1");
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
