using System.Runtime.Versioning;
using Microsoft.Data.Sqlite;
using Nergal.Core.Deployment;
using Nergal.LocalState;

namespace Nergal.LocalState.Tests;

/// <summary>Exercises real private files and SQLite transactions, not simulated persistence.</summary>
[SupportedOSPlatform("linux")]
public sealed class ApplyJournalTests
{
    private static readonly Guid Agent = Guid.Parse("00000000-0000-0000-0000-000000000001");
    private static readonly Guid Owner = Guid.Parse("00000000-0000-0000-0000-000000000002");
    private static readonly Guid Watchdog = Guid.Parse("00000000-0000-0000-0000-000000000003");
    private const string Prior = "synthetic rollback artifact\n";
    private const string Candidate = "synthetic candidate artifact\n";

    /// <summary>Reopening reconstructs bound operations without process-local object identity.</summary>
    [Fact]
    public void Reopen_ReplaysArmedAppliedAndConfirmedState()
    {
        using var fixture = new JournalFixture();
        var plan = fixture.Plan();
        fixture.Store.Start(plan, Candidate, Prior);
        fixture.Accept(plan, ApplyEvent.RollbackArmed);
        fixture.Clock.Seconds = 101;
        fixture.Accept(plan, ApplyEvent.CandidateApplied);
        var reopened = ApplyJournal.Open(fixture.Path, fixture.Clock);
        Assert.Equal(ApplyPhase.AwaitingConfirmation, reopened.Read(plan.OperationId).Session.Phase);
        fixture.Clock.Seconds = 102;
        Assert.True(reopened.Advance(plan.OperationId, ApplyEvent.Confirm, plan, Watchdog).Accepted);
        var committed = ApplyJournal.Open(fixture.Path, fixture.Clock);
        Assert.Null(committed.ReadActive());
        Assert.Equal(2UL, committed.ReadEnrollment().Ownership.Revision);
        Assert.Equal(Candidate, committed.ReadEnrollment().Artifact);
        Assert.Equal(ApplyPhase.Confirmed, committed.Read(plan.OperationId).Session.Phase);
    }

    /// <summary>Unverified restoration blocks new work; only verified rollback releases it without revision advance.</summary>
    [Theory]
    [InlineData(ApplyEvent.RollbackSucceeded, ApplyPhase.RolledBack)]
    [InlineData(ApplyEvent.RollbackFailed, ApplyPhase.RecoveryRequired)]
    public void Rollback_ControlsReservationAndPreservesConfirmedRevision(ApplyEvent outcome, ApplyPhase phase)
    {
        using var fixture = new JournalFixture();
        var plan = fixture.Plan();
        fixture.Store.Start(plan, Candidate, Prior);
        fixture.Accept(plan, ApplyEvent.RollbackArmed);
        fixture.Accept(plan, ApplyEvent.ApplyFailed);
        fixture.Accept(plan, outcome);
        Assert.Equal(phase, fixture.Store.Read(plan.OperationId).Session.Phase);
        Assert.Equal(1UL, fixture.Store.ReadEnrollment().Ownership.Revision);
        Assert.Equal(Prior, fixture.Store.ReadEnrollment().Artifact);
        if (phase == ApplyPhase.RolledBack)
        {
            Assert.NotNull(fixture.Store.Start(fixture.Plan(), Candidate, Prior));
        }
        else
        {
            Reject("resource.busy", () => fixture.Store.Start(fixture.Plan(), Candidate, Prior));
        }
    }

    /// <summary>Unknown or corrupt durable evidence cannot be silently reset or treated as unrestricted.</summary>
    [Theory]
    [InlineData("PRAGMA user_version=99", "journal.schemaOrIntegrity")]
    [InlineData("PRAGMA application_id=0", "journal.schemaOrIntegrity")]
    [InlineData("UPDATE enrollment SET digest='invalid'", "journal.corrupt")]
    [InlineData("DELETE FROM enrollment", "journal.corrupt")]
    public void Open_InvalidState_FailsClosed(string damage, string code)
    {
        using var fixture = new JournalFixture();
        fixture.Damage(damage);
        Reject(code, () => ApplyJournal.Open(fixture.Path, fixture.Clock));
    }

    /// <summary>Semantic replay rejects altered artifacts and histories even when the database is structurally valid.</summary>
    [Theory]
    [InlineData("UPDATE operations SET candidate='changed'")]
    [InlineData("UPDATE operations SET phase=99")]
    [InlineData("UPDATE events SET kind=99")]
    [InlineData("UPDATE events SET elapsed=-1")]
    [InlineData("DELETE FROM events")]
    [InlineData("UPDATE events SET sequence=2")]
    public void Read_DamagedOperation_FailsClosed(string damage)
    {
        using var fixture = new JournalFixture();
        var plan = fixture.Plan();
        fixture.Store.Start(plan, Candidate, Prior);
        fixture.Accept(plan, ApplyEvent.RollbackArmed);
        fixture.Damage(damage);
        Reject("journal.corrupt", () => fixture.Store.Read(plan.OperationId));
    }

    /// <summary>Deleted or truncated databases remain failures; normal open never reenrolls or recreates them.</summary>
    [Fact]
    public void MissingAndTruncatedDatabase_AreNotReinitialized()
    {
        using var fixture = new JournalFixture();
        File.Delete(fixture.Database);
        Reject("journal.missing", () => ApplyJournal.Open(fixture.Path));
        Assert.False(File.Exists(fixture.Database));
        File.WriteAllText(fixture.Database, "incomplete database");
        File.SetUnixFileMode(fixture.Database, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        Reject("database.error", () => ApplyJournal.Open(fixture.Path));
        Assert.Equal("incomplete database", File.ReadAllText(fixture.Database));
    }

    /// <summary>Open refuses exposed permissions rather than quietly changing them or touching content.</summary>
    [Fact]
    public void PrivateModes_AreCreatedAndEnforced()
    {
        using var fixture = new JournalFixture();
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(fixture.Database));
        File.SetUnixFileMode(fixture.Database, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead);
        Reject("path.databaseMode", () => ApplyJournal.Open(fixture.Path));
        File.SetUnixFileMode(fixture.Database, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.SetUnixFileMode(fixture.Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupExecute);
        Reject("path.directoryMode", () => ApplyJournal.Open(fixture.Path));
    }

    /// <summary>Database and sidecar symbolic links cannot redirect SQLite writes into foreign files.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("-journal")]
    [InlineData("-wal")]
    [InlineData("-shm")]
    public void SymlinkDatabaseOrSidecar_RejectsWithoutTouchingTarget(string suffix)
    {
        using var fixture = new JournalFixture();
        var target = System.IO.Path.Combine(fixture.Path, "sentinel");
        File.WriteAllText(target, "foreign sentinel");
        var link = fixture.Database + suffix;
        if (suffix.Length == 0)
        {
            File.Delete(link);
        }

        File.CreateSymbolicLink(link, target);
        Reject("path.symlink", () => ApplyJournal.Open(fixture.Path));
        Assert.Equal("foreign sentinel", File.ReadAllText(target));
    }

    /// <summary>Directory aliases and relative paths cannot hide the state path being opened.</summary>
    [Fact]
    public void SymlinkDirectoryAndRelativePath_Reject()
    {
        using var fixture = new JournalFixture();
        var link = fixture.Path + "-link";
        try
        {
            Directory.CreateSymbolicLink(link, fixture.Path);
            Reject("path.symlink", () => ApplyJournal.Open(link));
            Reject("path.absoluteRequired", () => ApplyJournal.Open("relative-state"));
        }
        finally { Directory.Delete(link); }
    }

    /// <summary>Enrollment is explicit and exclusive; initialization never overwrites existing history.</summary>
    [Fact]
    public void Initialize_ExistingDatabaseRejects()
    {
        using var fixture = new JournalFixture();
        Reject("journal.exists", () => ApplyJournal.Initialize(fixture.Path, new(Agent, Owner, 1), "other"));
        Assert.Equal(Prior, fixture.Store.ReadEnrollment().Artifact);
    }

    /// <summary>Artifact bytes, enrolled owner and revision must agree before reserving a resource.</summary>
    [Fact]
    public void Start_RejectsContentAndOwnershipMismatches()
    {
        using var fixture = new JournalFixture();
        Reject("artifact.mismatch", () => fixture.Store.Start(fixture.Plan(), "changed", Prior));
        var stale = new ApplyPlan(Guid.NewGuid(), new(Agent, Owner, 2), CandidateDigest.FromText(Candidate), CandidateDigest.FromText(Prior), TimeSpan.FromSeconds(30));
        Reject("ownership.stale", () => fixture.Store.Start(stale, Candidate, Prior));
        var foreign = new ApplyPlan(Guid.NewGuid(), new(Agent, Guid.NewGuid(), 1), CandidateDigest.FromText(Candidate), CandidateDigest.FromText(Prior), TimeSpan.FromSeconds(30));
        Reject("ownership.stale", () => fixture.Store.Start(foreign, Candidate, Prior));
        var changedRollback = new ApplyPlan(Guid.NewGuid(), new(Agent, Owner, 1), CandidateDigest.FromText(Candidate), CandidateDigest.FromText("other"), TimeSpan.FromSeconds(30));
        Reject("rollback.mismatch", () => fixture.Store.Start(changedRollback, Candidate, "other"));
        Assert.Null(fixture.Store.ReadActive());
    }

    /// <summary>Exact artifact bytes survive SQLite storage; excessively large content is refused before writes.</summary>
    [Fact]
    public void Artifacts_KeepUtf8AndRejectOversizedInput()
    {
        using var fixture = new JournalFixture();
        const string text = "quoted ' artifact\0é\r\n";
        var plan = fixture.Plan(candidate: text);
        var entry = fixture.Store.Start(plan, text, Prior);
        Assert.Equal(text, ApplyJournal.Open(fixture.Path, fixture.Clock).Read(plan.OperationId).Candidate);
        Reject("artifact.tooLarge", () => fixture.Store.Start(fixture.Plan(), new string('x', 1024 * 1024 + 1), Prior));
        Assert.Equal(entry.Candidate, fixture.Store.ReadActive()!.Candidate);
    }

    /// <summary>A retained operation identifier cannot be reused after rollback releases its reservation.</summary>
    [Fact]
    public void ReplayedOperationId_IsRejected()
    {
        using var fixture = new JournalFixture();
        var plan = fixture.Plan();
        fixture.Store.Start(plan, Candidate, Prior);
        fixture.Accept(plan, ApplyEvent.RollbackArmed);
        fixture.Accept(plan, ApplyEvent.ApplyFailed);
        fixture.Accept(plan, ApplyEvent.RollbackSucceeded);
        Reject("operation.reused", () => fixture.Store.Start(plan, Candidate, Prior));
    }

    /// <summary>Reboot or monotonic regression cannot restart a confirmation window; recovery blocks subsequent work.</summary>
    [Theory]
    [InlineData(true, "clock.bootChanged")]
    [InlineData(false, "clock.regressed")]
    public void ClockDiscontinuity_RequiresRecovery(bool reboot, string error)
    {
        using var fixture = new JournalFixture();
        var plan = fixture.Plan();
        fixture.Store.Start(plan, Candidate, Prior);
        fixture.Accept(plan, ApplyEvent.RollbackArmed);
        if (reboot)
        {
            fixture.Clock.Boot = Guid.NewGuid();
        }
        else
        {
            fixture.Clock.Seconds = 99;
        }

        var result = fixture.Store.Advance(plan.OperationId, ApplyEvent.CandidateApplied, plan, Watchdog);
        Assert.False(result.Accepted);
        Assert.Equal(error, result.ErrorCode);
        Assert.Equal(ApplyPhase.RecoveryRequired, fixture.Store.ReadActive()!.Session.Phase);
        fixture.Clock.Seconds = 101;
        fixture.Clock.Boot = ManualClock.InitialBoot;
        Reject("resource.busy", () => fixture.Store.Start(fixture.Plan(), Candidate, Prior));
    }

    /// <summary>Real concurrent writers cannot both reserve the sole resource.</summary>
    [Fact]
    public async Task ConcurrentStarts_OnlyOneWins()
    {
        using var fixture = new JournalFixture();
        using var gate = new Barrier(2);
        var tasks = Enumerable.Range(0, 2).Select(_ => Task.Run(() =>
        {
            var store = ApplyJournal.Open(fixture.Path, fixture.Clock);
            var plan = fixture.Plan();
            Assert.True(gate.SignalAndWait(TimeSpan.FromSeconds(10)), "Concurrent actor did not reach the transaction test gate.");
            try { store.Start(plan, Candidate, Prior); return "started"; }
            catch (JournalException error) { return error.Code; }
        })).ToArray();
        var outcomes = await Task.WhenAll(tasks);
        Assert.Equal(1, outcomes.Count(x => x == "started"));
        Assert.Equal(1, outcomes.Count(x => x == "resource.busy"));
    }

    /// <summary>Confirmation and timeout at the exact deadline serialize to rollback, never a revision advance.</summary>
    [Fact]
    public async Task ConcurrentConfirmationAndTimeout_DeadlineWins()
    {
        using var fixture = new JournalFixture();
        var plan = fixture.Plan();
        fixture.Store.Start(plan, Candidate, Prior);
        fixture.Accept(plan, ApplyEvent.RollbackArmed);
        fixture.Accept(plan, ApplyEvent.CandidateApplied);
        fixture.Clock.Seconds = 130;
        using var gate = new Barrier(2);
        var results = await Task.WhenAll(new[] { ApplyEvent.Confirm, ApplyEvent.CheckDeadline }.Select(kind => Task.Run(() =>
        {
            var store = ApplyJournal.Open(fixture.Path, fixture.Clock);
            Assert.True(gate.SignalAndWait(TimeSpan.FromSeconds(10)), "Concurrent actor did not reach the transaction test gate.");
            return store.Advance(plan.OperationId, kind, plan, Watchdog);
        })));
        Assert.False(results[0].Accepted);
        Assert.True(results[1].Accepted);
        Assert.Equal(ApplyPhase.RollbackRequired, fixture.Store.ReadActive()!.Session.Phase);
        Assert.Equal(1UL, fixture.Store.ReadEnrollment().Ownership.Revision);
    }

    private static void Reject(string code, Action action) => Assert.Equal(code, Assert.Throws<JournalException>(action).Code);

    private sealed class ManualClock : IJournalClock
    {
        internal static readonly Guid InitialBoot = Guid.Parse("00000000-0000-0000-0000-000000000004");
        internal Guid Boot { get; set; } = InitialBoot;
        internal int Seconds { get; set; } = 100;
        public JournalTime Read() => new(Boot, TimeSpan.FromSeconds(Seconds));
    }

    private sealed class JournalFixture : IDisposable
    {
        internal string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "nergal-journal-" + Guid.NewGuid().ToString("N"));
        internal string Database => System.IO.Path.Combine(Path, "journal.db");
        internal ManualClock Clock { get; } = new();
        internal ApplyJournal Store { get; }
        internal JournalFixture()
        {
            Directory.CreateDirectory(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Store = ApplyJournal.Initialize(Path, new(Agent, Owner, 1), Prior, Clock);
        }
        internal ApplyPlan Plan(string candidate = Candidate) => new(Guid.NewGuid(), new(Agent, Owner, 1), CandidateDigest.FromText(candidate), CandidateDigest.FromText(Prior), TimeSpan.FromSeconds(30));
        internal void Accept(ApplyPlan plan, ApplyEvent kind)
        {
            var result = Store.Advance(plan.OperationId, kind, plan, Watchdog);
            Assert.True(result.Accepted, result.ErrorCode);
        }
        internal void Damage(string sql)
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
