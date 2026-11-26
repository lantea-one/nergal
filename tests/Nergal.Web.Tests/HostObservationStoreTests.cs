using System.Runtime.Versioning;
using Microsoft.Data.Sqlite;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;

namespace Nergal.Web.Tests;

/// <summary>Verifies that observations follow registrations and preserve status provenance.</summary>
[SupportedOSPlatform("linux")]
public sealed class HostObservationStoreTests
{
    private static readonly string Actor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("26b60f38-3184-4888-a2fc-61c501a16e50"));
    private static readonly DateTimeOffset FirstTime = new(2026, 11, 25, 13, 1, 30, TimeSpan.Zero);

    /// <summary>Newer authenticated replies win without turning drift or old evidence into a confirmed revision.</summary>
    [Fact]
    public async Task RetainsNewestObservationButKeepsSettledRevisionSeparate()
    {
        using var fixture = new Fixture();
        var host = fixture.RegisterHost();
        Assert.Null(fixture.Store.ReadHostObservation(host.Id));
        var first = new HostObservation(host.Id, HostObservationState.Matched, 7, FirstTime);
        Assert.True(fixture.Store.RecordHostObservation(first, updateLastKnownRevision: true));
        var newer = new HostObservation(host.Id, HostObservationState.Drift, ulong.MaxValue, FirstTime.AddSeconds(2));
        var older = new HostObservation(host.Id, HostObservationState.Matched, 6, FirstTime.AddSeconds(1));
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var race = new[] { newer, older }.Select(observation => Task.Run(async () =>
        {
            await start.Task;
            fixture.Store.RecordHostObservation(observation);
        }, TestContext.Current.CancellationToken)).ToArray();
        start.SetResult();
        await Task.WhenAll(race);
        Assert.False(fixture.Store.RecordHostObservation(older, updateLastKnownRevision: true));
        Assert.False(fixture.Store.RecordHostObservation(newer with { ReportedRevision = 8 }));
        Assert.Throws<ArgumentException>(() => fixture.Store.RecordHostObservation(newer, updateLastKnownRevision: true));
        Assert.Throws<ArgumentException>(() => fixture.Store.RecordHostObservation(
            newer with { ObservedAtUtc = FirstTime.ToOffset(TimeSpan.FromHours(1)) }));

        var reopened = ControllerStateStore.Open(new(fixture.Directory));
        Assert.Equal(newer, reopened.ReadHostObservation(host.Id));
        Assert.Equal(7UL, reopened.GetHost(host.Id)!.LastKnownRevision);
        Assert.Single(reopened.ListAuditEntries());
        Assert.Empty(reopened.ListPolicyRevisions());
    }

    /// <summary>A reply to an earlier request cannot overwrite a settled revision recorded while it was in flight.</summary>
    [Fact]
    public void InFlightObservationDoesNotOverwriteAnInterveningRevision()
    {
        using var fixture = new Fixture();
        var host = fixture.RegisterHost();
        fixture.Store.UpdateHostLastRevision(host.Id, 8);
        var pendingReply = new HostObservation(host.Id, HostObservationState.Matched, 7, FirstTime);
        Assert.True(fixture.Store.RecordHostObservation(pendingReply, updateLastKnownRevision: true, host.LastKnownRevision));
        Assert.Equal(pendingReply, fixture.Store.ReadHostObservation(host.Id));
        Assert.Equal(8UL, fixture.Store.GetHost(host.Id)!.LastKnownRevision);
    }

    /// <summary>A deleted host's observation cannot survive or be recreated by a delayed reply.</summary>
    [Fact]
    public void RegistrationRemovalCascadesAndRejectsLaterStatus()
    {
        using var fixture = new Fixture();
        var host = fixture.RegisterHost();
        var status = new HostObservation(host.Id, HostObservationState.Missing, null, FirstTime);
        Assert.True(fixture.Store.RecordHostObservation(status));
        Assert.Equal(status, fixture.Store.ReadHostObservation(host.Id));
        Assert.True(fixture.Store.DeleteHost(host.Id, Actor, NergalRoles.Administrator));
        Assert.Null(fixture.Store.ReadHostObservation(host.Id));
        Assert.False(fixture.Store.RecordHostObservation(status with { ObservedAtUtc = FirstTime.AddMinutes(1) }));
        Assert.Equal(0L, fixture.Sql("SELECT count(*) FROM host_observations"));
        Assert.Equal(new[] { "host.delete", "host.register" }, fixture.Store.ListAuditEntries().Select(entry => entry.Action));
    }

    /// <summary>Corrupt payloads and a missing observation table fail closed.</summary>
    [Fact]
    public void CorruptOrMissingObservationDataIsRejected()
    {
        using var fixture = new Fixture();
        var host = fixture.RegisterHost();
        Assert.True(fixture.Store.RecordHostObservation(new HostObservation(host.Id, HostObservationState.Online, null, FirstTime)));
        fixture.Sql("UPDATE host_observations SET observed_at_utc = '2026-11-25T14:01:30.0000000+01:00'");
        Assert.Equal("observation.corrupt",
            Assert.Throws<ControllerStateException>(() => fixture.Store.ReadHostObservation(host.Id)).Code);
        fixture.Sql("DROP TABLE host_observations");
        Assert.Equal("controller.corrupt", Assert.Throws<ControllerStateException>(() => ControllerStateStore.Open(new(fixture.Directory))).Code);
    }

    private sealed class Fixture : IDisposable
    {
        internal string Directory { get; } = Path.Combine(Path.GetTempPath(), "ng-host-observation-" + Guid.NewGuid().ToString("N"));
        internal ControllerStateStore Store { get; }

        internal Fixture()
        {
            System.IO.Directory.CreateDirectory(Directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Store = ControllerStateStore.Initialize(new(Directory));
        }

        internal ManagedHostRecord RegisterHost()
        {
            var host = new ManagedHostRecord(Guid.NewGuid(), "fixture-observed-host", AgentTransportKind.Unix,
                "/tmp/fixture-observed-agent.sock", expectedServerUserId: 1234);
            Store.RegisterHost(host, Actor, NergalRoles.Administrator);
            return host;
        }

        internal object? Sql(string sql)
        {
            using var connection = new SqliteConnection($"Data Source={Path.Combine(Directory, "controller.db")};Pooling=False");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            return command.ExecuteScalar();
        }

        public void Dispose() => System.IO.Directory.Delete(Directory, true);
    }
}
