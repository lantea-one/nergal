using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using Nergal.Agent;
using Nergal.Core.Agent;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;
using Nergal.Linux;
using Nergal.Nftables;

namespace Nergal.LocalState.Tests;

/// <summary>Verifies per-resource lock hardening, CLI argument bounds, and read-only agent status classification.</summary>
[SupportedOSPlatform("linux")]
public sealed class AgentStatusServiceTests
{
    private static readonly Guid Agent = Guid.Parse("00000000-0000-0000-0000-000000000001");
    private static readonly Guid Owner = Guid.Parse("00000000-0000-0000-0000-000000000002");
    private static readonly Guid Resource = Guid.Parse("00000000-0000-0000-0000-000000000003");
    private static readonly ResourceOwnership Ownership = new(Agent, Owner, 1);

    /// <summary>Concurrent resource lock holders serialize cleanly and non-positive or excessive timeouts fail closed.</summary>
    [Fact]
    public async Task ResourceLock_SerializesHoldersAndValidatesTimeout()
    {
        using var fixture = new Fixture();
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            ResourceExecutionLock.AcquireAsync(fixture.Path, TimeSpan.Zero, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            ResourceExecutionLock.AcquireAsync(fixture.Path, TimeSpan.FromMinutes(6), TestContext.Current.CancellationToken));

        using (var held = await ResourceExecutionLock.AcquireAsync(fixture.Path, TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken))
        {
            var error = await Assert.ThrowsAsync<JournalException>(() =>
                ResourceExecutionLock.AcquireAsync(fixture.Path, TimeSpan.FromMilliseconds(40), TestContext.Current.CancellationToken));
            Assert.Equal("resource.lockTimeout", error.Code);
        }

        using var reacquired = await ResourceExecutionLock.AcquireAsync(fixture.Path, TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(fixture.Path, "resource.lock")));
    }

    /// <summary>Symlinks, non-regular files, permissive modes, and hard links at resource.lock are rejected without altering targets.</summary>
    [Fact]
    public async Task ResourceLock_RejectsUnsafeLockInodes()
    {
        using var fixture = new Fixture();
        var lockPath = Path.Combine(fixture.Path, "resource.lock");
        var target = Path.Combine(fixture.Path, "sentinel.txt");
        File.WriteAllText(target, "keep");
        File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        File.CreateSymbolicLink(lockPath, target);
        await RejectLock("path.symlink", fixture.Path);
        File.Delete(lockPath);

        Directory.CreateDirectory(lockPath);
        await RejectLock("path.type", fixture.Path);
        Directory.Delete(lockPath);

        Assert.Equal(0, link(target, lockPath));
        await RejectLock("path.hardLink", fixture.Path);
        File.Delete(lockPath);

        File.WriteAllText(lockPath, "");
        File.SetUnixFileMode(lockPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        await RejectLock("path.databaseMode", fixture.Path);
        Assert.Equal("keep", File.ReadAllText(target));
    }

    /// <summary>CLI parsing rejects unknown commands, relative paths, and malformed numeric identities.</summary>
    public static TheoryData<string[]> InvalidCliArguments => new()
    {
        Array.Empty<string>(),
        new string[] { "unknown" },
        new string[] { "enroll", "relative/path" },
        new string[] { "reconcile", "relative/path" },
        new string[] { "status-serve", "/tmp/journal", "relative/sock", "1000" },
        new string[] { "status-serve", "relative/journal", "/tmp/status.sock", "1000" },
        new string[] { "status-serve", "/tmp/journal", "/tmp/status.sock", "-1" },
        new string[] { "status-serve", "/tmp/journal", "/tmp/status.sock", "1000", "not-a-gid" },
        new string[] { "status-serve", "/tmp/journal", "/tmp/status.sock", "1000", "2000", "extra" },
        new string[] { "prepare", "/tmp/journal", "not-a-guid", "10", "drop" },
        new string[] { "prepare", "/tmp/journal", "00000000-0000-0000-0000-000000000000", "10", "drop" },
        new string[] { "prepare", "/tmp/journal", "00000000-0000-0000-0000-000000000001", "0", "drop" },
        new string[] { "prepare", "/tmp/journal", "00000000-0000-0000-0000-000000000001", "3601", "drop" },
        new string[] { "prepare", "/tmp/journal", "00000000-0000-0000-0000-000000000001", "10", "reject" },
        new string[] { "prepare", "/tmp/journal", "00000000-0000-0000-0000-000000000001", "10", "drop", "icmp:accept" },
        new string[] { "watch", "/tmp/journal", "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000000" },
        new string[] { "apply", "relative/journal", "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002" },
        new string[] { "confirm", "/tmp/journal", "00000000-0000-0000-0000-000000000001" },
    };


    /// <summary>CLI parsing rejects unknown commands, relative paths, and malformed numeric identities.</summary>
    [Theory]
    [MemberData(nameof(InvalidCliArguments))]
    public async Task Cli_RejectsInvalidArgumentsWithUsageExitCode(string[] args)
    {
        Assert.False(AgentCommands.TryParseCommand(args, out _));
        using var output = new StringWriter();
        using var error = new StringWriter();
        var exitCode = await AgentCommands.RunAsync(args, output, error);
        Assert.Equal(2, exitCode);
        Assert.Contains("Usage:", error.ToString(), StringComparison.Ordinal);
    }

    /// <summary>Valid enroll and status-serve arguments preserve exact parsed identities and paths.</summary>
    [Fact]
    public void Cli_AcceptsExpectedEnrollAndStatusServeShapes()
    {
        Assert.True(AgentCommands.TryParseCommand(["enroll", "/var/lib/nergal/agent"], out var enroll));
        var parsedEnroll = Assert.IsType<AgentCommands.EnrollCommand>(enroll);
        Assert.Equal("/var/lib/nergal/agent", parsedEnroll.Directory);

        Assert.True(AgentCommands.TryParseCommand(["status-serve", "/var/lib/nergal/agent", "/run/nergal/status.sock", "1001", "2002"], out var serve));
        var parsedServe = Assert.IsType<AgentCommands.StatusServeCommand>(serve);
        Assert.Equal("/var/lib/nergal/agent", parsedServe.Directory);
        Assert.Equal("/run/nergal/status.sock", parsedServe.SocketPath);
        Assert.Equal(1001u, parsedServe.AllowedPeerUid);
        Assert.Equal(2002u, parsedServe.SocketGroupId);

        Assert.True(AgentCommands.TryParseCommand(
            ["prepare", "/var/lib/nergal/agent", "00000000-0000-0000-0000-000000000010", "30", "drop", "ipv4:drop", "ipv6:accept"],
            out var prepare));
        var parsedPrepare = Assert.IsType<AgentCommands.PrepareCommand>(prepare);
        Assert.Equal(30, parsedPrepare.TimeoutSeconds);
        Assert.Equal(FilterVerdict.Drop, parsedPrepare.DefaultVerdict);
        Assert.Equal(2, parsedPrepare.Rules.Count);

        Assert.True(AgentCommands.TryParseCommand(["reconcile", "/var/lib/nergal/agent"], out var reconcile));
        Assert.IsType<AgentCommands.ReconcileCommand>(reconcile);
    }

    /// <summary>Status evaluation reports unbound, matched, drift, and metadata-free unavailable without altering journal bytes.</summary>
    [Fact]
    public async Task StatusProvider_ClassifiesStateAndMasksErrorsWithoutMutatingJournal()
    {
        using var fixture = new Fixture();
        var initialBytes = File.ReadAllBytes(fixture.Database);
        Assert.Equal(
            new(AgentStatusOutcome.Unbound, 1),
            await AgentStatusProvider.EvaluateAsync(fixture.Path, _ => Task.FromResult<NftTableObservation?>(null), () => 42UL, CancellationToken.None));
        Assert.Equal(initialBytes, File.ReadAllBytes(fixture.Database));

        var actual = Observe();
        var expected = new NftTableReceipt(fixture.BootId, 42UL, actual.Identity, actual.TableHandle, actual.StateDigest);
        fixture.Store.BindExpectedResource(Ownership, expected, actual, 42UL);
        var boundBytes = File.ReadAllBytes(fixture.Database);

        Assert.Equal(
            new(AgentStatusOutcome.Matched, 1),
            await AgentStatusProvider.EvaluateAsync(fixture.Path, _ => Task.FromResult<NftTableObservation?>(actual), () => 42UL, CancellationToken.None));
        Assert.Equal(
            new(AgentStatusOutcome.Drift, 1),
            await AgentStatusProvider.EvaluateAsync(fixture.Path, _ => Task.FromResult<NftTableObservation?>(Observe(FilterVerdict.Drop)), () => 42UL, CancellationToken.None));
        Assert.Equal(
            new(AgentStatusOutcome.Unavailable),
            await AgentStatusProvider.EvaluateAsync(fixture.Path, _ => Task.FromResult<NftTableObservation?>(null), () => 42UL, CancellationToken.None));
        Assert.Equal(
            new(AgentStatusOutcome.Unavailable),
            await AgentStatusProvider.EvaluateAsync(fixture.Path, _ => Task.FromResult<NftTableObservation?>(actual), () => 0UL, CancellationToken.None));
        Assert.Equal(boundBytes, File.ReadAllBytes(fixture.Database));

        File.WriteAllText(fixture.Database, "corrupt database");
        Assert.Equal(
            new(AgentStatusOutcome.Unavailable),
            await AgentStatusProvider.EvaluateAsync(fixture.Path, _ => Task.FromResult<NftTableObservation?>(actual), () => 42UL, CancellationToken.None));
        Assert.Equal("corrupt database", File.ReadAllText(fixture.Database));
    }

    private static async Task RejectLock(string expectedCode, string directory)
    {
        var error = await Assert.ThrowsAsync<JournalException>(() =>
            ResourceExecutionLock.AcquireAsync(directory, TimeSpan.FromMilliseconds(50)));
        Assert.Equal(expectedCode, error.Code);
    }

    private static NftTableObservation Observe(FilterVerdict verdict = FilterVerdict.Accept)
    {
        var text = JsonSerializer.Serialize(new
        {
            nftables = new object[]
            {
                new { metainfo = new { version = "fixture", release_name = "fixture", json_schema_version = 1 } },
                new { table = new { family = "inet", name = "nergal_filter", handle = 7UL, comment = new NftTableIdentity(Owner, Resource).Comment } },
                new { chain = new { family = "inet", table = "nergal_filter", name = "input", handle = 9UL, type = "filter", hook = "input", prio = 0, policy = verdict == FilterVerdict.Accept ? "accept" : "drop" } },
            }
        });
        return NftTableObservation.Parse(text).Observation!;
    }

    private sealed class Fixture : IDisposable
    {
        internal string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "nergal-agent-status-" + Guid.NewGuid().ToString("N"));
        internal string Database => System.IO.Path.Combine(Path, "journal.db");
        internal Guid BootId { get; }
        internal ApplyJournal Store { get; }

        internal Fixture()
        {
            Directory.CreateDirectory(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var clock = new LinuxBootClock();
            BootId = clock.Read().BootId;
            var baseline = NftFilterCompiler.Compile(new(1, FilterVerdict.Accept, []), new(Owner, Resource)).Candidate!;
            Store = ApplyJournal.InitializeResourceIntent(Path, Ownership, baseline, clock);
        }

        public void Dispose() => Directory.Delete(Path, true);
    }

    [DllImport("libc")]
    private static extern int link(string existing, string newPath);
}
