using System.Diagnostics;
using System.Runtime.Versioning;
using System.Runtime.InteropServices;
using System.Text.Json;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;
using Nergal.LocalState;
using Nergal.Nftables;

// Test executable only. No native operation or state write precedes the namespace guard.
if (!OperatingSystem.IsLinux() || args.Length != 6)
{
    return 2;
}

try
{
    FixtureGuard.Check(args[2], args[3]);
    return await WatchdogFixture.Run(args[0], args[1], Guid.Parse(args[4]), int.Parse(args[5], System.Globalization.CultureInfo.InvariantCulture));
}
catch (JournalException error) { Console.Error.WriteLine(error.Code); return 1; }
catch (Exception error) when (error is InvalidOperationException or IOException or FormatException or TimeoutException or ArgumentException)
{
    Console.Error.WriteLine(error.Message);
    return 1;
}

[SupportedOSPlatform("linux")]
internal static class FixtureGuard
{
    internal static void Check(string parentNet, string parentUser)
    {
        var currentNet = File.ResolveLinkTarget("/proc/self/ns/net", false)?.Name;
        var currentUser = File.ResolveLinkTarget("/proc/self/ns/user", false)?.Name;
        if (currentNet is null || currentUser is null || !parentNet.StartsWith("net:[", StringComparison.Ordinal) ||
            !parentUser.StartsWith("user:[", StringComparison.Ordinal) || currentNet == parentNet || currentUser == parentUser)
        {
            throw new InvalidOperationException("fixture.namespaceNotIsolated");
        }

        var map = File.ReadAllText("/proc/self/uid_map").Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (geteuid() != 0 || map.Length != 3 || map[0] != "0" || map[1] == "0" || map[2] != "1")
        {
            throw new InvalidOperationException("fixture.rootlessUserNamespaceRequired");
        }
    }
    [DllImport("libc")]
    private static extern uint geteuid();
}

[SupportedOSPlatform("linux")]
internal static class WatchdogFixture
{
    private static readonly Guid Agent = Guid.Parse("00000000-0000-0000-0000-000000000001");
    private static readonly Guid Owner = Guid.Parse("00000000-0000-0000-0000-000000000002");
    private static readonly Guid Watchdog = Guid.Parse("00000000-0000-0000-0000-000000000003");
    private static readonly LinuxBootClock Clock = new();
    private static string Artifact(FilterVerdict verdict) => NftFilterCompiler.Compile(new(1, verdict, [])).Candidate!;

    internal static async Task<int> Run(string mode, string directory, Guid operation, int timeoutMilliseconds)
    {
        if (mode == "seed")
        {
            // Fresh namespace ownership, not adoption: create fails if a table already exists.
            await NativeNft.Batch(Artifact(FilterVerdict.Accept), false);
            _ = ApplyJournal.Initialize(directory, new(Agent, Owner, 1), Artifact(FilterVerdict.Accept));
            Signal("SEEDED");
            return 0;
        }
        var journal = ApplyJournal.Open(directory);
        if (mode == "begin")
        {
            if (timeoutMilliseconds is < 500 or > 30000)
            {
                throw new InvalidOperationException("fixture.timeoutRange");
            }

            var plan = new ApplyPlan(operation, journal.ReadEnrollment().Ownership,
                CandidateDigest.FromText(Artifact(FilterVerdict.Drop)), CandidateDigest.FromText(Artifact(FilterVerdict.Accept)),
                TimeSpan.FromMilliseconds(timeoutMilliseconds));
            journal.Start(plan, Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept));
            Signal("PREPARED");
            return 0;
        }
        if (mode == "status")
        {
            var entry = journal.Read(operation);
            Console.WriteLine(JsonSerializer.Serialize(new { phase = entry.Session.Phase.ToString(), revision = journal.ReadEnrollment().Ownership.Revision, deadlineTicks = entry.Session.Deadline?.Ticks }));
            return 0;
        }
        if (mode is "watch" or "watch-pause-after-restore")
        {
            return await Watch(journal, directory, operation, mode == "watch-pause-after-restore");
        }

        if (mode is not ("apply" or "apply-pause-before" or "apply-pause-after" or "confirm"))
        {
            throw new InvalidOperationException("fixture.unknownMode");
        }

        using var lease = await ExecutionLease.Take(directory);
        var current = journal.Read(operation);
        VerifyBinding(current);
        var check = journal.Advance(operation, ApplyEvent.CheckDeadline, current.Session.Plan, current.Session.WatchdogId);
        Require(check.Accepted && (check.Entry.Session.Phase is ApplyPhase.RollbackArmed or ApplyPhase.AwaitingConfirmation), "fixture.notArmedOrExpired");
        if (mode == "confirm")
        {
            Require(await NativeNft.Policy() == "drop", "fixture.candidateMismatch");
            var confirmed = journal.Advance(operation, ApplyEvent.Confirm, current.Session.Plan, Watchdog);
            Require(confirmed.Accepted, confirmed.ErrorCode ?? "fixture.confirmationDenied");
            Signal("CONFIRMED");
            return 0;
        }
        Require(check.Entry.Session.Phase == ApplyPhase.RollbackArmed, "fixture.alreadyApplied");
        Require(await NativeNft.Policy() == "accept", "fixture.baselineMismatch");
        if (mode == "apply-pause-before")
        {
            await Pause("BEFORE_APPLY");
        }

        await Replace(FilterVerdict.Drop);
        if (mode == "apply-pause-after")
        {
            await Pause("APPLIED_BEFORE_ACK");
        }

        var applied = journal.Advance(operation, ApplyEvent.CandidateApplied, current.Session.Plan, Watchdog);
        Require(applied.Accepted, applied.ErrorCode ?? "fixture.applyAcknowledgmentDenied");
        Signal("APPLIED");
        return 0;
    }

    private static async Task<int> Watch(ApplyJournal journal, string directory, Guid operation, bool pauseAfterRestore)
    {
        using (var lease = await ExecutionLease.Take(directory))
        {
            var entry = journal.Read(operation);
            VerifyBinding(entry);
            if (entry.Session.Phase == ApplyPhase.Prepared)
            {
                var armed = journal.Advance(operation, ApplyEvent.RollbackArmed, entry.Session.Plan, Watchdog);
                Require(armed.Accepted, armed.ErrorCode ?? "fixture.armingDenied");
            }
            Signal("WATCHING");
        }
        while (true)
        {
            var entry = journal.Read(operation);
            if (entry.Session.IsTerminal) { Signal(entry.Session.Phase.ToString()); return 0; }
            var now = Clock.Read();
            var due = now.BootId != entry.Started.BootId || entry.Session.Phase == ApplyPhase.RollbackRequired ||
                now.SinceBoot - entry.Started.SinceBoot >= entry.Session.Deadline!.Value;
            if (!due) { await Task.Delay(50); continue; }
            using var lease = await ExecutionLease.Take(directory);
            // The journal samples time after its own transaction lock; stale reads cannot decide confirmation/timeout.
            var checkedState = journal.Advance(operation, ApplyEvent.CheckDeadline, entry.Session.Plan, Watchdog);
            entry = checkedState.Entry;
            if (entry.Session.IsTerminal) { Signal(entry.Session.Phase.ToString()); return 0; }
            Require(entry.Session.Phase == ApplyPhase.RollbackRequired, "fixture.rollbackNotRequired");
            try
            {
                VerifyBinding(entry);
                var policy = await NativeNft.Policy();
                Require(policy is "accept" or "drop", "fixture.unknownOwnedState");
                if (policy == "drop")
                {
                    await Replace(FilterVerdict.Accept);
                }

                Require(await NativeNft.Policy() == "accept", "fixture.restorationMismatch");
                if (pauseAfterRestore)
                {
                    await Pause("RESTORED_BEFORE_ACK");
                }

                var restored = journal.Advance(operation, ApplyEvent.RollbackSucceeded, entry.Session.Plan, Watchdog);
                Require(restored.Accepted, restored.ErrorCode ?? "fixture.rollbackAcknowledgmentDenied");
                Signal("RolledBack");
                return 0;
            }
            catch (Exception error) when (error is InvalidOperationException or IOException or TimeoutException)
            {
                _ = journal.Advance(operation, ApplyEvent.RollbackFailed, entry.Session.Plan, Watchdog);
                Signal("RecoveryRequired");
                return 1;
            }
        }
    }

    private static void VerifyBinding(JournalEntry entry)
    {
        Require(entry.Candidate == Artifact(FilterVerdict.Drop) && entry.Rollback == Artifact(FilterVerdict.Accept) &&
            entry.Session.Plan.Ownership.AgentId == Agent && entry.Session.Plan.Ownership.OwnerId == Owner,
            "fixture.bindingMismatch");
    }
    private static async Task Replace(FilterVerdict verdict)
    {
        var batch = "delete table inet nergal_filter\n" + Artifact(verdict);
        await NativeNft.Batch(batch, true);
        await NativeNft.Batch(batch, false);
    }
    private static void Require(bool condition, string code)
    {
        if (!condition)
        {
            throw new InvalidOperationException(code);
        }
    }
    private static void Signal(string value) { Console.WriteLine(value); Console.Out.Flush(); }
    private static async Task Pause(string value) { Signal(value); await Task.Delay(Timeout.InfiniteTimeSpan); }
}

[SupportedOSPlatform("linux")]
internal sealed class ExecutionLease : IDisposable
{
    private readonly FileStream stream;
    private ExecutionLease(FileStream stream) => this.stream = stream;
    internal static async Task<ExecutionLease> Take(string directory)
    {
        var path = Path.Combine(directory, "execution.lock");
        if (new FileInfo(path).LinkTarget is not null)
        {
            throw new InvalidOperationException("fixture.lockSymlink");
        }

        if (File.Exists(path) && File.GetUnixFileMode(path) != (UnixFileMode.UserRead | UnixFileMode.UserWrite))
        {
            throw new InvalidOperationException("fixture.lockMode");
        }

        var stream = new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.OpenOrCreate,
            Access = FileAccess.ReadWrite,
            Share = FileShare.ReadWrite,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });
        var started = Stopwatch.GetTimestamp();
        while (true)
        {
            try { stream.Lock(0, 1); return new(stream); }
            catch (IOException)
            {
                if (Stopwatch.GetElapsedTime(started) > TimeSpan.FromSeconds(10)) { stream.Dispose(); throw new TimeoutException("fixture.executionLockTimeout"); }
                await Task.Delay(10);
            }
        }
    }
    public void Dispose() => stream.Dispose();
}

internal static class NativeNft
{
    internal static async Task Batch(string text, bool check) => _ = await Run(check ? ["--check", "--file", "-"] : ["--file", "-"], text);

    internal static async Task<string> Policy()
    {
        try { return ParsePolicy(await Run(["--json", "list", "table", "inet", "nergal_filter"], null)); }
        catch (Exception error) when (error is JsonException or KeyNotFoundException)
        {
            throw new InvalidOperationException("fixture.tableShape");
        }
    }
    private static string ParsePolicy(string text)
    {
        using var json = JsonDocument.Parse(text);
        var items = json.RootElement.GetProperty("nftables").EnumerateArray().ToArray();
        if (items.Length != 3 || !items[0].TryGetProperty("metainfo", out _) ||
            !items[1].TryGetProperty("table", out var table) || !items[2].TryGetProperty("chain", out var chain))
        {
            throw new InvalidOperationException("fixture.tableShape");
        }

        ExactProperties(table, ["family", "name", "handle"]);
        ExactProperties(chain, ["family", "table", "name", "handle", "type", "hook", "prio", "policy"]);
        if (table.GetProperty("family").GetString() != "inet" || table.GetProperty("name").GetString() != "nergal_filter" ||
            chain.GetProperty("family").GetString() != "inet" || chain.GetProperty("table").GetString() != "nergal_filter" ||
            chain.GetProperty("name").GetString() != "input" || chain.GetProperty("type").GetString() != "filter" ||
            chain.GetProperty("hook").GetString() != "input" || chain.GetProperty("prio").GetInt32() != 0)
        {
            throw new InvalidOperationException("fixture.tableShape");
        }

        return chain.GetProperty("policy").GetString() ?? throw new InvalidOperationException("fixture.tableShape");
    }
    private static void ExactProperties(JsonElement value, string[] allowed)
    {
        if (!value.EnumerateObject().Select(property => property.Name).Order().SequenceEqual(allowed.Order()))
        {
            throw new InvalidOperationException("fixture.tableShape");
        }
    }
    private static async Task<string> Run(string[] arguments, string? input)
    {
        var start = new ProcessStartInfo("nft") { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start) ?? throw new InvalidOperationException("fixture.nftStartFailed");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (input is not null)
        {
            await process.StandardInput.WriteAsync(input);
        }

        process.StandardInput.Close();
        try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); }
        catch (TimeoutException) { process.Kill(true); await process.WaitForExitAsync(); throw; }
        await error;
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException("fixture.nftFailed");
        }

        return await output;
    }
}
