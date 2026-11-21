using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Data.Sqlite;
using Nergal.Core.Agent;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;
using Nergal.LocalState;
using Nergal.LocalTransport;
using Nergal.Nftables;

namespace Nergal.Agent;

internal static class AgentCommands
{
    private const string Usage = """
        Usage:
          nergal-agent enroll ABSOLUTE_PRIVATE_JOURNAL_DIRECTORY
          nergal-agent status-serve ABSOLUTE_PRIVATE_JOURNAL_DIRECTORY ABSOLUTE_SOCKET_PATH ALLOWED_PEER_UID [SOCKET_GROUP_ID]
          nergal-agent prepare ABSOLUTE_PRIVATE_JOURNAL_DIRECTORY OPERATION_UUID TIMEOUT_SECONDS <accept|drop> [ipv4|ipv6:accept|drop ...]
          nergal-agent watch ABSOLUTE_PRIVATE_JOURNAL_DIRECTORY OPERATION_UUID WATCHDOG_UUID
          nergal-agent apply ABSOLUTE_PRIVATE_JOURNAL_DIRECTORY OPERATION_UUID WATCHDOG_UUID
          nergal-agent confirm ABSOLUTE_PRIVATE_JOURNAL_DIRECTORY OPERATION_UUID WATCHDOG_UUID
          nergal-agent reconcile ABSOLUTE_PRIVATE_JOURNAL_DIRECTORY
        """;

    internal static async Task<int> RunAsync(string[] args, TextWriter? output = null, TextWriter? error = null)
    {
        output ??= Console.Out;
        error ??= Console.Error;
        if (!OperatingSystem.IsLinux())
        {
            error.WriteLine("platform.unsupported");
            return 1;
        }

        if (!TryParseCommand(args, out var command))
        {
            error.WriteLine(Usage);
            return 2;
        }

        return command switch
        {
            EnrollCommand enroll => await EnrollAsync(enroll.Directory, output, error),
            StatusServeCommand serve => await ServeStatusAsync(serve, output, error),
            PrepareCommand prepare => await PrepareAsync(prepare, output, error),
            WatchCommand watch => await WatchAsync(watch, output, error),
            ApplyCommand apply => await ApplyAsync(apply, output, error),
            ConfirmCommand confirm => await ConfirmAsync(confirm, output, error),
            ReconcileCommand reconcile => await ReconcileAsync(reconcile.Directory, output, error),
            _ => 2,
        };
    }

    internal static bool TryParseCommand(string[] args, [NotNullWhen(true)] out AgentCommand? command)
    {
        command = null;
        if (args is ["enroll", var directory] && IsAbsolutePath(directory))
        {
            command = new EnrollCommand(directory);
            return true;
        }

        if (args is ["reconcile", var reconcileDir] && IsAbsolutePath(reconcileDir))
        {
            command = new ReconcileCommand(reconcileDir);
            return true;
        }

        if (args.Length is 4 or 5 && args[0] == "status-serve" &&
            IsAbsolutePath(args[1]) && IsAbsolutePath(args[2]) &&
            uint.TryParse(args[3], NumberStyles.None, CultureInfo.InvariantCulture, out var peerUid))
        {
            uint? socketGroup = null;
            if (args.Length == 5)
            {
                if (!uint.TryParse(args[4], NumberStyles.None, CultureInfo.InvariantCulture, out var gid))
                {
                    return false;
                }

                socketGroup = gid;
            }

            command = new StatusServeCommand(args[1], args[2], peerUid, socketGroup);
            return true;
        }

        if (args.Length >= 5 && args[0] == "prepare" && IsAbsolutePath(args[1]) &&
            TryParseNonEmptyGuid(args[2], out var prepareOp) &&
            int.TryParse(args[3], NumberStyles.None, CultureInfo.InvariantCulture, out var timeoutSeconds) &&
            timeoutSeconds is >= 1 and <= 3600 &&
            TryParseVerdict(args[4], out var defaultVerdict))
        {
            var rules = new List<FilterRule>();
            for (var index = 5; index < args.Length; index++)
            {
                if (!TryParseFamilyRule(args[index], out var rule))
                {
                    return false;
                }

                rules.Add(rule);
            }

            command = new PrepareCommand(args[1], prepareOp, timeoutSeconds, defaultVerdict, rules);
            return true;
        }

        if (args.Length == 4 && args[0] is "watch" or "apply" or "confirm" &&
            IsAbsolutePath(args[1]) &&
            TryParseNonEmptyGuid(args[2], out var opId) &&
            TryParseNonEmptyGuid(args[3], out var watchdogId))
        {
            command = args[0] switch
            {
                "watch" => new WatchCommand(args[1], opId, watchdogId),
                "apply" => new ApplyCommand(args[1], opId, watchdogId),
                _ => new ConfirmCommand(args[1], opId, watchdogId),
            };
            return true;
        }

        return false;
    }

    private static bool IsAbsolutePath(string path) => !string.IsNullOrWhiteSpace(path) && Path.IsPathFullyQualified(path);

    private static bool TryParseNonEmptyGuid(string value, out Guid parsed) =>
        Guid.TryParse(value, out parsed) && parsed != Guid.Empty;

    private static bool TryParseVerdict(string value, out FilterVerdict verdict)
    {
        if (value == "accept") { verdict = FilterVerdict.Accept; return true; }
        if (value == "drop") { verdict = FilterVerdict.Drop; return true; }
        verdict = default;
        return false;
    }

    private static bool TryParseFamilyRule(string value, [NotNullWhen(true)] out FilterRule? rule)
    {
        rule = value switch
        {
            "ipv4:accept" => new FilterRule(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Accept),
            "ipv4:drop" => new FilterRule(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Drop),
            "ipv6:accept" => new FilterRule(IpFamily.IPv6, FilterProtocol.Any, FilterVerdict.Accept),
            "ipv6:drop" => new FilterRule(IpFamily.IPv6, FilterProtocol.Any, FilterVerdict.Drop),
            _ => null,
        };
        return rule is not null;
    }

    [SupportedOSPlatform("linux")]
    private static async Task<int> EnrollAsync(string directory, TextWriter output, TextWriter error)
    {
        try
        {
            using var executionLock = await ResourceExecutionLock.AcquireAsync(directory, TimeSpan.FromSeconds(10));
            var ns = AgentStatusProvider.ReadNetworkNamespace();
            var clock = new LinuxBootClock();
            var boot = clock.Read().BootId;
            var ownership = new ResourceOwnership(Guid.NewGuid(), Guid.NewGuid(), 1);
            var identity = new NftTableIdentity(ownership.OwnerId, Guid.NewGuid());
            var baseline = NftFilterCompiler.Compile(new(1, FilterVerdict.Accept, []), identity).Candidate!;
            var journal = ApplyJournal.InitializeResourceIntent(directory, ownership, baseline, clock);
            Nergal.Linux.LinuxDirectoryDurability.Synchronize(directory);

            await NativeNft.Run(["--check", "--file", "-"], baseline);
            var echo = await NativeNft.Run(["--echo", "--handle", "--json", "--file", "-"], baseline);
            var created = NftTableObservation.ParseEnrollmentEcho(echo).Observation;
            if (created is null || created.Identity != identity)
            {
                throw new IOException("Creation evidence unavailable.");
            }

            var expected = new NftTableReceipt(boot, ns, identity, created.TableHandle, created.StateDigest);
            var actual = await ObserveLiveAsync();
            journal.BindExpectedResource(ownership, expected, actual, ns);
            output.WriteLine("Enrolled inet nergal_filter with an empty accept input chain.");
            return 0;
        }
        catch (JournalException err) { error.WriteLine(err.Code); }
        catch (Exception err) when (err is IOException or UnauthorizedAccessException or Win32Exception or
            OperationCanceledException or DecoderFallbackException or SqliteException or PlatformNotSupportedException)
        {
            error.WriteLine("Enrollment incomplete. Inspect local journal and kernel state before recovery.");
        }

        return 1;
    }

    [SupportedOSPlatform("linux")]
    private static async Task<int> ServeStatusAsync(StatusServeCommand command, TextWriter output, TextWriter error)
    {
        try
        {
            _ = ApplyJournal.Open(command.Directory);
            _ = AgentStatusProvider.ReadNetworkNamespace();
            using var server = UnixStatusServer.Bind(new UnixStatusOptions(
                command.SocketPath, [command.AllowedPeerUid], command.SocketGroupId, TimeSpan.FromSeconds(2)));
            using var stopping = new CancellationTokenSource();
            using var sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, context =>
            {
                context.Cancel = true;
                stopping.Cancel();
            });
            using var sigint = PosixSignalRegistration.Create(PosixSignal.SIGINT, context =>
            {
                context.Cancel = true;
                stopping.Cancel();
            });
            output.WriteLine("Listening for authorized status queries.");
            output.Flush();
            await server.ServeAsync(
                token => AgentStatusProvider.EvaluateAsync(command.Directory, NativeNft.TryObserveAsync, AgentStatusProvider.ReadNetworkNamespace, token),
                stopping.Token);
            return 0;
        }
        catch (JournalException err) { error.WriteLine(err.Code); }
        catch (LocalTransportException err) { error.WriteLine(err.Code); }
        catch (Exception err) when (err is IOException or UnauthorizedAccessException or Win32Exception or
            SqliteException or PlatformNotSupportedException or ArgumentException)
        {
            error.WriteLine("Status listener failed.");
        }

        return 1;
    }

    [SupportedOSPlatform("linux")]
    private static async Task<int> PrepareAsync(PrepareCommand command, TextWriter output, TextWriter error)
    {
        try
        {
            using var executionLock = await ResourceExecutionLock.AcquireAsync(command.Directory, TimeSpan.FromSeconds(10));
            var journal = ApplyJournal.Open(command.Directory);
            var enrollment = journal.ReadEnrollment();
            var expected = journal.ReadExpectedResource();
            if (expected is null) { error.WriteLine("resource.unbound"); return 1; }
            var ns = AgentStatusProvider.ReadNetworkNamespace();
            var actual = await ObserveLiveAsync();
            var compiled = NftFilterCompiler.Compile(new(1, command.DefaultVerdict, command.Rules), expected.Identity);
            if (!compiled.IsSuccess || compiled.Candidate is null)
            {
                error.WriteLine("candidate.invalid");
                return 1;
            }

            if (compiled.Candidate == enrollment.Artifact)
            {
                error.WriteLine("candidate.unchanged");
                return 1;
            }

            await NativeNft.Run(["--check", "--file", "-"], "delete table inet " + NftFilterCompiler.TableName + "\n" + compiled.Candidate);
            var plan = new ApplyPlan(command.OperationId, enrollment.Ownership, compiled.Digest!,
                CandidateDigest.FromText(enrollment.Artifact), TimeSpan.FromSeconds(command.TimeoutSeconds));
            _ = journal.StartBound(plan, compiled.Candidate, enrollment.Artifact, actual, ns);
            output.WriteLine("PREPARED");
            return 0;
        }
        catch (JournalException err) { error.WriteLine(err.Code); }
        catch (Exception err) when (err is IOException or UnauthorizedAccessException or Win32Exception or
            OperationCanceledException or DecoderFallbackException or SqliteException or PlatformNotSupportedException or ArgumentException)
        {
            error.WriteLine("Prepare failed.");
        }

        return 1;
    }

    [SupportedOSPlatform("linux")]
    private static async Task<int> WatchAsync(WatchCommand command, TextWriter output, TextWriter error)
    {
        var clock = new LinuxBootClock();
        try
        {
            ApplyJournal journal;
            using (var armLock = await ResourceExecutionLock.AcquireAsync(command.Directory, TimeSpan.FromSeconds(10)))
            {
                journal = ApplyJournal.Open(command.Directory, clock);
                var initial = journal.Read(command.OperationId);
                if (initial.Rollback != journal.ReadEnrollment().Artifact)
                {
                    error.WriteLine("rollback.mismatch");
                    return 1;
                }

                if (initial.Session.Phase == ApplyPhase.Prepared)
                {
                    var armed = journal.Advance(command.OperationId, ApplyEvent.RollbackArmed, initial.Session.Plan, command.WatchdogId);
                    if (!armed.Accepted)
                    {
                        error.WriteLine(armed.ErrorCode ?? "arming.denied");
                        return 1;
                    }
                }
                else if (initial.Session.WatchdogId != Guid.Empty && initial.Session.WatchdogId != command.WatchdogId)
                {
                    error.WriteLine("watchdog.mismatch");
                    return 1;
                }
            }

            output.WriteLine("WATCHING");
            output.Flush();

            while (true)
            {
                var current = journal.Read(command.OperationId);
                if (current.Session.IsTerminal)
                {
                    output.WriteLine(current.Session.Phase.ToString());
                    output.Flush();
                    return current.Session.Phase == ApplyPhase.RecoveryRequired ? 1 : 0;
                }

                var now = clock.Read();
                var due = now.BootId != current.Started.BootId ||
                    current.Session.Phase == ApplyPhase.RollbackRequired ||
                    now.SinceBoot - current.Started.SinceBoot >= current.Session.Deadline!.Value;
                if (!due)
                {
                    await Task.Delay(50);
                    continue;
                }

                using var executionLock = await ResourceExecutionLock.AcquireAsync(command.Directory, TimeSpan.FromSeconds(10));
                var checkedState = journal.Advance(command.OperationId, ApplyEvent.CheckDeadline, current.Session.Plan, command.WatchdogId);
                var entry = checkedState.Entry;
                if (entry.Session.IsTerminal)
                {
                    output.WriteLine(entry.Session.Phase.ToString());
                    output.Flush();
                    return entry.Session.Phase == ApplyPhase.RecoveryRequired ? 1 : 0;
                }

                if (entry.Session.Phase != ApplyPhase.RollbackRequired)
                {
                    error.WriteLine(checkedState.ErrorCode ?? "phase.invalid");
                    return 1;
                }

                try
                {
                    var ns = AgentStatusProvider.ReadNetworkNamespace();
                    now = clock.Read();
                    var expected = journal.ReadExpectedResource() ?? throw new IOException("resource.unbound");
                    var live = await ObserveLiveAsync();
                    if (live.Identity != expected.Identity)
                    {
                        throw new IOException("Observed table identity disagrees.");
                    }

                    var liveCandidate = NftFilterCompiler.Compile(live.Policy, live.Identity).Candidate;
                    NftTableReceipt restoredReceipt;
                    NftTableObservation restoredListing;
                    if (liveCandidate == entry.Rollback)
                    {
                        if (now.BootId != expected.BootId || ns != expected.NetworkNamespace)
                        {
                            throw new IOException("Observed context disagrees.");
                        }

                        restoredReceipt = new NftTableReceipt(now.BootId, ns, live.Identity, live.TableHandle, live.StateDigest);
                        restoredListing = live;
                    }
                    else if (liveCandidate == entry.Candidate)
                    {
                        (restoredReceipt, restoredListing) = await ReplaceAndVerifyAsync(entry.Rollback, now.BootId, ns, expected.Identity);
                    }
                    else
                    {
                        throw new IOException("Unexpected owned table state during rollback.");
                    }

                    var restored = journal.RecordRollbackSucceededBound(
                        command.OperationId, entry.Session.Plan, command.WatchdogId, restoredReceipt, restoredListing, ns);
                    if (!restored.Accepted)
                    {
                        throw new IOException(restored.ErrorCode ?? "rollback.denied");
                    }

                    output.WriteLine("RolledBack");
                    output.Flush();
                    return 0;
                }
                catch (Exception err) when (err is JournalException or IOException or UnauthorizedAccessException or
                    Win32Exception or OperationCanceledException or DecoderFallbackException or SqliteException or InvalidOperationException)
                {
                    _ = journal.Advance(command.OperationId, ApplyEvent.RollbackFailed, entry.Session.Plan, command.WatchdogId);
                    output.WriteLine("RecoveryRequired");
                    output.Flush();
                    return 1;
                }
            }
        }
        catch (JournalException err) { error.WriteLine(err.Code); }
        catch (Exception err) when (err is IOException or UnauthorizedAccessException or Win32Exception or
            OperationCanceledException or SqliteException or PlatformNotSupportedException)
        {
            error.WriteLine("Watchdog failed.");
        }

        return 1;
    }

    [SupportedOSPlatform("linux")]
    private static async Task<int> ApplyAsync(ApplyCommand command, TextWriter output, TextWriter error)
    {
        try
        {
            using var executionLock = await ResourceExecutionLock.AcquireAsync(command.Directory, TimeSpan.FromSeconds(10));
            var clock = new LinuxBootClock();
            var journal = ApplyJournal.Open(command.Directory, clock);
            var entry = journal.Read(command.OperationId);
            var checkedState = journal.Advance(command.OperationId, ApplyEvent.CheckDeadline, entry.Session.Plan, command.WatchdogId);
            if (!checkedState.Accepted || checkedState.Entry.Session.Phase != ApplyPhase.RollbackArmed)
            {
                error.WriteLine(checkedState.ErrorCode ?? "phase.invalid");
                return 1;
            }

            var ns = AgentStatusProvider.ReadNetworkNamespace();
            var now = clock.Read();
            var expected = journal.ReadExpectedResource();
            if (expected is null) { error.WriteLine("resource.unbound"); return 1; }
            var live = await ObserveLiveAsync();
            if (!journal.VerifyExpectedResource(live, ns).IsMatch)
            {
                error.WriteLine("resource.drift");
                return 1;
            }

            var (candidateReceipt, candidateListing) = await ReplaceAndVerifyAsync(entry.Candidate, now.BootId, ns, expected.Identity);
            var applied = journal.RecordCandidateAppliedBound(
                command.OperationId, entry.Session.Plan, command.WatchdogId, candidateReceipt, candidateListing, ns);
            if (!applied.Accepted)
            {
                error.WriteLine(applied.ErrorCode ?? "apply.denied");
                return 1;
            }

            output.WriteLine("APPLIED");
            return 0;
        }
        catch (JournalException err) { error.WriteLine(err.Code); }
        catch (Exception err) when (err is IOException or UnauthorizedAccessException or Win32Exception or
            OperationCanceledException or DecoderFallbackException or SqliteException or PlatformNotSupportedException)
        {
            error.WriteLine("Apply failed.");
        }

        return 1;
    }

    [SupportedOSPlatform("linux")]
    private static async Task<int> ConfirmAsync(ConfirmCommand command, TextWriter output, TextWriter error)
    {
        try
        {
            using var executionLock = await ResourceExecutionLock.AcquireAsync(command.Directory, TimeSpan.FromSeconds(10));
            var journal = ApplyJournal.Open(command.Directory);
            var entry = journal.Read(command.OperationId);
            var ns = AgentStatusProvider.ReadNetworkNamespace();
            var currentListing = await ObserveLiveAsync();
            var confirmed = journal.ConfirmBound(command.OperationId, entry.Session.Plan, command.WatchdogId, currentListing, ns);
            if (!confirmed.Accepted)
            {
                error.WriteLine(confirmed.ErrorCode ?? "confirm.denied");
                return 1;
            }

            output.WriteLine("CONFIRMED");
            return 0;
        }
        catch (JournalException err) { error.WriteLine(err.Code); }
        catch (Exception err) when (err is IOException or UnauthorizedAccessException or Win32Exception or
            OperationCanceledException or DecoderFallbackException or SqliteException or PlatformNotSupportedException)
        {
            error.WriteLine("Confirm failed.");
        }

        return 1;
    }

    [SupportedOSPlatform("linux")]
    private static async Task<int> ReconcileAsync(string directory, TextWriter output, TextWriter error)
    {
        try
        {
            using var executionLock = await ResourceExecutionLock.AcquireAsync(directory, TimeSpan.FromSeconds(10));
            var clock = new LinuxBootClock();
            var journal = ApplyJournal.Open(directory, clock);
            var enrollment = journal.ReadEnrollment();
            var prior = journal.ReadExpectedResource();
            if (prior is null) { error.WriteLine("resource.unbound"); return 1; }
            var now = clock.Read();
            if (now.BootId == prior.BootId)
            {
                error.WriteLine("reconcile.sameBoot");
                return 1;
            }

            var ns = AgentStatusProvider.ReadNetworkNamespace();
            await NativeNft.Run(["--check", "--file", "-"], enrollment.Artifact);
            var echo = await NativeNft.Run(["--echo", "--handle", "--json", "--file", "-"], enrollment.Artifact);
            var created = NftTableObservation.ParseReplacementEcho(echo).Observation;
            if (created is null || created.Identity != prior.Identity)
            {
                throw new IOException("Creation evidence unavailable.");
            }

            var recreatedExpected = new NftTableReceipt(now.BootId, ns, created.Identity, created.TableHandle, created.StateDigest);
            var recreatedActual = await ObserveLiveAsync();
            journal.ReconcileBoot(enrollment.Ownership, recreatedExpected, recreatedActual, ns);
            output.WriteLine("Reconciled inet nergal_filter on new boot.");
            return 0;
        }
        catch (JournalException err) { error.WriteLine(err.Code); }
        catch (Exception err) when (err is IOException or UnauthorizedAccessException or Win32Exception or
            OperationCanceledException or DecoderFallbackException or SqliteException or PlatformNotSupportedException)
        {
            error.WriteLine("Boot reconciliation failed.");
        }

        return 1;
    }

    private static async Task<NftTableObservation> ObserveLiveAsync(CancellationToken cancellation = default)
    {
        var listed = await NativeNft.Run(["--json", "list", "table", "inet", NftFilterCompiler.TableName], "", cancellation);
        return NftTableObservation.Parse(listed).Observation ?? throw new IOException("Complete observation unavailable.");
    }

    private static async Task<(NftTableReceipt EchoReceipt, NftTableObservation Listing)> ReplaceAndVerifyAsync(
        string artifact, Guid boot, ulong ns, NftTableIdentity expectedIdentity)
    {
        var batch = "delete table inet " + NftFilterCompiler.TableName + "\n" + artifact;
        await NativeNft.Run(["--check", "--file", "-"], batch);
        var echo = await NativeNft.Run(["--echo", "--handle", "--json", "--file", "-"], batch);
        var created = NftTableObservation.ParseReplacementEcho(echo).Observation;
        if (created is null || created.Identity != expectedIdentity)
        {
            throw new IOException("Replacement evidence unavailable.");
        }

        var receipt = new NftTableReceipt(boot, ns, expectedIdentity, created.TableHandle, created.StateDigest);
        var listing = await ObserveLiveAsync();
        return (receipt, listing);
    }

    internal abstract record AgentCommand;
    internal sealed record EnrollCommand(string Directory) : AgentCommand;
    internal sealed record StatusServeCommand(string Directory, string SocketPath, uint AllowedPeerUid, uint? SocketGroupId) : AgentCommand;
    internal sealed record PrepareCommand(string Directory, Guid OperationId, int TimeoutSeconds, FilterVerdict DefaultVerdict, IReadOnlyList<FilterRule> Rules) : AgentCommand;
    internal sealed record WatchCommand(string Directory, Guid OperationId, Guid WatchdogId) : AgentCommand;
    internal sealed record ApplyCommand(string Directory, Guid OperationId, Guid WatchdogId) : AgentCommand;
    internal sealed record ConfirmCommand(string Directory, Guid OperationId, Guid WatchdogId) : AgentCommand;
    internal sealed record ReconcileCommand(string Directory) : AgentCommand;
}

internal static class AgentStatusProvider
{
    internal static ulong ReadNetworkNamespace()
    {
        var context = new FileInfo("/proc/self/ns/net").LinkTarget;
        if (context is null || !context.StartsWith("net:[", StringComparison.Ordinal) || !context.EndsWith(']') ||
            !ulong.TryParse(context.AsSpan(5, context.Length - 6), NumberStyles.None, CultureInfo.InvariantCulture, out var ns) || ns == 0)
        {
            throw new IOException("Namespace unavailable.");
        }

        return ns;
    }

    [SupportedOSPlatform("linux")]
    internal static async ValueTask<AgentStatusReply> EvaluateAsync(
        string directory,
        Func<CancellationToken, Task<NftTableObservation?>> observe,
        Func<ulong> readNamespace,
        CancellationToken cancellation)
    {
        try
        {
            using var executionLock = await ResourceExecutionLock.AcquireAsync(directory, TimeSpan.FromSeconds(1), cancellation);
            var ns = readNamespace();
            if (ns == 0)
            {
                return new(AgentStatusOutcome.Unavailable);
            }

            var journal = ApplyJournal.Open(directory);
            var actual = await observe(cancellation);
            return journal.ReadResourceStatus(actual, ns);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error) when (error is JournalException or IOException or UnauthorizedAccessException or
            Win32Exception or OperationCanceledException or SqliteException or PlatformNotSupportedException or ArgumentException)
        {
            return new(AgentStatusOutcome.Unavailable);
        }
    }
}
