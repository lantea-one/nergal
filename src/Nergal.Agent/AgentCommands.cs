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

        if (command is EnrollCommand enroll)
        {
            return await EnrollAsync(enroll.Directory, output, error);
        }

        var serve = (StatusServeCommand)command;
        return await ServeStatusAsync(serve, output, error);
    }

    internal static bool TryParseCommand(string[] args, [NotNullWhen(true)] out AgentCommand? command)
    {
        command = null;
        if (args is ["enroll", var directory] && IsAbsolutePath(directory))
        {
            command = new EnrollCommand(directory);
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

        return false;
    }

    private static bool IsAbsolutePath(string path) => !string.IsNullOrWhiteSpace(path) && Path.IsPathFullyQualified(path);

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
            var listed = await NativeNft.Run(["--json", "list", "table", "inet", NftFilterCompiler.TableName], "");
            var actual = NftTableObservation.Parse(listed).Observation ?? throw new IOException("Complete observation unavailable.");
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

    internal abstract record AgentCommand;
    internal sealed record EnrollCommand(string Directory) : AgentCommand;
    internal sealed record StatusServeCommand(string Directory, string SocketPath, uint AllowedPeerUid, uint? SocketGroupId) : AgentCommand;
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
