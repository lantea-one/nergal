using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Nergal.Linux;
using Nergal.LocalState;
using Nergal.LocalTransport;
using Nergal.RemoteTransport;

namespace Nergal.Agent;

[SupportedOSPlatform("linux")]
internal static class AgentControlCli
{
    internal static bool TryParse(string[] args, [NotNullWhen(true)] out AgentCommands.AgentCommand? command)
    {
        command = null;
        if (args.Length == 0)
        {
            return false;
        }

        if (args[0] == "control-serve")
        {
            if (args.Length is not (4 or 5) ||
                !IsAbsolutePath(args[1]) ||
                !IsAbsolutePath(args[2]) ||
                !uint.TryParse(args[3], NumberStyles.None, CultureInfo.InvariantCulture, out var peerUid))
            {
                return false;
            }

            uint? groupId = null;
            if (args.Length == 5)
            {
                if (!uint.TryParse(args[4], NumberStyles.None, CultureInfo.InvariantCulture, out var parsedGid))
                {
                    return false;
                }

                groupId = parsedGid;
            }

            command = new AgentCommands.ControlServeCommand(args[1], args[2], peerUid, groupId);
            return true;
        }

        if (args[0] == "tls-serve")
        {
            if (args.Length != 6 ||
                !IsAbsolutePath(args[1]) ||
                !IPEndPoint.TryParse(args[2], out var listenEndPoint) ||
                !IsAbsolutePath(args[3]) ||
                !IsAbsolutePath(args[4]) ||
                string.IsNullOrWhiteSpace(args[5]))
            {
                return false;
            }

            var rawPins = args[5].Split(',', StringSplitOptions.TrimEntries);
            if (rawPins.Length == 0 || rawPins.Any(string.IsNullOrEmpty))
            {
                return false;
            }

            string[] pins;
            try
            {
                pins = rawPins.Select(TlsThumbprintPolicy.NormalizeThumbprint).ToArray();
            }
            catch (ArgumentException)
            {
                return false;
            }

            command = new AgentCommands.TlsServeCommand(args[1], listenEndPoint, args[3], args[4], pins);
            return true;
        }

        return false;
    }

    internal static async Task<int> ServeControlAsync(AgentCommands.ControlServeCommand command, TextWriter output, TextWriter error)
    {
        try
        {
            _ = ApplyJournal.Open(command.Directory);

            var options = new UnixControlOptions(command.SocketPath, [command.AllowedPeerUid], command.SocketGroupId);
            using var server = UnixControlServer.Bind(options);
            var handler = new AgentControlHandler(command.Directory);

            using var cts = CreateShutdownTokenSource(out var registrations);
            try
            {
                await output.WriteLineAsync("Listening for authorized control requests.").ConfigureAwait(false);
                await output.FlushAsync().ConfigureAwait(false);
                await server.ServeAsync(handler.HandleAsync, cts.Token).ConfigureAwait(false);
                return 0;
            }
            finally
            {
                registrations.Dispose();
            }
        }
        catch (JournalException err)
        {
            error.WriteLine(err.Code);
            return 1;
        }
        catch (LocalTransportException err)
        {
            error.WriteLine(err.Code);
            return 1;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
        {
            error.WriteLine("Control listener failed.");
            return 1;
        }
    }

    internal static async Task<int> ServeTlsAsync(AgentCommands.TlsServeCommand command, TextWriter output, TextWriter error)
    {
        try
        {
            _ = ApplyJournal.Open(command.Directory);

            ValidatePemPaths(command.ServerCertPath, command.ServerKeyPath);
            using var serverCert = X509Certificate2.CreateFromPemFile(command.ServerCertPath, command.ServerKeyPath);
            var options = new TlsControlServerOptions(command.ListenEndPoint, serverCert, command.TrustedClientThumbprints);
            using var server = TlsControlServer.Bind(options);
            var handler = new AgentControlHandler(command.Directory);

            using var cts = CreateShutdownTokenSource(out var registrations);
            try
            {
                await output.WriteLineAsync($"LISTENING {server.BoundEndPoint}").ConfigureAwait(false);
                await output.FlushAsync().ConfigureAwait(false);
                await server.ServeAsync(handler.HandleAsync, cts.Token).ConfigureAwait(false);
                return 0;
            }
            finally
            {
                registrations.Dispose();
            }
        }
        catch (JournalException err)
        {
            error.WriteLine(err.Code);
            return 1;
        }
        catch (RemoteTransportException err)
        {
            error.WriteLine(err.Code);
            return 1;
        }
        catch (InvalidOperationException err) when (err.Message is "tls.certInvalid" or "tls.keyPermissions")
        {
            error.WriteLine(err.Message);
            return 1;
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException or IOException or UnauthorizedAccessException)
        {
            error.WriteLine("TLS control listener failed.");
            return 1;
        }
    }

    private static void ValidatePemPaths(string certPath, string keyPath)
    {
        var fullCert = Path.GetFullPath(certPath);
        var fullKey = Path.GetFullPath(keyPath);
        EnsureNoSymlinkAncestors(Path.GetDirectoryName(fullCert), "tls.certInvalid");
        EnsureNoSymlinkAncestors(Path.GetDirectoryName(fullKey), "tls.keyPermissions");

        var certNode = LinuxFileSystem.Read(fullCert);
        if (certNode is null || certNode.Value.Type != LinuxNodeType.RegularFile || certNode.Value.LinkCount != 1)
        {
            throw new InvalidOperationException("tls.certInvalid");
        }

        var owner = LinuxProcessIdentity.EffectiveUserId;
        var keyParentPath = Path.GetDirectoryName(fullKey) ?? throw new InvalidOperationException("tls.keyPermissions");
        var keyParent = LinuxFileSystem.Read(keyParentPath);
        if (keyParent is null ||
            keyParent.Value.Type != LinuxNodeType.Directory ||
            keyParent.Value.OwnerUserId != owner ||
            (keyParent.Value.Permissions & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
        {
            throw new InvalidOperationException("tls.keyPermissions");
        }

        var keyNode = LinuxFileSystem.Read(fullKey);
        if (keyNode is null ||
            keyNode.Value.Type != LinuxNodeType.RegularFile ||
            keyNode.Value.LinkCount != 1 ||
            keyNode.Value.OwnerUserId != owner ||
            keyNode.Value.Permissions != (UnixFileMode.UserRead | UnixFileMode.UserWrite))
        {
            throw new InvalidOperationException("tls.keyPermissions");
        }
    }

    private static void EnsureNoSymlinkAncestors(string? directory, string errorCode)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new InvalidOperationException(errorCode);
        }

        for (DirectoryInfo? part = new(directory); part is not null; part = part.Parent)
        {
            if (part.LinkTarget is not null)
            {
                throw new InvalidOperationException(errorCode);
            }
        }
    }

    private static CancellationTokenSource CreateShutdownTokenSource(out IDisposable registrations)
    {
        var cts = new CancellationTokenSource();
        void OnCancelKeyPress(object? _, ConsoleCancelEventArgs e)
        {
            e.Cancel = true;
            cts.Cancel();
        }

        Console.CancelKeyPress += OnCancelKeyPress;
        var sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx =>
        {
            ctx.Cancel = true;
            cts.Cancel();
        });
        var sigint = PosixSignalRegistration.Create(PosixSignal.SIGINT, ctx =>
        {
            ctx.Cancel = true;
            cts.Cancel();
        });

        registrations = new ShutdownRegistrations(OnCancelKeyPress, sigterm, sigint);
        return cts;
    }

    private static bool IsAbsolutePath(string path) => !string.IsNullOrWhiteSpace(path) && Path.IsPathFullyQualified(path);

    private sealed class ShutdownRegistrations(
        ConsoleCancelEventHandler cancelHandler,
        PosixSignalRegistration sigterm,
        PosixSignalRegistration sigint) : IDisposable
    {
        public void Dispose()
        {
            Console.CancelKeyPress -= cancelHandler;
            sigterm.Dispose();
            sigint.Dispose();
        }
    }
}
