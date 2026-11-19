using System.Diagnostics;
using System.Globalization;
using Nergal.Core.Agent;
using Nergal.Linux;
using Nergal.LocalState;
using Nergal.LocalTransport;
using Nergal.Nftables;

if (!OperatingSystem.IsLinux() || args.Length != 5 || args[0] is not ("serve" or "overflow" or "slow"))
{
    return 2;
}

try
{
    var user = new FileInfo("/proc/self/ns/user").LinkTarget;
    var net = new FileInfo("/proc/self/ns/net").LinkTarget;
    var rootMap = File.ReadAllLines("/proc/self/uid_map").Select(line => line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        .SingleOrDefault(fields => fields[0] == "0");
    if (user is null || net is null || user == args[3] || net == args[4] || LinuxProcessIdentity.EffectiveUserId != 0 ||
        rootMap is null || rootMap[1] == "0" || rootMap[2] != "1")
    {
        throw new InvalidOperationException("fixture.namespaceRequired");
    }

    var peers = new HashSet<uint> { args[0] == "overflow" ? LinuxProcessIdentity.ReadOverflowUserId() : 1 };
    using var server = UnixStatusServer.Bind(new(args[2], peers, 1, TimeSpan.FromSeconds(2)));
    peers.Add(2); // Caller mutation must not expand the listener's defensive allowlist.
    var counterPath = Path.Combine(args[1], "provider-count");
    using (var file = new FileStream(counterPath, new FileStreamOptions
    {
        Mode = FileMode.Create,
        Access = FileAccess.Write,
        UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
    })) { }
    var count = 0;
    File.WriteAllText(counterPath, "0");
    using var lifetime = new CancellationTokenSource();
    var serving = server.ServeAsync(Status, lifetime.Token);
    Console.WriteLine("READY");
    Console.Out.Flush();
    _ = await Console.In.ReadLineAsync();
    lifetime.Cancel();
    await serving;
    return 0;

    async ValueTask<AgentStatusReply> Status(CancellationToken cancellation)
    {
        File.WriteAllText(counterPath, Interlocked.Increment(ref count).ToString(CultureInfo.InvariantCulture));
        if (args[0] == "slow")
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellation);
        }

        try
        {
            var store = ApplyJournal.Open(args[1]);
            var revision = store.ReadEnrollment().Ownership.Revision;
            if (store.ReadExpectedResource() is null)
            {
                return new(AgentStatusOutcome.Unbound, revision);
            }

            var start = new ProcessStartInfo("nft") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            foreach (var argument in new[] { "--json", "list", "table", "inet", "nergal_filter" })
            {
                start.ArgumentList.Add(argument);
            }

            using var process = Process.Start(start) ?? throw new IOException("fixture.nativeUnavailable");
            var output = process.StandardOutput.ReadToEndAsync(cancellation);
            var error = process.StandardError.ReadToEndAsync(cancellation);
            try { await process.WaitForExitAsync(cancellation); }
            catch (OperationCanceledException) { process.Kill(true); await process.WaitForExitAsync(); throw; }
            await error;
            if (process.ExitCode != 0)
            {
                return new(AgentStatusOutcome.Unavailable);
            }

            var parsed = NftTableObservation.Parse(await output);
            if (!parsed.IsSuccess)
            {
                return new(AgentStatusOutcome.Unavailable);
            }

            var context = new FileInfo("/proc/self/ns/net").LinkTarget ?? throw new IOException("fixture.contextUnavailable");
            var inode = ulong.Parse(context.AsSpan(5, context.Length - 6), NumberStyles.None, CultureInfo.InvariantCulture);
            var comparison = store.VerifyExpectedResource(parsed.Observation!, inode);
            return new(comparison.IsMatch ? AgentStatusOutcome.Matched : AgentStatusOutcome.Drift, revision);
        }
        catch (Exception error) when (error is JournalException or IOException or InvalidOperationException)
        { return new(AgentStatusOutcome.Unavailable); }
    }
}
catch (LocalTransportException error) { Console.Error.WriteLine(error.Code); return 1; }
