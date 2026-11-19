using System.Diagnostics;
using System.Globalization;
using Nergal.Core.Agent;
using Nergal.Linux;
using Nergal.LocalState;
using Nergal.LocalTransport;
using Nergal.Nftables;

if (!OperatingSystem.IsLinux() || args.Length != 5 || args[0] is not ("serve" or "overflow" or "slow" or "query" or "query-cancel"))
{
    return 2;
}

try
{
    var user = new FileInfo("/proc/self/ns/user").LinkTarget;
    var net = new FileInfo("/proc/self/ns/net").LinkTarget;
    var rootMap = File.ReadAllLines("/proc/self/uid_map").Select(line => line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        .SingleOrDefault(fields => fields[0] == "0");
    if (user is null || net is null || user == args[3] || net == args[4] ||
        rootMap is null || rootMap[1] == "0" || rootMap[2] != "1")
    {
        throw new InvalidOperationException("fixture.namespaceRequired");
    }

    if (args[0] is "query" or "query-cancel")
    {
        var capabilities = File.ReadLines("/proc/self/status").Single(line => line.StartsWith("CapEff:", StringComparison.Ordinal)).Split(':')[1].Trim();
        if (LinuxProcessIdentity.EffectiveUserId is not (1 or 2) || ulong.Parse(capabilities, NumberStyles.HexNumber, CultureInfo.InvariantCulture) != 0)
        {
            throw new InvalidOperationException("fixture.unprivilegedClientRequired");
        }

        var expected = uint.Parse(args[1], NumberStyles.None, CultureInfo.InvariantCulture);
        var client = new UnixStatusClient(new(args[2], expected, 1, TimeSpan.FromMilliseconds(500)));
        using var canceled = new CancellationTokenSource();
        var querying = client.QueryAsync(canceled.Token);
        if (args[0] == "query-cancel") { canceled.Cancel(); }
        try
        {
            var reply = await querying;
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(AgentStatusCodec.EncodeReply(reply)));
            return 0;
        }
        catch (OperationCanceledException) { Console.Error.WriteLine("query.canceled"); return 1; }
    }

    if (LinuxProcessIdentity.EffectiveUserId != 0)
    {
        throw new InvalidOperationException("fixture.agentIdentityRequired");
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
            var nativeOutput = await output;
            var parsed = process.ExitCode == 0 ? NftTableObservation.Parse(nativeOutput).Observation : null;
            var context = new FileInfo("/proc/self/ns/net").LinkTarget ?? throw new IOException("fixture.contextUnavailable");
            var inode = ulong.Parse(context.AsSpan(5, context.Length - 6), NumberStyles.None, CultureInfo.InvariantCulture);
            return store.ReadResourceStatus(parsed, inode);
        }
        catch (Exception error) when (error is JournalException or IOException or InvalidOperationException)
        { return new(AgentStatusOutcome.Unavailable); }
    }
}
catch (LocalTransportException error) { Console.Error.WriteLine(error.Code); return 1; }
