using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using Nergal.Nftables;
using Nergal.Linux;

namespace Nergal.Agent;

internal static class NativeNft
{
    // Only fixed argument lists and locally compiled bytes enter this child process.
    internal static async Task<string> Run(string[] arguments, string input, CancellationToken cancellation = default,
        int maximumOutputBytes = NftObservationLimits.MaximumInventoryBytes)
    {
        var start = new ProcessStartInfo("/usr/sbin/nft")
        {
            WorkingDirectory = "/",
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(false),
        };
        start.Environment.Clear();
        foreach (var argument in arguments) { start.ArgumentList.Add(argument); }
        using var child = Process.Start(start) ?? throw new IOException("Cannot start nft.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            var output = ReadOutput(child.StandardOutput.BaseStream, maximumOutputBytes, deadline.Token);
            var discardErrors = child.StandardError.BaseStream.CopyToAsync(Stream.Null, deadline.Token);
            if (input.Length > 0)
            {
                await child.StandardInput.WriteAsync(input.AsMemory(), deadline.Token);
            }

            child.StandardInput.Close();
            await Task.WhenAll(child.WaitForExitAsync(deadline.Token), discardErrors, output);
            if (child.ExitCode != 0) { throw new IOException("Native transaction failed."); }
            return await output;
        }
        finally
        {
            try
            {
                if (!child.HasExited)
                {
                    child.Kill(entireProcessTree: true);
                    await child.WaitForExitAsync();
                }
            }
            catch (InvalidOperationException) { }
        }
    }

    internal static Task<string> ApplyWithReceiptEcho(string input) =>
        Run(["--echo", "--handle", "--json", "--file", "-"], input, maximumOutputBytes: NftObservationLimits.MaximumDocumentBytes);

    internal static async Task<NftTableObservation?> TryObserveAsync(CancellationToken cancellation = default) =>
        (await TryObserveCompleteAsync(cancellation))?.Observation;

    internal sealed record CompleteObservation(NftTableObservation Observation, IReadOnlyList<string> Snapshots);

    internal static async Task<CompleteObservation?> TryObserveCompleteAsync(CancellationToken cancellation = default)
    {
        if (!OperatingSystem.IsLinux()) { return null; }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        var snapshots = new List<string>();
        try
        {
            var observation = await CollectConsistentAsync(() => OperatingSystem.IsLinux() ? LinuxNftablesGeneration.Read(deadline.Token) : throw new PlatformNotSupportedException(), Collect, deadline.Token);
            return observation is null ? null : new(observation, Array.AsReadOnly(snapshots.ToArray()));
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or Win32Exception or
            OperationCanceledException or DecoderFallbackException or ArgumentException)
        {
            return null;
        }

        async Task<NftTableObservation?> Collect()
        {
            var listed = await CollectTable("inet", NftFilterCompiler.TableName, deadline.Token);
            snapshots.Add(listed);
            var primary = NftTableObservation.Parse(listed).Observation;
            if (primary is null) { return null; }
            var presence = await TryInspectAuxiliaryTablesAsync(primary.Identity, deadline.Token);
            if (presence is null) { return null; }
            NftNatTableObservation? nat = null;
            NftBridgeTableObservation? bridge = null;
            NftAuxiliaryTableObservation? auxiliary = null;
            if (presence.NatExists && presence.NatOwned)
            {
                var snapshot = await CollectTable("inet", NftNatCompiler.TableName, deadline.Token);
                snapshots.Add(snapshot);
                nat = NftNatTableObservation.Parse(snapshot).Observation;
                if (nat is null) { return null; }
            }
            if (presence.BridgeExists && presence.BridgeOwned)
            {
                var snapshot = await CollectTable("bridge", NftBridgeCompiler.TableName, deadline.Token);
                snapshots.Add(snapshot);
                bridge = NftBridgeTableObservation.Parse(snapshot).Observation;
                if (bridge is null) { return null; }
            }
            if (presence.AuxiliaryExists && presence.AuxiliaryOwned)
            {
                var snapshot = await CollectTable("inet", NftAuxiliaryTableObservation.TableName, deadline.Token);
                snapshots.Add(snapshot);
                auxiliary = NftAuxiliaryTableObservation.Parse(snapshot);
                if (auxiliary is null) { return null; }
            }
            return NftTableObservation.Combine(primary, nat, bridge, auxiliary);
        }
    }

    private static async Task<string> CollectTable(string family, string table, CancellationToken cancellation)
    {
        var terse = await Run(["--terse", "--json", "list", "table", family, table], "", cancellation, NftObservationLimits.MaximumDocumentBytes);
        var names = NftStaticSetCollection.Names(terse, family, table);
        if (names.Count == 0) { return terse; }
        var contents = new List<string>(names.Count);
        foreach (var name in names)
        { contents.Add(await Run(["--json", "list", "set", family, table, name], "", cancellation)); }
        return NftStaticSetCollection.Complete(terse, family, table, contents);
    }

    // An outside writer must not make separate table/set listings appear to be one snapshot.
    internal static async Task<NftTableObservation?> CollectConsistentAsync(
        Func<uint> readGeneration, Func<Task<NftTableObservation?>> collect, CancellationToken cancellation = default)
    {
        cancellation.ThrowIfCancellationRequested();
        var before = readGeneration();
        var observation = await collect();
        cancellation.ThrowIfCancellationRequested();
        if (observation is null) { return null; }
        return readGeneration() == before ? observation : null;
    }

    internal static async Task<AuxiliaryTablePresence?> TryInspectAuxiliaryTablesAsync(
        NftTableIdentity expectedIdentity,
        CancellationToken cancellation = default)
    {
        try
        {
            var listed = await Run(["--terse", "--json", "list", "tables"], "", cancellation);
            return NftTableObservation.TryInspectAuxiliaryTables(listed, expectedIdentity, out var presence, out _)
                ? presence
                : null;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or Win32Exception or
            OperationCanceledException or DecoderFallbackException)
        {
            return null;
        }
    }

    internal static async Task<string> ReadOutput(Stream stream, int maximumBytes, CancellationToken token)
    {
        var data = new byte[checked(maximumBytes + 1)];
        var length = await stream.ReadAtLeastAsync(data, data.Length, throwOnEndOfStream: false, cancellationToken: token);
        if (length == data.Length)
        {
            await stream.CopyToAsync(Stream.Null, token);
            throw new IOException("Native output exceeds observation limit.");
        }
        return new UTF8Encoding(false, true).GetString(data, 0, length);
    }
}
