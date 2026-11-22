using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using Nergal.Nftables;

namespace Nergal.Agent;

internal static class NativeNft
{
    // Only fixed argument lists and locally compiled bytes enter this child process.
    internal static async Task<string> Run(string[] arguments, string input, CancellationToken cancellation = default)
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
            var output = ReadOutput(child.StandardOutput.BaseStream, deadline.Token);
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

    internal static async Task<NftTableObservation?> TryObserveAsync(CancellationToken cancellation = default)
    {
        try
        {
            var listed = await Run(["--terse", "--json", "list", "table", "inet", NftFilterCompiler.TableName], "", cancellation);
            var primary = NftTableObservation.Parse(listed).Observation;
            if (primary is null) { return null; }
            var presence = await TryInspectAuxiliaryTablesAsync(primary.Identity, cancellation);
            if (presence is null) { return null; }
            NftNatTableObservation? nat = null;
            NftBridgeTableObservation? bridge = null;
            NftAuxiliaryTableObservation? auxiliary = null;
            if (presence.NatExists && presence.NatOwned)
            {
                var snapshot = await Run(["--terse", "--json", "list", "table", "inet", NftNatCompiler.TableName], "", cancellation);
                nat = NftNatTableObservation.Parse(snapshot).Observation;
                if (nat is null) { return null; }
            }
            if (presence.BridgeExists && presence.BridgeOwned)
            {
                var snapshot = await Run(["--terse", "--json", "list", "table", "bridge", NftBridgeCompiler.TableName], "", cancellation);
                bridge = NftBridgeTableObservation.Parse(snapshot).Observation;
                if (bridge is null) { return null; }
            }
            if (presence.AuxiliaryExists && presence.AuxiliaryOwned)
            {
                var snapshot = await Run(["--terse", "--json", "list", "table", "inet", NftAuxiliaryTableObservation.TableName], "", cancellation);
                auxiliary = NftAuxiliaryTableObservation.Parse(snapshot);
                if (auxiliary is null) { return null; }
            }
            return NftTableObservation.Combine(primary, nat, bridge, auxiliary);
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

    private static async Task<string> ReadOutput(Stream stream, CancellationToken token)
    {
        var data = new byte[65537];
        var length = await stream.ReadAtLeastAsync(data, data.Length, throwOnEndOfStream: false, cancellationToken: token);
        if (length == data.Length)
        {
            await stream.CopyToAsync(Stream.Null, token);
            throw new IOException("Native output exceeds observation limit.");
        }
        return new UTF8Encoding(false, true).GetString(data, 0, length);
    }
}
