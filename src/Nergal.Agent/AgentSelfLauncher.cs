using System.Diagnostics;

namespace Nergal.Agent;

/// <summary>Spawns an independent <c>nergal-agent watch</c> child process without a shell and waits for durable arming.</summary>
internal static class AgentSelfLauncher
{
    private static readonly TimeSpan ArmingTimeout = TimeSpan.FromSeconds(15);

    internal static async Task<bool> StartWatchdogAsync(
        string directory,
        Guid operationId,
        Guid watchdogId,
        CancellationToken cancellationToken)
    {
        var processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath))
        {
            return false;
        }

        var start = new ProcessStartInfo(processPath)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        if (Path.GetFileNameWithoutExtension(processPath).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        {
            var entry = Environment.GetCommandLineArgs().FirstOrDefault();
            var assemblyPath = !string.IsNullOrWhiteSpace(entry) && entry.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                ? Path.GetFullPath(entry)
                : typeof(AgentSelfLauncher).Assembly.Location;
            start.ArgumentList.Add(assemblyPath);
        }

        start.ArgumentList.Add("watch");
        start.ArgumentList.Add(directory);
        start.ArgumentList.Add(operationId.ToString("D"));
        start.ArgumentList.Add(watchdogId.ToString("D"));

        var child = Process.Start(start);
        if (child is null)
        {
            return false;
        }

        child.StandardInput.Close();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(ArmingTimeout);

        try
        {
            while (true)
            {
                var line = await child.StandardOutput.ReadLineAsync(cts.Token).ConfigureAwait(false);
                if (line is null)
                {
                    await TerminateAndDisposeAsync(child).ConfigureAwait(false);
                    return false;
                }

                if (string.Equals(line.Trim(), "WATCHING", StringComparison.Ordinal))
                {
                    _ = DrainAndReapAsync(child);
                    return true;
                }
            }
        }
        catch (OperationCanceledException)
        {
            await TerminateAndDisposeAsync(child).ConfigureAwait(false);
            return false;
        }
        catch (IOException)
        {
            await TerminateAndDisposeAsync(child).ConfigureAwait(false);
            return false;
        }
        catch (InvalidOperationException)
        {
            await TerminateAndDisposeAsync(child).ConfigureAwait(false);
            return false;
        }
    }

    private static async Task DrainAndReapAsync(Process child)
    {
        try
        {
            var outDrain = DrainTextAsync(child.StandardOutput);
            var errDrain = DrainTextAsync(child.StandardError);
            await Task.WhenAll(outDrain, errDrain).ConfigureAwait(false);
            await child.WaitForExitAsync().ConfigureAwait(false);
        }
        catch (Exception)
        {
        }
        finally
        {
            child.Dispose();
        }
    }

    private static async Task DrainTextAsync(StreamReader reader)
    {
        try
        {
            while (await reader.ReadLineAsync().ConfigureAwait(false) is not null)
            {
            }
        }
        catch (IOException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private static async Task TerminateAndDisposeAsync(Process child)
    {
        try
        {
            if (!child.HasExited)
            {
                child.Kill(entireProcessTree: false);
            }

            using var waitCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await child.WaitForExitAsync(waitCts.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
        }
        finally
        {
            child.Dispose();
        }
    }
}
