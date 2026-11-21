using System.Diagnostics;
using System.Text;

internal static class NativeNft
{
    // Only fixed argument lists and locally compiled bytes enter this child process.
    internal static async Task<string> Run(string[] arguments, string input)
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
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            var output = ReadOutput(child.StandardOutput.BaseStream, deadline.Token);
            var discardErrors = child.StandardError.BaseStream.CopyToAsync(Stream.Null, deadline.Token);
            await child.StandardInput.WriteAsync(input.AsMemory(), deadline.Token);
            child.StandardInput.Close();
            await Task.WhenAll(child.WaitForExitAsync(deadline.Token), discardErrors, output);
            if (child.ExitCode != 0) { throw new IOException("Native transaction failed."); }
            return await output;
        }
        finally
        {
            if (!child.HasExited) { child.Kill(); await child.WaitForExitAsync(); }
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
