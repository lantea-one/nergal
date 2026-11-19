using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Nergal.Admin;

// Use the fixed system terminal utility for its portable termios layout.
// Its arguments contain flags or saved terminal modes, never password bytes.
internal sealed class HiddenTerminal : IDisposable
{
    private readonly string saved;
    private readonly object gate = new();
    private bool restored;
    private readonly List<PosixSignalRegistration> signals = [];

    private HiddenTerminal(string saved) => this.saved = saved;

    internal static HiddenTerminal Open()
    {
        var saved = Stty("-g");
        if (saved.Length is < 1 or > 2048 || !saved.All(ch => char.IsAsciiHexDigit(ch) || ch == ':'))
        { throw new IOException("Cannot capture terminal mode."); }
        var terminal = new HiddenTerminal(saved);
        try
        {
            foreach (var signal in new[] { PosixSignal.SIGINT, PosixSignal.SIGTERM, PosixSignal.SIGHUP })
            {
                terminal.signals.Add(PosixSignalRegistration.Create(signal, _ => terminal.Restore()));
            }
            lock (terminal.gate)
            {
                if (terminal.restored) { throw new IOException("Terminal input interrupted."); }
                Stty("icanon", "-echo", "-echonl");
            }
            return terminal;
        }
        catch { terminal.Dispose(); throw; }
    }

    private void Restore()
    {
        lock (gate)
        {
            if (restored) { return; }
            Stty(saved);
            restored = true;
        }
    }

    public void Dispose()
    {
        try { Restore(); }
        finally { foreach (var registration in signals) { registration.Dispose(); } }
    }

    private static string Stty(params string[] args)
    {
        var start = new ProcessStartInfo("/usr/bin/stty")
        { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in args) { start.ArgumentList.Add(argument); }
        try
        {
            using var process = Process.Start(start) ?? throw new IOException("Terminal settings unavailable.");
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            if (process.ExitCode != 0) { throw new IOException("Terminal settings unavailable."); }
            return output.TrimEnd();
        }
        catch (Win32Exception) { throw new IOException("Terminal settings unavailable."); }
    }
}
