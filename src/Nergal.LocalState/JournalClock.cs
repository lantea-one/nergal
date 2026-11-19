using System.Runtime.InteropServices;

namespace Nergal.LocalState;

/// <summary>A boot identity and monotonic duration since boot; never a wall-clock deadline.</summary>
/// <param name="BootId">Nonempty operating-system boot identity.</param>
/// <param name="SinceBoot">Nonnegative suspend-inclusive monotonic duration.</param>
public sealed record JournalTime(Guid BootId, TimeSpan SinceBoot);

/// <summary>Supplies boot-scoped monotonic time, sampled after obtaining a journal transaction lock.</summary>
public interface IJournalClock
{
    /// <summary>Reads the current boot identity and monotonic elapsed duration.</summary>
    JournalTime Read();
}

/// <summary>Linux CLOCK_BOOTTIME includes suspend time; reboot changes the accompanying boot UUID.</summary>
public sealed class LinuxBootClock : IJournalClock
{
    /// <inheritdoc />
    public JournalTime Read()
    {
        if (!OperatingSystem.IsLinux() || !Environment.Is64BitProcess)
        {
            throw new PlatformNotSupportedException("The boot clock requires 64-bit Linux.");
        }

        var boot = Guid.Parse(File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim());
        if (clock_gettime(7, out var stamp) != 0)
        {
            throw new IOException("Cannot read boot-scoped monotonic time.");
        }

        var ticks = checked(stamp.Seconds * TimeSpan.TicksPerSecond + stamp.Nanoseconds / 100);
        return new(boot, TimeSpan.FromTicks(ticks));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Timespec
    {
        internal long Seconds;
        internal long Nanoseconds;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int clock_gettime(int clockId, out Timespec time);
}
