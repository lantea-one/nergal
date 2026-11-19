using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Nergal.Linux;

/// <summary>Local kernel process identity, never caller-supplied application claims.</summary>
[SupportedOSPlatform("linux")]
public static class LinuxProcessIdentity
{
    /// <summary>Gets the effective UID in the current user namespace.</summary>
    public static uint EffectiveUserId => geteuid();
    /// <summary>Gets the effective GID in the current user namespace.</summary>
    public static uint EffectiveGroupId => getegid();
    /// <summary>Reads the kernel overflow UID so unmapped peer identities are never configured as trusted authority.</summary>
    public static uint ReadOverflowUserId()
    {
        if (!uint.TryParse(File.ReadAllText("/proc/sys/kernel/overflowuid").Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var id))
        {
            throw new IOException("Cannot establish kernel overflow UID.");
        }

        return id;
    }
    [DllImport("libc")]
    private static extern uint geteuid();
    [DllImport("libc")]
    private static extern uint getegid();
}
