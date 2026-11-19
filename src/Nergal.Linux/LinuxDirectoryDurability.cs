using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Nergal.Linux;

/// <summary>Synchronizes a trusted local directory after an atomic file publication; performs no creation, deletion or shell operations.</summary>
[SupportedOSPlatform("linux")]
public static class LinuxDirectoryDurability
{
    /// <summary>Opens an absolute directory without following its final symlink and fsyncs its entries.</summary>
    /// <remarks>Requires trusted ancestors and a local filesystem supporting directory synchronization; no weaker fallback exists.</remarks>
    /// <exception cref="ArgumentException">Path is missing, relative or contains a NUL.</exception>
    /// <exception cref="IOException">Directory open or synchronization fails.</exception>
    /// <exception cref="PlatformNotSupportedException">Platform is not Linux x64/arm64.</exception>
    public static void Synchronize(string directory)
    {
        if (!OperatingSystem.IsLinux() || RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64))
        { throw new PlatformNotSupportedException("Directory synchronization requires Linux x64 or arm64."); }
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        if (!Path.IsPathFullyQualified(directory) || directory.Contains('\0'))
        { throw new ArgumentException("An absolute NUL-free directory is required.", nameof(directory)); }
        var descriptor = open(directory, 0xb0000); // O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        if (descriptor < 0) { throw new IOException("Cannot open directory for synchronization."); }
        using var handle = new SafeFileHandle((IntPtr)descriptor, ownsHandle: true);
        if (fsync(handle) != 0) { throw new IOException("Cannot synchronize directory."); }
    }
    [DllImport("libc", SetLastError = true)]
    private static extern int open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);
    [DllImport("libc", SetLastError = true)]
    private static extern int fsync(SafeFileHandle descriptor);
}
