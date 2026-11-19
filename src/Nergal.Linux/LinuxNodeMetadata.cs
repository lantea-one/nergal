using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Nergal.Linux;

/// <summary>Recognized Linux filesystem node types; unknown types remain explicit.</summary>
public enum LinuxNodeType
{
    /// <summary>A node outside the recognized directory/file/link/socket set.</summary>
    Other,
    /// <summary>A directory.</summary>
    Directory,
    /// <summary>A regular file.</summary>
    RegularFile,
    /// <summary>A symbolic link, never followed by metadata inspection.</summary>
    SymbolicLink,
    /// <summary>A filesystem Unix socket.</summary>
    Socket,
}

/// <summary>Immutable no-follow metadata snapshot; not a path-confinement or authority token.</summary>
public readonly record struct LinuxNodeMetadata
{
    internal LinuxNodeMetadata(ushort mode, uint owner, uint group, uint links, ulong inode, uint major, uint minor)
    {
        Type = (mode & 0xf000) switch
        {
            0x4000 => LinuxNodeType.Directory,
            0x8000 => LinuxNodeType.RegularFile,
            0xa000 => LinuxNodeType.SymbolicLink,
            0xc000 => LinuxNodeType.Socket,
            _ => LinuxNodeType.Other
        };
        Permissions = (UnixFileMode)(mode & 0xfff);
        OwnerUserId = owner;
        OwnerGroupId = group;
        LinkCount = links;
        Inode = inode;
        DeviceMajor = major;
        DeviceMinor = minor;
    }
    /// <summary>Gets the recognized node type.</summary>
    public LinuxNodeType Type { get; }
    /// <summary>Gets permission/special mode bits, excluding node type.</summary>
    public UnixFileMode Permissions { get; }
    /// <summary>Gets the owner UID in the inspecting process's user namespace.</summary>
    public uint OwnerUserId { get; }
    /// <summary>Gets the owner GID in the inspecting process's user namespace.</summary>
    public uint OwnerGroupId { get; }
    /// <summary>Gets the hard-link count.</summary>
    public uint LinkCount { get; }
    /// <summary>Gets the inode identity, valid together with device identity and caller's trusted context.</summary>
    public ulong Inode { get; }
    /// <summary>Gets the containing device's major identifier.</summary>
    public uint DeviceMajor { get; }
    /// <summary>Gets the containing device's minor identifier.</summary>
    public uint DeviceMinor { get; }
}

/// <summary>Shared Linux statx boundary with required-field validation and no weaker fallback.</summary>
[SupportedOSPlatform("linux")]
public static class LinuxFileSystem
{
    // TYPE | MODE | NLINK | UID | GID | INO. Fields with unavailable mask bits are never inferred from dummy values.
    private const uint RequiredFields = 0x11f;

    /// <summary>Reads an absolute path without following its final symbolic link or automounting its final component.</summary>
    /// <returns>A complete required-field snapshot, or null for missing/non-directory path components.</returns>
    /// <exception cref="ArgumentException">Path is empty, relative or contains a NUL.</exception>
    /// <exception cref="LinuxMetadataException">Required statx support or metadata is unavailable.</exception>
    /// <exception cref="UnauthorizedAccessException">Search permission prevents inspection.</exception>
    public static LinuxNodeMetadata? Read(string path)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("Linux metadata requires Linux.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path) || path.Contains('\0'))
        {
            throw new ArgumentException("An absolute NUL-free path is required.", nameof(path));
        }

        try
        {
            if (statx(-100, path, 0x900, RequiredFields, out var value) != 0) // AT_FDCWD, NOFOLLOW | NO_AUTOMOUNT
            {
                var error = Marshal.GetLastPInvokeError();
                if (error is 2 or 20)
                {
                    return null;
                }

                if (error == 13)
                {
                    throw new UnauthorizedAccessException("Cannot inspect Linux node metadata.");
                }

                throw new LinuxMetadataException();
            }
            if ((value.Mask & RequiredFields) != RequiredFields)
            {
                throw new LinuxMetadataException();
            }

            return new(value.Mode, value.UserId, value.GroupId, value.LinkCount, value.Inode, value.DeviceMajor, value.DeviceMinor);
        }
        catch (EntryPointNotFoundException) { throw new LinuxMetadataException(); }
    }

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct Statx
    {
        [FieldOffset(0)] internal uint Mask;
        [FieldOffset(16)] internal uint LinkCount;
        [FieldOffset(20)] internal uint UserId;
        [FieldOffset(24)] internal uint GroupId;
        [FieldOffset(28)] internal ushort Mode;
        [FieldOffset(32)] internal ulong Inode;
        [FieldOffset(136)] internal uint DeviceMajor;
        [FieldOffset(140)] internal uint DeviceMinor;
    }
    [DllImport("libc", SetLastError = true)]
    private static extern int statx(int directoryFd, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, out Statx metadata);
}

/// <summary>Required Linux filesystem metadata could not be established; contains no path or file contents.</summary>
public sealed class LinuxMetadataException : IOException
{
    internal LinuxMetadataException() : base("Required Linux node metadata is unavailable.") { }
}
