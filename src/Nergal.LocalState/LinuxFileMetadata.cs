using System.Runtime.InteropServices;

namespace Nergal.LocalState;

// Fixed-layout Linux UAPI statx structure. Required fields are checked, never inferred from dummy values.
internal static class LinuxFileMetadata
{
    private const uint RequiredFields = 0x0f; // STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_UID
    internal static Metadata? Read(string path)
    {
        try
        {
            if (statx(-100, path, 0x900, RequiredFields, out var metadata) != 0) // AT_FDCWD, NOFOLLOW | NO_AUTOMOUNT
            {
                var error = Marshal.GetLastPInvokeError();
                if (error is 2 or 20)
                {
                    return null; // ENOENT / ENOTDIR
                }

                if (error == 13)
                {
                    throw new UnauthorizedAccessException("Cannot inspect private journal metadata.");
                }

                throw new JournalException("path.metadataUnavailable");
            }
            if ((metadata.Mask & RequiredFields) != RequiredFields)
            {
                throw new JournalException("path.metadataUnavailable");
            }

            return metadata;
        }
        catch (EntryPointNotFoundException) { throw new JournalException("path.metadataUnavailable"); }
    }

    internal static void Validate(Metadata metadata, bool directory)
    {
        var type = metadata.Mode & 0xf000;
        if (type == 0xa000)
        {
            throw new JournalException("path.symlink");
        }

        if (type != (directory ? 0x4000 : 0x8000))
        {
            throw new JournalException("path.type");
        }

        if (metadata.UserId != geteuid())
        {
            throw new JournalException("path.owner");
        }

        if (!directory && metadata.LinkCount != 1)
        {
            throw new JournalException("path.hardLink");
        }

        var expected = directory ? PrivateJournalPath.DirectoryMode : PrivateJournalPath.FileMode;
        if ((UnixFileMode)(metadata.Mode & 0xfff) != expected)
        {
            throw new JournalException(directory ? "path.directoryMode" : "path.databaseMode");
        }
    }

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    internal struct Metadata
    {
        [FieldOffset(0)] internal uint Mask;
        [FieldOffset(16)] internal uint LinkCount;
        [FieldOffset(20)] internal uint UserId;
        [FieldOffset(28)] internal ushort Mode;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int statx(int directoryFd, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, out Metadata metadata);
    [DllImport("libc")]
    private static extern uint geteuid();
}
