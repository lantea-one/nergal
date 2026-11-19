using System.Runtime.Versioning;
using Nergal.Linux;

namespace Nergal.LocalState;

// Journal-specific policy stays here; no-follow Linux metadata is shared with local transport.
[SupportedOSPlatform("linux")]
internal static class LinuxFileMetadata
{
    internal static LinuxNodeMetadata? Read(string path)
    {
        try { return LinuxFileSystem.Read(path); }
        catch (LinuxMetadataException) { throw new JournalException("path.metadataUnavailable"); }
    }

    internal static void Validate(LinuxNodeMetadata metadata, bool directory)
    {
        if (metadata.Type == LinuxNodeType.SymbolicLink)
        {
            throw new JournalException("path.symlink");
        }

        if (metadata.Type != (directory ? LinuxNodeType.Directory : LinuxNodeType.RegularFile))
        {
            throw new JournalException("path.type");
        }

        if (metadata.OwnerUserId != LinuxProcessIdentity.EffectiveUserId)
        {
            throw new JournalException("path.owner");
        }

        if (!directory && metadata.LinkCount != 1)
        {
            throw new JournalException("path.hardLink");
        }

        var expected = directory ? PrivateJournalPath.DirectoryMode : PrivateJournalPath.FileMode;
        if (metadata.Permissions != expected)
        {
            throw new JournalException(directory ? "path.directoryMode" : "path.databaseMode");
        }
    }
}
