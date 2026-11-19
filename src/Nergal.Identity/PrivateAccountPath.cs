using Nergal.Linux;
using System.Runtime.Versioning;

namespace Nergal.Identity;

[SupportedOSPlatform("linux")]
internal static class PrivateAccountPath
{
    internal static string Validate(LocalAccountOptions options, bool requireDatabase)
    {
        try
        {
            for (DirectoryInfo? part = new(options.Directory); part is not null; part = part.Parent)
            {
                if (part.LinkTarget is not null) { throw new AccountStoreException("path.symlink"); }
            }
            var directory = LinuxFileSystem.Read(options.Directory) ?? throw new AccountStoreException("path.directoryMissing");
            Require(directory, true);
            var database = Path.Combine(options.Directory, "accounts.db");
            foreach (var suffix in new[] { "", "-journal", "-wal", "-shm" })
            {
                var node = LinuxFileSystem.Read(database + suffix);
                if (node is { } found) { Require(found, false); }
                else if (suffix == "" && requireDatabase) { throw new AccountStoreException("account.databaseMissing"); }
            }
            return database;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        { throw new AccountStoreException("path.metadataUnavailable"); }
    }

    private static void Require(LinuxNodeMetadata node, bool directory)
    {
        if (node.Type == LinuxNodeType.SymbolicLink) { throw new AccountStoreException("path.symlink"); }
        if (node.Type != (directory ? LinuxNodeType.Directory : LinuxNodeType.RegularFile)) { throw new AccountStoreException("path.type"); }
        if (node.OwnerUserId != LinuxProcessIdentity.EffectiveUserId) { throw new AccountStoreException("path.owner"); }
        if (!directory && node.LinkCount != 1) { throw new AccountStoreException("path.hardLink"); }
        var mode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        if (directory) { mode |= UnixFileMode.UserExecute; }
        if (node.Permissions != mode) { throw new AccountStoreException("path.mode"); }
    }
}
