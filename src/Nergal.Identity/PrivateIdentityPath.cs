using System.Runtime.Versioning;
using Nergal.Linux;

namespace Nergal.Identity;

// Common owner-only filesystem policy for distinct account and session-key directories.
[SupportedOSPlatform("linux")]
internal static class PrivateIdentityPath
{
    internal static void RequireDirectory(string path)
    {
        Inspect(() =>
        {
            for (DirectoryInfo? part = new(path); part is not null; part = part.Parent)
            {
                if (part.LinkTarget is not null) { throw new AccountStoreException("path.symlink"); }
            }
            Require(LinuxFileSystem.Read(path) ?? throw new AccountStoreException("path.directoryMissing"), true);
            return true;
        });
    }
    internal static LinuxNodeMetadata? ReadFile(string path) => Inspect(() =>
    {
        var node = LinuxFileSystem.Read(path);
        if (node is { } found) { Require(found, false); }
        return node;
    });
    private static T Inspect<T>(Func<T> action)
    {
        try { return action(); }
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
