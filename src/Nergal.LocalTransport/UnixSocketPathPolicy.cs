using Nergal.Linux;
using System.Runtime.Versioning;

namespace Nergal.LocalTransport;

// Shared listener/client filesystem contract. Trusted ancestors remain a provisioning requirement.
[SupportedOSPlatform("linux")]
internal static class UnixSocketPathPolicy
{
    internal static void RequireSupportedPlatform()
    {
        if (!OperatingSystem.IsLinux() || System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture is not
            (System.Runtime.InteropServices.Architecture.X64 or System.Runtime.InteropServices.Architecture.Arm64))
        {
            throw new PlatformNotSupportedException("Local peer status requires Linux x64 or arm64.");
        }
    }

    internal static void RequireParent(string path, uint owner, uint? group)
    {
        var parent = Path.GetDirectoryName(path) ?? throw new LocalTransportException("socket.parent");
        for (DirectoryInfo? part = new(parent); part is not null; part = part.Parent)
        {
            if (part.LinkTarget is not null)
            {
                throw new LocalTransportException("socket.symlink");
            }
        }

        var directory = LinuxFileSystem.Read(parent) ?? throw new LocalTransportException("socket.parentMissing");
        var mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        if (group.HasValue)
        {
            mode |= UnixFileMode.GroupExecute | UnixFileMode.SetGroup;
        }

        if (directory.Type != LinuxNodeType.Directory || directory.OwnerUserId != owner || directory.Permissions != mode ||
            (group is { } expectedGroup && directory.OwnerGroupId != expectedGroup))
        {
            throw new LocalTransportException("socket.parentPolicy");
        }
    }

    internal static LinuxNodeMetadata RequireSocket(string path, uint owner, uint? group)
    {
        var node = LinuxFileSystem.Read(path) ?? throw new LocalTransportException("socket.missing");
        var mode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        if (group.HasValue)
        {
            mode |= UnixFileMode.GroupRead | UnixFileMode.GroupWrite;
        }

        if (node.Type != LinuxNodeType.Socket || node.OwnerUserId != owner || node.Permissions != mode || node.LinkCount != 1 ||
            node.Inode == 0 || (group is { } expectedGroup && node.OwnerGroupId != expectedGroup))
        {
            throw new LocalTransportException("socket.metadata");
        }

        return node;
    }
}
