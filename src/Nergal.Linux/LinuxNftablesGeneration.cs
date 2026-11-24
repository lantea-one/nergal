using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Nergal.Linux;

/// <summary>Read-only, bounded inspection of the current network namespace's nftables transaction sequence.</summary>
[SupportedOSPlatform("linux")]
public static class LinuxNftablesGeneration
{
    // Linux UAPI values; no application-controlled netlink command or destination exists.
    private const ushort AddressFamilyNetlink = 16;
    private const int NetfilterProtocol = 12;
    private const int RawCloseOnExecNonblocking = 3 | 0x80000 | 0x800;
    private const uint AddressLength = 12;
    private const int MessageTruncate = 0x20;

    /// <summary>Queries the kernel transaction generation without listing or modifying policy.</summary>
    /// <remarks>
    /// Requires the kernel's netfilter query capability in the current namespace. Compare only within
    /// one bounded observation; this is neither an ownership receipt nor transaction authorization.
    /// No multicast subscription, ambient socket, shell or policy input is used.
    /// </remarks>
    /// <exception cref="IOException">The fixed query is denied, unavailable, malformed or exceeds its one-second deadline.</exception>
    /// <exception cref="OperationCanceledException">The caller cancels collection.</exception>
    public static uint Read(CancellationToken cancellation = default)
    {
        cancellation.ThrowIfCancellationRequested();
        using var descriptor = new NetlinkHandle(socket(AddressFamilyNetlink, RawCloseOnExecNonblocking, NetfilterProtocol));
        if (descriptor.IsInvalid) { throw Unavailable(); }
        var local = new NetlinkAddress { Family = AddressFamilyNetlink };
        if (bind(descriptor, ref local, AddressLength) != 0) { throw Unavailable(); }
        uint addressLength = AddressLength;
        if (getsockname(descriptor, out local, ref addressLength) != 0 || addressLength != AddressLength ||
            local.Family != AddressFamilyNetlink || local.Port == 0 || local.Groups != 0)
        { throw Unavailable(); }
        var sequence = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4)) | 1u;
        var request = NftGenerationMessage.Request(sequence, local.Port);
        var kernel = new NetlinkAddress { Family = AddressFamilyNetlink };
        if (sendto(descriptor, request, (nuint)request.Length, 0, ref kernel, AddressLength) != request.Length)
        { throw Unavailable(); }

        var deadline = Stopwatch.StartNew();
        var buffer = new byte[4096];
        while (deadline.Elapsed < TimeSpan.FromSeconds(1))
        {
            cancellation.ThrowIfCancellationRequested();
            var pollDescriptor = new PollDescriptor { Descriptor = descriptor.DangerousGetHandle().ToInt32(), Events = 1 };
            var polled = poll(ref pollDescriptor, 1, 50);
            if (polled < 0 && Marshal.GetLastPInvokeError() == 4) { continue; } // EINTR.
            if (polled < 0 || (pollDescriptor.ReturnedEvents & ~1) != 0) { throw Unavailable(); }
            if (polled == 0) { continue; }
            addressLength = AddressLength;
            var count = recvfrom(descriptor, buffer, (nuint)buffer.Length, MessageTruncate, out var sender, ref addressLength); // MSG_TRUNC.
            if (count < 0 && Marshal.GetLastPInvokeError() is 4 or 11) { continue; } // EINTR / EAGAIN.
            if (deadline.Elapsed >= TimeSpan.FromSeconds(1) || count < 0 || count > buffer.Length || addressLength != AddressLength ||
                sender.Family != AddressFamilyNetlink || sender.Port != 0 || sender.Groups != 0)
            { throw Unavailable(); }
            cancellation.ThrowIfCancellationRequested();
            return NftGenerationMessage.Decode(buffer.AsSpan(0, (int)count), sequence, local.Port);
        }
        throw Unavailable();
    }

    private static IOException Unavailable() => new("Cannot establish nftables transaction generation.");

    [StructLayout(LayoutKind.Sequential)]
    private struct NetlinkAddress { internal ushort Family; private ushort padding; internal uint Port; internal uint Groups; }
    [StructLayout(LayoutKind.Sequential)]
    private struct PollDescriptor { internal int Descriptor; internal short Events; internal short ReturnedEvents; }
    private sealed class NetlinkHandle : SafeHandleMinusOneIsInvalid
    {
        internal NetlinkHandle(int descriptor) : base(true) { SetHandle(descriptor); }
        protected override bool ReleaseHandle() => close(handle.ToInt32()) == 0;
    }

    [DllImport("libc", SetLastError = true)] private static extern int socket(int family, int type, int protocol);
    [DllImport("libc", SetLastError = true)] private static extern int bind(NetlinkHandle socket, ref NetlinkAddress address, uint length);
    [DllImport("libc", SetLastError = true)] private static extern int getsockname(NetlinkHandle socket, out NetlinkAddress address, ref uint length);
    [DllImport("libc", SetLastError = true)] private static extern nint sendto(NetlinkHandle socket, byte[] data, nuint length, int flags, ref NetlinkAddress address, uint addressLength);
    [DllImport("libc", SetLastError = true)] private static extern nint recvfrom(NetlinkHandle socket, [Out] byte[] data, nuint length, int flags, out NetlinkAddress address, ref uint addressLength);
    [DllImport("libc", SetLastError = true)] private static extern int poll(ref PollDescriptor descriptors, nuint count, int milliseconds);
    [DllImport("libc")] private static extern int close(int descriptor);
}
