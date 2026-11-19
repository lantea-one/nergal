using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Nergal.LocalTransport;

// Never construct authority from request JSON. SO_PEERCRED is read from the accepted kernel socket.
[SupportedOSPlatform("linux")]
internal static class UnixPeerCredentials
{
    internal static uint ReadUserId(Socket socket)
    {
        var held = false;
        try
        {
            socket.SafeHandle.DangerousAddRef(ref held);
            var length = (uint)Marshal.SizeOf<Credentials>();
            if (getsockopt(socket.SafeHandle.DangerousGetHandle().ToInt32(), 1, 17, out var credentials, ref length) != 0 ||
                length != Marshal.SizeOf<Credentials>())
            {
                throw new LocalTransportException("peer.unavailable");
            }

            return credentials.UserId;
        }
        finally
        {
            if (held)
            {
                socket.SafeHandle.DangerousRelease();
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Credentials
    {
        internal int ProcessId;
        internal uint UserId;
        internal uint GroupId;
    }
    [DllImport("libc", SetLastError = true)]
    private static extern int getsockopt(int socket, int level, int option, out Credentials credentials, ref uint length);
}
