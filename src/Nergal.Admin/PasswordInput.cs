using Microsoft.Win32.SafeHandles;
using System.Security.Cryptography;
using System.Text;

namespace Nergal.Admin;

internal static class PasswordInput
{
    // Identity accepts at most 128 Unicode scalars (up to four UTF-8 bytes per scalar).
    internal static async Task<string> ReadPipeAsync(Stream input)
    {
        var buffer = new byte[515]; // Includes an optional CRLF and one overflow sentinel.
        var length = 0;
        try
        {
            while (length < buffer.Length)
            {
                var read = await input.ReadAsync(buffer.AsMemory(length));
                if (read == 0)
                {
                    if (length > 0 && buffer[length - 1] == 10)
                    {
                        length--;
                        if (length > 0 && buffer[length - 1] == 13) { length--; }
                    }
                    if (length > 512 || buffer.AsSpan(0, length).IndexOfAny((byte)10, (byte)13) >= 0)
                    { throw new InvalidDataException(); }
                    return new UTF8Encoding(false, true).GetString(buffer, 0, length);
                }
                length += read;
            }
            throw new InvalidDataException();
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    internal static string ReadConfirmed()
    {
        // Disable echo before displaying even the first prompt. Intercepting
        // individual keystrokes leaves a race when a password is pasted.
        using var terminal = HiddenTerminal.Open();
        // Console's interactive reader performs its own terminal editing/echo.
        // Read fd 0 directly under the captured kernel mode.
        using var descriptor = new SafeFileHandle(IntPtr.Zero, ownsHandle: false);
        using var input = new FileStream(descriptor, FileAccess.Read, bufferSize: 1);
        Console.Error.Write("New password: ");
        var password = ReadLine(input);
        Console.Error.Write("Confirm password: ");
        if (!string.Equals(password, ReadLine(input), StringComparison.Ordinal)) { throw new InvalidDataException(); }
        return password;
    }

    private static string ReadLine(Stream input)
    {
        var bytes = new byte[512];
        var count = 0;
        var overflow = false;
        try
        {
            while (true)
            {
                var value = input.ReadByte();
                if (value < 0) { throw new InvalidDataException(); }
                if (value == 10)
                {
                    if (overflow) { throw new InvalidDataException(); }
                    return new UTF8Encoding(false, true).GetString(bytes, 0, count);
                }
                if (count < bytes.Length) { bytes[count++] = (byte)value; }
                else { overflow = true; }
            }
        }
        finally { CryptographicOperations.ZeroMemory(bytes); Console.Error.WriteLine(); }
    }
}
