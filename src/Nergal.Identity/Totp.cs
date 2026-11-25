using System.Buffers.Binary;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Nergal.Identity;

internal static class Totp
{
    internal const int SeedLength = 20;

    // A 160-bit random seed encodes as exactly 32 Base32 characters, without padding.
    internal static string ManualKey(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != SeedLength) { throw new ArgumentException("Invalid TOTP seed length.", nameof(seed)); }
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        Span<char> key = stackalloc char[32];
        int buffer = 0, bits = 0, index = 0;
        foreach (var octet in seed)
        {
            buffer = (buffer << 8) | octet;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                key[index++] = alphabet[(buffer >> bits) & 31];
            }
        }
        return new string(key);
    }

    internal static long? Match(ReadOnlySpan<byte> seed, string? code, DateTimeOffset now, long lastStep, bool enrollment)
    {
        if (seed.Length != SeedLength || code is not { Length: 6 } || !code.All(char.IsAsciiDigit) ||
            now < DateTimeOffset.UnixEpoch) { return null; }
        var step = now.ToUnixTimeSeconds() / 30;
        // Enrollment requires the current step. Sign-in tolerates one step of drift in either direction.
        var drift = enrollment ? 0 : 1;
        long? accepted = null;
        Span<byte> counter = stackalloc byte[8];
        Span<byte> mac = stackalloc byte[20];
        Span<char> digits = stackalloc char[6];
        for (var candidate = Math.Max(step - drift, 0); candidate <= step + drift; candidate++)
        {
            BinaryPrimitives.WriteInt64BigEndian(counter, candidate);
            HMACSHA1.HashData(seed, counter, mac);
            var offset = mac[^1] & 15;
            var truncated = BinaryPrimitives.ReadUInt32BigEndian(mac[offset..]) & 0x7fffffff;
            (truncated % 1_000_000).TryFormat(digits, out _, "D6", CultureInfo.InvariantCulture);
            if (CryptographicOperations.FixedTimeEquals(MemoryMarshal.AsBytes((ReadOnlySpan<char>)digits),
                MemoryMarshal.AsBytes(code.AsSpan())) && candidate > lastStep)
            { accepted = candidate; }
        }
        return accepted;
    }
}
