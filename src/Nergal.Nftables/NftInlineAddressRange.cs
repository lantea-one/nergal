using System.Globalization;
using System.Net;
using System.Text.Json;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

// nft renders adjacent CIDRs as one interval in anonymous sets. Recover the
// unique minimal prefix cover without accepting unbounded expansion.
internal static class NftInlineAddressRange
{
    internal static bool TryAppend(JsonElement range, IpFamily family, List<NetworkPrefix> destination)
    {
        if (range.ValueKind != JsonValueKind.Array || range.GetArrayLength() != 2 ||
            !TryEndpoint(range[0], family, out var start) || !TryEndpoint(range[1], family, out var end) ||
            start >= end) { return false; }

        var width = family == IpFamily.IPv4 ? 32 : 128;
        while (true)
        {
            if (destination.Count == 64) { return false; }
            var bits = 0;
            UInt128 mask = 0;
            while (bits < width)
            {
                var largerMask = (mask << 1) | 1;
                if ((start & largerMask) != 0 || (start | largerMask) > end) { break; }
                mask = largerMask;
                bits++;
            }

            var address = ToAddress(start, width / 8);
            destination.Add(new NetworkPrefix(address + "/" + (width - bits).ToString(CultureInfo.InvariantCulture)));
            var last = start | mask;
            if (last == end) { return true; }
            start = last + 1;
        }
    }

    private static bool TryEndpoint(JsonElement value, IpFamily family, out UInt128 result)
    {
        result = 0;
        if (value.ValueKind != JsonValueKind.String ||
            !FilterPolicyValidation.TryParseSingleIpAddress(value.GetString(), out var address, out var actualFamily, out _) ||
            actualFamily != family) { return false; }
        foreach (var octet in address.GetAddressBytes()) { result = (result << 8) | octet; }
        return true;
    }

    private static IPAddress ToAddress(UInt128 value, int length)
    {
        Span<byte> bytes = stackalloc byte[length];
        for (var index = length - 1; index >= 0; index--)
        {
            bytes[index] = (byte)(value & 0xff);
            value >>= 8;
        }
        return new(bytes);
    }
}
