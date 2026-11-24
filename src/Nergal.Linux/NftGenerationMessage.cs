using System.Buffers.Binary;

namespace Nergal.Linux;

// Public Linux wire ABI only. Keep decoding pure so malformed replies need no kernel access in tests.
internal static class NftGenerationMessage
{
    internal const ushort GetGeneration = 0x0a10;
    private const ushort NewGeneration = 0x0a0f;

    internal static byte[] Request(uint sequence, uint port)
    {
        var bytes = new byte[20];
        Write32(bytes, 20);
        Write16(bytes.AsSpan(4), GetGeneration);
        Write16(bytes.AsSpan(6), 1); // NLM_F_REQUEST, no multicast or acknowledgement subscription.
        Write32(bytes.AsSpan(8), sequence);
        Write32(bytes.AsSpan(12), port);
        return bytes;
    }

    internal static uint Decode(ReadOnlySpan<byte> bytes, uint sequence, uint port)
    {
        if (bytes.Length < 28 || Read32(bytes) != bytes.Length || Read16(bytes[4..]) != NewGeneration ||
            Read16(bytes[6..]) != 0 || Read32(bytes[8..]) != sequence || Read32(bytes[12..]) != port ||
            bytes[16] != 0 || bytes[17] != 0)
        { throw InvalidReply(); }

        uint? generation = null;
        var seenProcessId = false;
        var seenProcessName = false;
        for (var offset = 20; offset < bytes.Length;)
        {
            if (bytes.Length - offset < 4) { throw InvalidReply(); }
            var length = Read16(bytes[offset..]);
            var type = Read16(bytes[(offset + 2)..]);
            var aligned = (length + 3) & ~3;
            if (length < 4 || aligned > bytes.Length - offset) { throw InvalidReply(); }
            var value = bytes.Slice(offset + 4, length - 4);
            switch (type)
            {
                case 1 or 0x4001: // NFTA_GEN_ID, optional NLA_F_NET_BYTEORDER.
                    if (generation is not null || value.Length != 4) { throw InvalidReply(); }
                    generation = BinaryPrimitives.ReadUInt32BigEndian(value);
                    break;
                case 2 or 0x4002: // Optional diagnostic process identity is never authorization.
                    if (seenProcessId || value.Length != 4) { throw InvalidReply(); }
                    seenProcessId = true;
                    break;
                case 3:
                    if (seenProcessName || value.Length is < 1 or > 16 || value[^1] != 0 || value[..^1].Contains((byte)0))
                    { throw InvalidReply(); }
                    seenProcessName = true;
                    break;
                default: throw InvalidReply();
            }
            offset += aligned;
        }
        if (generation is null || BinaryPrimitives.ReadUInt16BigEndian(bytes[18..]) != (ushort)generation.Value)
        { throw InvalidReply(); }
        return generation.Value;
    }

    private static IOException InvalidReply() => new("Cannot establish nftables transaction generation.");
    private static ushort Read16(ReadOnlySpan<byte> bytes) => BitConverter.IsLittleEndian
        ? BinaryPrimitives.ReadUInt16LittleEndian(bytes) : BinaryPrimitives.ReadUInt16BigEndian(bytes);
    private static uint Read32(ReadOnlySpan<byte> bytes) => BitConverter.IsLittleEndian
        ? BinaryPrimitives.ReadUInt32LittleEndian(bytes) : BinaryPrimitives.ReadUInt32BigEndian(bytes);
    private static void Write16(Span<byte> bytes, ushort value)
    {
        if (BitConverter.IsLittleEndian) { BinaryPrimitives.WriteUInt16LittleEndian(bytes, value); }
        else { BinaryPrimitives.WriteUInt16BigEndian(bytes, value); }
    }
    private static void Write32(Span<byte> bytes, uint value)
    {
        if (BitConverter.IsLittleEndian) { BinaryPrimitives.WriteUInt32LittleEndian(bytes, value); }
        else { BinaryPrimitives.WriteUInt32BigEndian(bytes, value); }
    }
}
