using System.Buffers.Binary;

namespace Nergal.Core.Agent;

/// <summary>Pure bounded big-endian framing for authenticated agent control messages.</summary>
public static class AgentControlFrame
{
    /// <summary>Fixed unsigned big-endian payload-length header size.</summary>
    public const int HeaderLength = 4;

    /// <summary>Encodes a fresh control frame without retaining caller-owned memory.</summary>
    /// <exception cref="StatusFrameException">Payload is empty or exceeds <see cref="AgentControlCodec.MaximumPayloadLength"/>.</exception>
    public static byte[] Encode(ReadOnlySpan<byte> payload)
    {
        if (payload.Length is < 1 or > AgentControlCodec.MaximumPayloadLength)
        {
            throw new StatusFrameException("frame.length");
        }

        var frame = new byte[HeaderLength + payload.Length];
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)payload.Length);
        payload.CopyTo(frame.AsSpan(HeaderLength));
        return frame;
    }

    /// <summary>Validates a complete header before allocating a payload buffer.</summary>
    /// <exception cref="StatusFrameException">Header length or declared size is invalid.</exception>
    public static int ReadPayloadLength(ReadOnlySpan<byte> header)
    {
        if (header.Length != HeaderLength)
        {
            throw new StatusFrameException("frame.header");
        }

        var length = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (length is < 1 or > AgentControlCodec.MaximumPayloadLength)
        {
            throw new StatusFrameException("frame.length");
        }

        return (int)length;
    }

    /// <summary>Validates exact frame extent and returns a caller-owned payload snapshot.</summary>
    /// <exception cref="StatusFrameException">Header, payload size, or extent mismatches.</exception>
    public static byte[] Decode(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < HeaderLength)
        {
            throw new StatusFrameException("frame.header");
        }

        var length = ReadPayloadLength(frame[..HeaderLength]);
        if (frame.Length != HeaderLength + length)
        {
            throw new StatusFrameException("frame.extent");
        }

        return frame[HeaderLength..].ToArray();
    }
}
