using System.Buffers.Binary;

namespace Nergal.Core.Agent;

/// <summary>Pure bounded big-endian framing; stream/socket I/O and deadlines belong to transport.</summary>
public static class AgentStatusFrame
{
    /// <summary>Fixed unsigned big-endian payload-length header size.</summary>
    public const int HeaderLength = 4;

    /// <summary>Encodes a fresh frame without retaining caller-owned payload memory.</summary>
    /// <exception cref="StatusFrameException">Payload is empty or exceeds the protocol limit.</exception>
    public static byte[] Encode(ReadOnlySpan<byte> payload)
    {
        if (payload.Length is < 1 or > AgentStatusCodec.MaximumPayloadLength)
        {
            throw new StatusFrameException("frame.length");
        }

        var frame = new byte[HeaderLength + payload.Length];
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)payload.Length);
        payload.CopyTo(frame.AsSpan(HeaderLength));
        return frame;
    }

    /// <summary>Validates a complete header before a transport allocates a payload buffer.</summary>
    /// <exception cref="StatusFrameException">Header is incomplete or its length is unsupported.</exception>
    public static int ReadPayloadLength(ReadOnlySpan<byte> header)
    {
        if (header.Length != HeaderLength)
        {
            throw new StatusFrameException("frame.header");
        }

        var length = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (length is < 1 or > AgentStatusCodec.MaximumPayloadLength)
        {
            throw new StatusFrameException("frame.length");
        }

        return (int)length;
    }

    /// <summary>Validates exact frame extent, including rejection of extra/truncated data, and returns a caller-owned payload snapshot.</summary>
    /// <exception cref="StatusFrameException">Header, length or exact frame extent is invalid.</exception>
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

/// <summary>Stable framing failure without payload or peer data.</summary>
public sealed class StatusFrameException : Exception
{
    internal StatusFrameException(string code) : base(code) => Code = code;
    /// <summary>Gets the stable framing diagnostic identifier.</summary>
    public string Code { get; }
}
