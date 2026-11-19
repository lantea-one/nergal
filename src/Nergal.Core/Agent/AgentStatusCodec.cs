using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Nergal.Core.Agent;

/// <summary>Pure version-1 UTF-8 status JSON codec. Valid decoding is never peer authorization.</summary>
public static class AgentStatusCodec
{
    /// <summary>Maximum UTF-8 payload size, shared by JSON and frame validation.</summary>
    public const int MaximumPayloadLength = 4096;

    /// <summary>Encodes the sole known request into a fresh caller-owned byte array.</summary>
    public static byte[] EncodeRequest() => Encoding.UTF8.GetBytes("{\"schemaVersion\":1,\"command\":\"status\"}");

    /// <summary>Validates exact known request fields/values without retaining caller memory or invoking any provider.</summary>
    public static StatusRequestResult DecodeRequest(ReadOnlySpan<byte> payload)
    {
        if (payload.Length > MaximumPayloadLength)
        {
            return new("payload.tooLarge");
        }

        try
        {
            using var document = JsonDocument.Parse(payload.ToArray(), new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (Duplicates(root))
            {
                return new("request.duplicateProperty");
            }

            if (!Properties(root, "schemaVersion", "command"))
            {
                return new("request.fields");
            }

            if (!Version(root))
            {
                return new("request.version");
            }

            if (root.GetProperty("command").ValueKind != JsonValueKind.String || root.GetProperty("command").GetString() != "status")
            {
                return new("request.command");
            }

            return new(null);
        }
        catch (JsonException) { return new("request.invalidJson"); }
        catch (InvalidOperationException) { return new("request.invalidJson"); }
    }

    /// <summary>Encodes a typed reply; revision is a canonical decimal string to preserve all unsigned 64-bit values.</summary>
    /// <exception cref="ArgumentNullException">Reply is null.</exception>
    public static byte[] EncodeReply(AgentStatusReply reply)
    {
        ArgumentNullException.ThrowIfNull(reply);
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(buffer);
        writer.WriteStartObject();
        writer.WriteNumber("schemaVersion", 1);
        writer.WriteString("outcome", Name(reply.Outcome));
        if (reply.Revision is { } revision)
        {
            writer.WriteString("revision", revision.ToString(CultureInfo.InvariantCulture));
        }

        writer.WriteEndObject();
        writer.Flush();
        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>Parses a reply without accepting unknown fields/outcomes, lossy numbers or metadata in denial/error replies.</summary>
    public static StatusReplyResult DecodeReply(ReadOnlySpan<byte> payload)
    {
        if (payload.Length > MaximumPayloadLength)
        {
            return new(null, "payload.tooLarge");
        }

        try
        {
            using var document = JsonDocument.Parse(payload.ToArray(), new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (Duplicates(root))
            {
                return new(null, "reply.duplicateProperty");
            }

            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("outcome", out var outcome) || outcome.ValueKind != JsonValueKind.String)
            {
                return new(null, "reply.fields");
            }

            var name = outcome.GetString();
            var known = Enum.GetValues<AgentStatusOutcome>().Where(value => Name(value) == name).ToArray();
            if (known.Length != 1)
            {
                return new(null, "reply.outcome");
            }

            var resource = known[0] is AgentStatusOutcome.Matched or AgentStatusOutcome.Drift or AgentStatusOutcome.Unbound;
            if (!(resource ? Properties(root, "schemaVersion", "outcome", "revision") : Properties(root, "schemaVersion", "outcome")))
            {
                return new(null, "reply.fields");
            }

            if (!Version(root))
            {
                return new(null, "reply.version");
            }

            ulong? revision = null;
            if (resource)
            {
                var field = root.GetProperty("revision");
                if (field.ValueKind != JsonValueKind.String || !ulong.TryParse(field.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) ||
                    parsed == 0 || parsed.ToString(CultureInfo.InvariantCulture) != field.GetString())
                {
                    return new(null, "reply.revision");
                }

                revision = parsed;
            }
            return new(new(known[0], revision), null);
        }
        catch (JsonException) { return new(null, "reply.invalidJson"); }
        catch (InvalidOperationException) { return new(null, "reply.invalidJson"); }
    }

    private static string Name(AgentStatusOutcome outcome) => outcome switch
    {
        AgentStatusOutcome.Matched => "matched",
        AgentStatusOutcome.Drift => "drift",
        AgentStatusOutcome.Unbound => "unbound",
        AgentStatusOutcome.Unavailable => "unavailable",
        AgentStatusOutcome.Denied => "denied",
        AgentStatusOutcome.InvalidRequest => "invalidRequest",
        _ => throw new ArgumentOutOfRangeException(nameof(outcome)),
    };
    private static bool Version(JsonElement root) => root.GetProperty("schemaVersion").ValueKind == JsonValueKind.Number &&
        root.GetProperty("schemaVersion").TryGetInt32(out var version) && version == 1;
    private static bool Properties(JsonElement root, params string[] names) => root.ValueKind == JsonValueKind.Object &&
        root.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).SequenceEqual(names.Order(StringComparer.Ordinal));
    private static bool Duplicates(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!seen.Add(property.Name) || Duplicates(property.Value))
                {
                    return true;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var value in element.EnumerateArray())
            {
                if (Duplicates(value))
                {
                    return true;
                }
            }
        }

        return false;
    }
}

/// <summary>Known status intent or a stable denial; no caller fields or authority claims are retained.</summary>
public sealed class StatusRequestResult
{
    internal StatusRequestResult(string? errorCode) => ErrorCode = errorCode;
    /// <summary>Gets whether the exact status-only request contract was understood.</summary>
    public bool IsValid => ErrorCode is null;
    /// <summary>Gets a stable failure code without input contents.</summary>
    public string? ErrorCode { get; }
}

/// <summary>Complete typed reply or a stable denial, never partial metadata.</summary>
public sealed class StatusReplyResult
{
    internal StatusReplyResult(AgentStatusReply? reply, string? errorCode) { Reply = reply; ErrorCode = errorCode; }
    /// <summary>Gets the complete reply, or null on any failure.</summary>
    public AgentStatusReply? Reply { get; }
    /// <summary>Gets whether the reply contract was completely understood.</summary>
    public bool IsValid => Reply is not null;
    /// <summary>Gets a stable failure code without input contents.</summary>
    public string? ErrorCode { get; }
}
