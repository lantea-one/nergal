using System.Text.Json;

namespace Nergal.Core.Policy;

public static partial class PolicyBundleJsonCodec
{
    private static bool TryReadPostroutingAddresses(JsonElement item, out IReadOnlyList<NetworkPrefix>? source,
        out IReadOnlyList<NetworkPrefix>? destination, out PolicyObjectReference? sourceObject, out PolicyObjectReference? destinationObject)
    {
        source = null; destination = null; sourceObject = null; destinationObject = null;
        return (!item.TryGetProperty("sourcePrefixes", out var s) || (s.ValueKind != JsonValueKind.Null && TryParsePrefixList(s, out source))) &&
            (!item.TryGetProperty("destinationPrefixes", out var d) || (d.ValueKind != JsonValueKind.Null && TryParsePrefixList(d, out destination))) &&
            TryReadObjectReference(item, "sourceObject", out sourceObject) && TryReadObjectReference(item, "destinationObject", out destinationObject);
    }

    private static void WritePostroutingAddresses(Utf8JsonWriter writer, SnatRule rule)
    {
        WritePrefixes("sourcePrefixes", rule.SourcePrefixes);
        WritePrefixes("destinationPrefixes", rule.DestinationPrefixes);
        WriteObjectReference(writer, "sourceObject", rule.SourceObject);
        WriteObjectReference(writer, "destinationObject", rule.DestinationObject);
        void WritePrefixes(string name, IReadOnlyList<NetworkPrefix>? prefixes)
        {
            if (prefixes is null) { return; }
            writer.WriteStartArray(name);
            foreach (var prefix in prefixes) { writer.WriteStringValue(prefix.Value); }
            writer.WriteEndArray();
        }
    }
}
