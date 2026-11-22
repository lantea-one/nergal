using System.Text.Json;
using Nergal.Core.Controller;

namespace Nergal.Core.Policy;

public static partial class PolicyBundleJsonCodec
{
    private static bool TryReadObjectReference(JsonElement rule, string property, out PolicyObjectReference? reference)
    {
        reference = null;
        if (!rule.TryGetProperty(property, out var el)) { return true; }
        if (el.ValueKind != JsonValueKind.Object || HasDuplicateProperties(el) ||
            !HasOnlyProperties(el, "id", "version", "name", "kind", "description", "entries", "digest") ||
            !el.TryGetProperty("id", out var idEl) || idEl.ValueKind != JsonValueKind.String ||
            !Guid.TryParseExact(idEl.GetString(), "D", out var id) || id.ToString("D") != idEl.GetString() ||
            !el.TryGetProperty("version", out var verEl) || verEl.ValueKind != JsonValueKind.Number || !verEl.TryGetInt32(out var version) ||
            !el.TryGetProperty("name", out var name) || name.ValueKind != JsonValueKind.String ||
            !el.TryGetProperty("kind", out var kindEl) || kindEl.ValueKind != JsonValueKind.String ||
            !el.TryGetProperty("description", out var description) || description.ValueKind != JsonValueKind.String ||
            !el.TryGetProperty("entries", out var entries) || entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() is < 1 or > ReusableObjectContent.MaximumEntries ||
            !el.TryGetProperty("digest", out var digest) || digest.ValueKind != JsonValueKind.String) { return false; }
        var kind = kindEl.GetString() switch { "ipv4" => (ReusableObjectKind?)ReusableObjectKind.Ipv4, "ipv6" => ReusableObjectKind.Ipv6, "port" => ReusableObjectKind.Port, _ => null };
        if (kind is null || entries.EnumerateArray().Any(e => e.ValueKind != JsonValueKind.String)) { return false; }
        try
        {
            var content = new ReusableObjectContent(name.GetString()!, kind.Value, description.GetString()!, entries.EnumerateArray().Select(e => e.GetString()!));
            if (content.Digest != digest.GetString()) { return false; }
            reference = new(id, version, content); return true;
        }
        catch (ArgumentException) { return false; }
    }
    private static void WriteObjectReference(Utf8JsonWriter writer, string property, PolicyObjectReference? reference)
    {
        if (reference is null) { return; }
        writer.WriteStartObject(property); writer.WriteString("id", reference.Id.ToString("D")); writer.WriteNumber("version", reference.Version);
        writer.WriteString("name", reference.Content.Name);
        writer.WriteString("kind", reference.Content.Kind switch { ReusableObjectKind.Ipv4 => "ipv4", ReusableObjectKind.Ipv6 => "ipv6", _ => "port" });
        writer.WriteString("description", reference.Content.Description);
        writer.WriteStartArray("entries"); foreach (var entry in reference.Content.Entries) { writer.WriteStringValue(entry); }
        writer.WriteEndArray();
        writer.WriteString("digest", reference.Content.Digest); writer.WriteEndObject();
    }
}
