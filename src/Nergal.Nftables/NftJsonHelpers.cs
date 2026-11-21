using System.Globalization;
using System.Text.Json;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

internal static class NftJsonHelpers
{
    internal static bool Properties(JsonElement element, params string[] names) =>
        element.ValueKind == JsonValueKind.Object &&
        element.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal)
            .SequenceEqual(names.Order(StringComparer.Ordinal));

    internal static bool HasDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name) || HasDuplicateProperties(property.Value))
                {
                    return true;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var value in element.EnumerateArray())
            {
                if (HasDuplicateProperties(value))
                {
                    return true;
                }
            }
        }

        return false;
    }

    internal static bool TryReadMetaHeader(JsonElement[] items)
    {
        if (items.Length < 1 || !Properties(items[0], "metainfo"))
        {
            return false;
        }

        var meta = items[0].GetProperty("metainfo");
        return Properties(meta, "version", "release_name", "json_schema_version") &&
            meta.GetProperty("version").ValueKind == JsonValueKind.String &&
            meta.GetProperty("release_name").ValueKind == JsonValueKind.String &&
            meta.GetProperty("json_schema_version").ValueKind == JsonValueKind.Number &&
            meta.GetProperty("json_schema_version").TryGetInt32(out var version) &&
            version == 1;
    }

    internal static NetworkPrefix? ParseNetworkPrefix(JsonElement right, IpFamily family)
    {
        var maxPrefixLength = family == IpFamily.IPv4 ? 32 : 128;
        string candidate;
        if (right.ValueKind == JsonValueKind.String)
        {
            var address = right.GetString();
            if (string.IsNullOrEmpty(address) || address.Contains('/', StringComparison.Ordinal))
            {
                return null;
            }

            candidate = address + "/" + maxPrefixLength.ToString(CultureInfo.InvariantCulture);
        }
        else if (right.ValueKind == JsonValueKind.Object && Properties(right, "prefix"))
        {
            var prefix = right.GetProperty("prefix");
            if (!Properties(prefix, "addr", "len") ||
                prefix.GetProperty("addr").ValueKind != JsonValueKind.String ||
                prefix.GetProperty("len").ValueKind != JsonValueKind.Number ||
                !prefix.GetProperty("len").TryGetInt32(out var length) ||
                length < 0 || length >= maxPrefixLength)
            {
                return null;
            }

            var address = prefix.GetProperty("addr").GetString();
            if (string.IsNullOrEmpty(address) || address.Contains('/', StringComparison.Ordinal))
            {
                return null;
            }

            candidate = address + "/" + length.ToString(CultureInfo.InvariantCulture);
        }
        else
        {
            return null;
        }

        try
        {
            var parsed = new NetworkPrefix(candidate);
            return parsed.Family == family && parsed.Value == candidate ? parsed : null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}
