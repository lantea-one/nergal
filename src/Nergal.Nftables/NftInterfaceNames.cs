using System.Text;
using System.Text.Json;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

internal static class NftInterfaceNames
{
    // Callers validate scalar names and exclude simultaneous scalar/selector inputs before generation.
    internal static void Append(StringBuilder text, string key, string? scalar, InterfaceNameSelector? selector, bool negate)
    {
        if (scalar is null && selector is null) { return; }
        text.Append(key).Append(negate ? " != " : " ");
        if (selector is null) { text.Append('"').Append(scalar).Append('"'); }
        else
        {
            if (selector.Patterns.Count > 1) { text.Append("{ "); }
            text.AppendJoin(", ", selector.Patterns.Select(p => $"\"{p.Value}\""));
            if (selector.Patterns.Count > 1) { text.Append(" }"); }
        }
        text.Append(' ');
    }

    internal static string Projection(string? scalar, InterfaceNameSelector? selector) =>
        selector is null ? scalar ?? "-" : string.Join(",", selector.Patterns.Select(p => p.Value));

    internal static bool TryRead(JsonElement value, out string? exactName, out InterfaceNameSelector? selector)
    {
        exactName = null;
        selector = null;
        if (value.ValueKind == JsonValueKind.String)
        {
            var name = value.GetString();
            if (FilterPolicyValidation.IsValidInterfaceName(name)) { exactName = name; return true; }
            selector = InterfaceNameSelector.Create([name]);
        }
        else if (NftJsonHelpers.Properties(value, "set") && value.GetProperty("set") is { ValueKind: JsonValueKind.Array } array &&
            array.GetArrayLength() is >= 2 and <= 64)
        {
            selector = InterfaceNameSelector.Create(array.EnumerateArray().Select(item =>
                item.ValueKind == JsonValueKind.String ? item.GetString() : null));
        }
        return selector is not null;
    }
}
