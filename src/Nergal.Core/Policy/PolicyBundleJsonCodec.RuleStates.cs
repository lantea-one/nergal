using System.Text.Json;

namespace Nergal.Core.Policy;

public static partial class PolicyBundleJsonCodec
{
    private static bool TryReadEnabled(JsonElement element, out bool enabled, string property = "enabled")
    {
        enabled = true;
        if (!element.TryGetProperty(property, out var state)) { return true; }
        if (state.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) { return false; }
        enabled = state.GetBoolean(); return true;
    }
}
