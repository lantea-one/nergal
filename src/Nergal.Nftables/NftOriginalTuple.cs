using System.Text;
using System.Text.Json;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

/// <summary>Shared native contract for positive, family-specific original addresses on DNAT connections.</summary>
internal static class NftOriginalTuple
{
    internal static void ValidateOriginalPrefixes(IReadOnlyList<NetworkPrefix>? prefixes, IpFamily family,
        bool matchOriginalDestinationDnat, string path, List<PolicyDiagnostic> errors)
    {
        if (prefixes is null) { return; }
        if (!matchOriginalDestinationDnat) { errors.Add(new("ct.originalTupleRequiresDnat", path)); }
        if (prefixes.Count == 1)
        {
            if (prefixes[0] is null) { errors.Add(new("set.nullElement", path + "[0]")); }
            else if (prefixes[0].Family != family) { errors.Add(new("network.familyMismatch", path + "[0]")); }
            return;
        }
        NftFilterCompiler.ValidatePrefixSet(prefixes, family, path, errors);
    }

    internal static void AppendOriginalPrefixes(StringBuilder text, IpFamily family, string field, IReadOnlyList<NetworkPrefix>? prefixes)
    {
        if (prefixes is null) { return; }
        var key = AddressKey(family, field) ?? throw new InvalidOperationException("Expected a validated original address selector.");
        text.Append("ct original ").Append(key).Append(' ');
        if (prefixes.Count == 1) { text.Append(prefixes[0].Value).Append(' '); }
        else { text.Append("{ ").Append(string.Join(", ", prefixes.Select(p => p.Value).Order(StringComparer.Ordinal))).Append(" } "); }
    }

    internal static bool IsDnatStatus(JsonElement expression) =>
        TryReadCtMatch(expression, "in", out var ct, out var right) && NftJsonHelpers.Properties(ct, "key") &&
        IsString(ct.GetProperty("key"), "status") && IsString(right, "dnat");

    /// <summary>Returns the family implied by a typed original-address key when nft elides a redundant nfproto match.</summary>
    internal static IpFamily? OriginalAddressFamily(JsonElement expression) =>
        TryReadOriginalAddress(expression, out var key, out _) ? key switch
        {
            "ip saddr" or "ip daddr" => IpFamily.IPv4,
            "ip6 saddr" or "ip6 daddr" => IpFamily.IPv6,
            _ => null
        } : null;

    /// <summary>Reads one optional selector and advances only on success. The caller must reject unconsumed expressions.</summary>
    internal static IReadOnlyList<NetworkPrefix>? ReadOriginalPrefixes(JsonElement expressions, ref int index, int end,
        IpFamily family, string field)
    {
        if (index >= end || !TryReadOriginalAddress(expressions[index], out var key, out var right) ||
            key != AddressKey(family, field)) { return null; }
        IReadOnlyList<NetworkPrefix>? prefixes;
        if (NftJsonHelpers.Properties(right, "set"))
        {
            prefixes = NftTableObservation.ParseNetworkPrefixSet(right.GetProperty("set"), family);
            if (prefixes is null) { return null; }
            var errors = new List<PolicyDiagnostic>();
            NftFilterCompiler.ValidatePrefixSet(prefixes, family, string.Empty, errors);
            if (errors.Count > 0) { return null; }
        }
        else
        {
            var prefix = NftJsonHelpers.ParseNetworkPrefix(right, family);
            if (prefix is null) { return null; }
            prefixes = [prefix];
        }
        index++;
        return prefixes;
    }

    private static string? AddressKey(IpFamily family, string field) => (family, field) switch
    {
        (IpFamily.IPv4, "saddr") => "ip saddr",
        (IpFamily.IPv4, "daddr") => "ip daddr",
        (IpFamily.IPv6, "saddr") => "ip6 saddr",
        (IpFamily.IPv6, "daddr") => "ip6 daddr",
        _ => null
    };

    private static bool TryReadOriginalAddress(JsonElement expression, out string? key, out JsonElement right)
    {
        key = null;
        if (!TryReadCtMatch(expression, "==", out var ct, out right) || !NftJsonHelpers.Properties(ct, "key", "dir") ||
            !IsString(ct.GetProperty("dir"), "original") || ct.GetProperty("key").ValueKind != JsonValueKind.String) { return false; }
        key = ct.GetProperty("key").GetString();
        return true;
    }

    private static bool TryReadCtMatch(JsonElement expression, string op, out JsonElement ct, out JsonElement right)
    {
        ct = right = default;
        if (!NftJsonHelpers.Properties(expression, "match")) { return false; }
        var match = expression.GetProperty("match");
        if (!NftJsonHelpers.Properties(match, "op", "left", "right") || !IsString(match.GetProperty("op"), op) ||
            !NftJsonHelpers.Properties(match.GetProperty("left"), "ct")) { return false; }
        ct = match.GetProperty("left").GetProperty("ct");
        right = match.GetProperty("right");
        return true;
    }

    private static bool IsString(JsonElement value, string expected) => value.ValueKind == JsonValueKind.String && value.ValueEquals(expected);
}
