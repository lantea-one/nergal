using System.Text.Json;
using System.Text.Json.Nodes;

namespace Nergal.Core.Policy;

public static partial class PolicyBundleJsonCodec
{
    private static bool TryReadBridgeRouterRule(JsonElement el, BridgeFilterRule initial, out BridgeFilterRule rule)
    {
        rule = initial;
        if (!TryReadAddressObjectsAndSets(el, out var sourcePrefixes, out var destinationPrefixes, out var sourceObject, out var destinationObject) ||
            !TryReadBool(el, "countPackets", out var countPackets) || !TryReadBool(el, "bindInputInterfaceIndex", out var bindIndex) ||
            !TryReadOptionalString(el, "bridgeName", out var bridge) || !TryReadOptionalString(el, "sourceMac", out var sm) ||
            !TryReadOptionalString(el, "destinationMac", out var dm) || !TryReadBool(el, "negateSourceMac", out var ns) ||
            !TryReadBool(el, "negateDestinationMac", out var nd) || !TryReadOptionalString(el, "source", out var source) ||
            !TryReadOptionalString(el, "destination", out var destination) || !TryReadOptionalInt(el, "destinationPort", out var port) ||
            !TryReadObjectReference(el, "destinationPortObject", out var portObject) || !TryReadOptionalString(el, "jumpTarget", out var target) || !TryReadBool(el, "return", out var ret)) { return false; }
        IpFamily? family = null;
        if (el.TryGetProperty("family", out var f) && f.ValueKind != JsonValueKind.Null)
        { family = ParseFamily(f); if (family is null) { return false; } }
        var protocol = el.TryGetProperty("protocol", out var proto) ? ParseProtocol(proto) : FilterProtocol.Any;
        if (protocol is null) { return false; }
        IReadOnlyList<int>? ports = null;
        if (el.TryGetProperty("destinationPorts", out var ps) && ps.ValueKind != JsonValueKind.Null && !TryParsePortList(ps, out ports)) { return false; }
        try
        {
            rule = initial with
            {
                CountPackets = countPackets,
                BindInputInterfaceIndex = bindIndex,
                BridgeName = bridge,
                SourceMac = sm is null ? null : new(sm),
                DestinationMac = dm is null ? null : new(dm),
                NegateSourceMac = ns,
                NegateDestinationMac = nd,
                Family = family,
                Source = source is null ? null : new(source),
                Destination = destination is null ? null : new(destination),
                Protocol = protocol.Value,
                DestinationPort = port,
                DestinationPorts = ports,
                DestinationPortObject = portObject,
                SourcePrefixes = sourcePrefixes,
                DestinationPrefixes = destinationPrefixes,
                SourceObject = sourceObject,
                DestinationObject = destinationObject,
                JumpTarget = target,
                Return = ret
            };
            return true;
        }
        catch (ArgumentException) { return false; }
    }

    private static bool TryReadBridgeSubChains(JsonElement el, out IReadOnlyList<BridgeSubChain> chains)
    {
        chains = [];
        if (!el.TryGetProperty("subChains", out var list)) { return true; }
        if (list.ValueKind != JsonValueKind.Array || list.GetArrayLength() > 32) { return false; }
        var result = new List<BridgeSubChain>();
        foreach (var item in list.EnumerateArray())
        {
            if (!HasOnlyProperties(item, "name", "rules") || !item.TryGetProperty("name", out var name) || name.ValueKind != JsonValueKind.String ||
                !item.TryGetProperty("rules", out var rules)) { return false; }
            var nested = new JsonObject { ["schemaVersion"] = 1, ["defaultVerdict"] = "drop", ["rules"] = JsonNode.Parse(rules.GetRawText()) };
            using var doc = JsonDocument.Parse(nested.ToJsonString());
            var decoded = TryParseBridgeElement(doc.RootElement);
            if (!decoded.IsSuccess) { return false; }
            result.Add(new(name.GetString()!, decoded.Value!.Rules));
        }
        chains = result.AsReadOnly();
        return true;
    }

    private static void WriteBridgeRouterRule(Utf8JsonWriter w, BridgeFilterRule r)
    {
        if (r.CountPackets) { w.WriteBoolean("countPackets", true); }
        if (r.BindInputInterfaceIndex) { w.WriteBoolean("bindInputInterfaceIndex", true); }
        if (r.BridgeName is not null) { w.WriteString("bridgeName", r.BridgeName); }
        if (r.SourceMac is not null) { w.WriteString("sourceMac", r.SourceMac.Value); }
        if (r.DestinationMac is not null) { w.WriteString("destinationMac", r.DestinationMac.Value); }
        if (r.NegateSourceMac) { w.WriteBoolean("negateSourceMac", true); }
        if (r.NegateDestinationMac) { w.WriteBoolean("negateDestinationMac", true); }
        if (r.Family is { } f) { w.WriteString("family", f == IpFamily.IPv4 ? "ipv4" : "ipv6"); }
        WritePrefixSet(w, "sourcePrefixes", r.SourcePrefixes);
        WritePrefixSet(w, "destinationPrefixes", r.DestinationPrefixes);
        WriteObjectReference(w, "sourceObject", r.SourceObject);
        WriteObjectReference(w, "destinationObject", r.DestinationObject);
        if (r.Source is not null) { w.WriteString("source", r.Source.Value); }
        if (r.Destination is not null) { w.WriteString("destination", r.Destination.Value); }
        if (r.Protocol != FilterProtocol.Any) { w.WriteString("protocol", ProtocolName(r.Protocol)); }
        if (r.DestinationPort is { } port) { w.WriteNumber("destinationPort", port); }
        if (r.DestinationPorts is { } ports)
        { w.WriteStartArray("destinationPorts"); foreach (var p in ports) { w.WriteNumberValue(p); } w.WriteEndArray(); }
        WriteObjectReference(w, "destinationPortObject", r.DestinationPortObject);
        if (r.JumpTarget is not null) { w.WriteString("jumpTarget", r.JumpTarget); }
        if (r.Return) { w.WriteBoolean("return", true); }
    }
}
