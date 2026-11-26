using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Nergal.Core.Controller;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;
using static Nergal.Nftables.NftJsonHelpers;

namespace Nergal.Nftables;

// Expand only recognized immutable lookups for the strict existing rule validators.
// The additional fingerprint retains object identity and lookup edges, never just the expanded values.
internal sealed class NftStaticSetSnapshot
{
    private sealed record Definition(string Name, ulong Handle, PolicyObjectReference Reference);
    private readonly SortedDictionary<string, Definition> definitions = new(StringComparer.Ordinal);
    private readonly SortedDictionary<ulong, Dictionary<string, string>> uses = [];
    internal string Json { get; private set; } = "";
    internal bool IsEmpty => definitions.Count == 0;
    internal static NftStaticSetSnapshot Expand(string json, string family, string table, bool echo)
    {
        var root = ReadRoot(json);
        var result = new NftStaticSetSnapshot { Json = json };
        var entries = new Dictionary<string, List<JsonNode?>>(StringComparer.Ordinal);
        var definitionHandles = new Dictionary<string, ulong>(StringComparer.Ordinal);
        var retained = new JsonArray();
        foreach (var item in root["nftables"]!.AsArray())
        {
            if (item is not JsonObject) { throw Invalid(); }
            var inner = echo ? item["add"] : item;
            if (inner?["set"] is JsonObject set && set["name"]?.GetValue<string>() is { } name && name.StartsWith("nergal_obj_", StringComparison.Ordinal))
            {
                RequireProperties(item.AsObject(), echo ? "add" : "set");
                if (echo) { RequireProperties(inner!.AsObject(), "set"); }
                ValidateDefinition(set, family, table, !echo);
                if (!entries.TryAdd(name, [])) { throw Invalid(); }
                if (set["elem"] is JsonArray elements) { entries[name].AddRange(elements.Select(e => e?.DeepClone())); }
                // Contents are complete only after all separate echo element records have been read.
                definitionHandles.Add(name, Required<ulong>(set["handle"]));
                continue;
            }
            if (echo && inner?["element"] is JsonObject element)
            {
                RequireProperties(item.AsObject(), "add");
                RequireProperties(inner.AsObject(), "element");
                RequireProperties(element, "family", "table", "name", "elem");
                Scope(element, family, table);
                var elementName = Required<string>(element["name"]);
                if (!entries.TryGetValue(elementName, out var values) || element["elem"] is not JsonObject valueSet) { throw Invalid(); }
                RequireProperties(valueSet, "set");
                if (valueSet["set"] is not JsonArray elements) { throw Invalid(); }
                values.AddRange(elements.Select(e => e?.DeepClone()));
                if (values.Count > ReusableObjectContent.MaximumEntries) { throw Invalid(); }
                continue;
            }
            retained.Add(item?.DeepClone());
        }
        if (entries.Count == 0) { return result; }
        if (entries.Count > 64) { throw Invalid(); }
        foreach (var (name, values) in entries)
        {
            var reference = Reference(name, values);
            if (reference.Content.Kind != ReusableObjectKind.Port && reference.Content.Entries.Count > 1)
            {
                var diagnostics = new List<PolicyDiagnostic>();
                NftFilterCompiler.ValidatePrefixSet(reference.Content.Entries.Select(e => new NetworkPrefix(e)).ToArray(),
                    reference.Content.Kind == ReusableObjectKind.Ipv4 ? IpFamily.IPv4 : IpFamily.IPv6, "objects", diagnostics);
                if (diagnostics.Count > 0) { throw Invalid(); }
            }
            result.definitions.Add(name, new(name, definitionHandles[name], reference));
        }
        if (result.definitions.Values.GroupBy(d => (d.Reference.Id, d.Reference.Version)).Any(g => g.Select(d => d.Reference.Content.Digest).Distinct(StringComparer.Ordinal).Count() != 1)) { throw Invalid(); }
        var staticHandles = result.definitions.Values.Select(d => d.Handle).ToHashSet();
        if (staticHandles.Count != result.definitions.Count) { throw Invalid(); }
        foreach (var item in retained)
        {
            var inner = echo ? item?["add"] : item;
            // nft handles are shared by chains, sets and rules within a table; the table has a separate handle space.
            foreach (var kind in new[] { "chain", "rule", "set" })
            {
                if (inner?[kind] is JsonObject obj && obj["handle"] is JsonValue h && staticHandles.Contains(h.GetValue<ulong>())) { throw Invalid(); }
            }
            if (inner?["rule"] is not JsonObject rule) { continue; }
            if (rule["expr"] is not JsonArray expressions) { throw Invalid(); }
            foreach (var expr in expressions)
            {
                if (expr?["match"] is not JsonObject match || match["right"] is not JsonValue right || !right.TryGetValue<string>(out var token) || !token.StartsWith('@')) { continue; }
                if (!result.definitions.TryGetValue(token[1..], out var definition) || Required<string>(rule["chain"]) is "rpfilter" or "raw_output") { throw Invalid(); }
                var payload = match["left"]?["payload"] as JsonObject;
                if (payload is null) { throw Invalid(); }
                RequireProperties(payload, "protocol", "field");
                var protocol = Required<string>(payload["protocol"]);
                var field = Required<string>(payload["field"]);
                var kind = definition.Reference.Content.Kind;
                var slot = (protocol, field) switch
                {
                    ("ip", "saddr") when kind == ReusableObjectKind.Ipv4 => "source",
                    ("ip6", "saddr") when kind == ReusableObjectKind.Ipv6 => "source",
                    ("ip", "daddr") when kind == ReusableObjectKind.Ipv4 => "destination",
                    ("ip6", "daddr") when kind == ReusableObjectKind.Ipv6 => "destination",
                    ("tcp" or "udp", "dport") when kind == ReusableObjectKind.Port => "port",
                    _ => throw Invalid()
                };
                var handle = Required<ulong>(rule["handle"]);
                if (!result.uses.TryGetValue(handle, out var slots)) { result.uses.Add(handle, slots = new(StringComparer.Ordinal)); }
                if (!slots.TryAdd(slot, definition.Name)) { throw Invalid(); }
                var literals = definition.Reference.Content.Entries.Select(e => Literal(e, kind)).ToArray();
                match["right"] = literals.Length == 1 ? literals[0] : new JsonObject { ["set"] = new JsonArray(literals) };
            }
        }
        if (result.definitions.Keys.Except(result.uses.Values.SelectMany(s => s.Values), StringComparer.Ordinal).Any()) { throw Invalid(); }
        root["nftables"] = retained;
        result.Json = root.ToJsonString();
        return result;
    }
    internal CandidateDigest Bind(CandidateDigest literalDigest)
    {
        if (IsEmpty) { return literalDigest; }
        var text = new StringBuilder("nergal-native-static-sets-v1\n").Append(literalDigest.Value);
        foreach (var definition in definitions.Values)
        {
            text.Append('\n').Append(definition.Name).Append(' ').Append(definition.Handle.ToString(CultureInfo.InvariantCulture))
                .Append(' ').Append(NftStaticSetPlan.Type(definition.Reference.Content.Kind)).Append(" constant")
                .Append(definition.Reference.Content.Kind == ReusableObjectKind.Port ? " " : ",interval ")
                .Append(string.Join(',', definition.Reference.Content.Entries));
        }
        foreach (var (handle, slots) in uses)
        {
            foreach (var (slot, name) in slots.OrderBy(s => s.Key, StringComparer.Ordinal))
            { text.Append('\n').Append(handle.ToString(CultureInfo.InvariantCulture)).Append(' ').Append(slot).Append(' ').Append(name); }
        }
        return CandidateDigest.FromText(text.ToString());
    }
    private PolicyObjectReference? At(ulong handle, string slot) => uses.TryGetValue(handle, out var slots) && slots.TryGetValue(slot, out var name) ? definitions[name].Reference : null;
    internal FilterRule Restore(ulong handle, FilterRule r) => r with
    {
        SourceObject = At(handle, "source"),
        Source = At(handle, "source") is null ? r.Source : null,
        SourcePrefixes = At(handle, "source") is null ? r.SourcePrefixes : null,
        DestinationObject = At(handle, "destination"),
        Destination = At(handle, "destination") is null ? r.Destination : null,
        DestinationPrefixes = At(handle, "destination") is null ? r.DestinationPrefixes : null,
        DestinationPortObject = At(handle, "port"),
        DestinationPort = At(handle, "port") is null ? r.DestinationPort : null,
        DestinationPorts = At(handle, "port") is null ? r.DestinationPorts : null
    };
    internal DnatRule Restore(ulong handle, DnatRule r) => r with
    {
        SourceObject = At(handle, "source"),
        Source = At(handle, "source") is null ? r.Source : null,
        SourcePrefixes = At(handle, "source") is null ? r.SourcePrefixes : null,
        DestinationObject = At(handle, "destination"),
        OriginalDestination = At(handle, "destination") is null ? r.OriginalDestination : null,
        DestinationPrefixes = At(handle, "destination") is null ? r.DestinationPrefixes : null,
        OriginalPortObject = At(handle, "port"),
        OriginalPort = At(handle, "port") is null ? r.OriginalPort : null,
        OriginalPorts = At(handle, "port") is null ? r.OriginalPorts : null
    };
    internal SnatRule Restore(ulong handle, SnatRule r) => r with
    {
        SourceObject = At(handle, "source"),
        Source = At(handle, "source") is null ? r.Source : null,
        SourcePrefixes = At(handle, "source") is null ? r.SourcePrefixes : null,
        DestinationObject = At(handle, "destination"),
        Destination = At(handle, "destination") is null ? r.Destination : null,
        DestinationPrefixes = At(handle, "destination") is null ? r.DestinationPrefixes : null,
        DestinationPortObject = At(handle, "port"),
        DestinationPort = At(handle, "port") is null ? r.DestinationPort : null,
        DestinationPorts = At(handle, "port") is null ? r.DestinationPorts : null
    };
    internal BridgeFilterRule Restore(ulong handle, BridgeFilterRule r) => r with
    {
        SourceObject = At(handle, "source"),
        Source = At(handle, "source") is null ? r.Source : null,
        SourcePrefixes = At(handle, "source") is null ? r.SourcePrefixes : null,
        DestinationObject = At(handle, "destination"),
        Destination = At(handle, "destination") is null ? r.Destination : null,
        DestinationPrefixes = At(handle, "destination") is null ? r.DestinationPrefixes : null,
        DestinationPortObject = At(handle, "port"),
        DestinationPort = At(handle, "port") is null ? r.DestinationPort : null,
        DestinationPorts = At(handle, "port") is null ? r.DestinationPorts : null
    };
    internal static JsonObject ReadRoot(string json)
    {
        if (new UTF8Encoding(false, true).GetByteCount(json) > 65536) { throw Invalid(); }
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
        if (HasDuplicateProperties(document.RootElement) || !Properties(document.RootElement, "nftables") || document.RootElement.GetProperty("nftables").ValueKind != JsonValueKind.Array) { throw Invalid(); }
        return JsonNode.Parse(json)!.AsObject();
    }
    internal static void ValidateDefinition(JsonObject set, string family, string table, bool complete)
    {
        if (complete) { RequireProperties(set, "family", "table", "name", "handle", "type", "flags", "elem"); }
        else if (set.ContainsKey("elem")) { RequireProperties(set, "family", "table", "name", "handle", "type", "flags", "elem"); }
        else { RequireProperties(set, "family", "table", "name", "handle", "type", "flags"); }
        Scope(set, family, table);
        if (!NftStaticSetPlan.TryIdentity(Required<string>(set["name"]), out _, out _, out var kind) || Required<ulong>(set["handle"]) == 0 ||
            Required<string>(set["type"]) != NftStaticSetPlan.Type(kind)) { throw Invalid(); }
        var expectedFlags = kind == ReusableObjectKind.Port ? new[] { "constant" } : new[] { "constant", "interval" };
        if (set["flags"] is not JsonArray flags || !flags.Select(f => Required<string>(f)).Order(StringComparer.Ordinal).SequenceEqual(expectedFlags.Order(StringComparer.Ordinal))) { throw Invalid(); }
        if (set.ContainsKey("elem") && (set["elem"] is not JsonArray elements || elements.Count is < 1 or > ReusableObjectContent.MaximumEntries)) { throw Invalid(); }
    }
    internal static PolicyObjectReference Reference(string name, IEnumerable<JsonNode?> elements)
    {
        if (!NftStaticSetPlan.TryIdentity(name, out var id, out var version, out var kind)) { throw Invalid(); }
        var entries = elements.Select(e =>
        {
            if (e is null) { throw Invalid(); }
            var json = JsonSerializer.SerializeToElement(e);
            if (kind == ReusableObjectKind.Port)
            { if (json.ValueKind != JsonValueKind.Number || !json.TryGetInt32(out var port) || port is < 1 or > 65535) { throw Invalid(); } return port.ToString(CultureInfo.InvariantCulture); }
            return ParseNetworkPrefix(json, kind == ReusableObjectKind.Ipv4 ? IpFamily.IPv4 : IpFamily.IPv6)?.Value ?? throw Invalid();
        }).ToArray();
        return new(id, version, new ReusableObjectContent("observed_" + id.ToString("N"), kind, "", entries), true);
    }
    private static JsonNode Literal(string entry, ReusableObjectKind kind)
    {
        if (kind == ReusableObjectKind.Port) { return JsonValue.Create(int.Parse(entry, CultureInfo.InvariantCulture))!; }
        var prefixLength = int.Parse(entry.Split('/')[1], CultureInfo.InvariantCulture);
        if (prefixLength == (kind == ReusableObjectKind.Ipv4 ? 32 : 128)) { return JsonValue.Create(entry.Split('/')[0])!; }
        return new JsonObject { ["prefix"] = new JsonObject { ["addr"] = entry.Split('/')[0], ["len"] = prefixLength } };
    }
    internal static void Scope(JsonObject obj, string family, string table)
    {
        if (obj["family"]?.GetValue<string>() != family || obj["table"]?.GetValue<string>() != table) { throw Invalid(); }
    }
    internal static void RequireProperties(JsonObject obj, params string[] names)
    { if (!obj.Select(p => p.Key).Order(StringComparer.Ordinal).SequenceEqual(names.Order(StringComparer.Ordinal))) { throw Invalid(); } }
    private static T Required<T>(JsonNode? node) => node is JsonValue value && value.TryGetValue<T>(out var result) ? result : throw Invalid();
    internal static ArgumentException Invalid() => new("observation.nativeStaticSet");
}
