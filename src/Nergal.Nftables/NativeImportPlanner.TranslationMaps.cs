using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using Nergal.Core.Controller;

namespace Nergal.Nftables;

public static partial class NativeImportPlanner
{
    private sealed record TranslationEntry(string Key, string Address);

    private sealed class StaticTranslationMap(string family, bool transportPortKey, IReadOnlyList<TranslationEntry> entries)
    {
        internal string Family { get; } = family;
        internal bool TransportPortKey { get; } = transportPortKey;
        internal IReadOnlyList<TranslationEntry> Entries { get; } = entries;
        internal bool Used { get; set; }
    }

    private sealed partial class Planner
    {
        private StaticTranslationMap ReadStaticTranslationMap(Term body, Scope scope)
        {
            string? keyType = null;
            string? targetType = null;
            Term[]? entries = null;
            var constant = false;
            foreach (var statement in NativeSourceDeclarationParser.Partition(body.Unit.Analysis.Lexical.Document!, body.Node.Children, false))
            {
                var terms = Expand(Terms(body.Unit, statement.Nodes), scope, 0);
                if (terms.Length == 0) { continue; }
                var first = terms[0];
                switch (first.Text)
                {
                    case "type":
                        Require(keyType is null && terms.Length == 4 && terms[2].Text == ":", first, "import.mapTypeUnsupported");
                        keyType = terms[1].Text;
                        targetType = terms[3].Text;
                        break;
                    case "elements":
                        Require(entries is null && terms.Length == 3 && terms[1].Text == "=" &&
                            terms[2].Node.Kind == NativeSourceNodeKind.Braces, first, "import.mapElementsUnsupported");
                        entries = Expand(terms[2].Children, scope, 0);
                        break;
                    case "flags":
                        Require(!constant && terms.Length == 2 && terms[1].Text == "constant", first, "import.mapOptionUnsupported");
                        constant = true;
                        break;
                    default: throw new ImportFailure("import.mapOptionUnsupported", first);
                }
            }

            Require(targetType is "ipv4_addr" or "ipv6_addr" && (keyType == "inet_service" || keyType == targetType),
                body, "import.mapTypeUnsupported");
            Require(entries is { Length: >= 3 and <= 255 } && entries.Length % 4 == 3, body, "import.mapElementsUnsupported");
            var ipv4 = targetType == "ipv4_addr";
            var addressField = ipv4 ? NativeRuleField.IpSource : NativeRuleField.Ip6Source;
            var portKey = keyType == "inet_service";
            var keys = new HashSet<string>(StringComparer.Ordinal);
            var pairs = new List<TranslationEntry>();
            for (var index = 0; index < entries!.Length; index += 4)
            {
                Require(entries[index + 1].Text == ":" && (index + 3 == entries.Length || entries[index + 3].Text == ","),
                    entries[index], "import.mapElementsUnsupported");
                var key = portKey
                    ? ((NativePortLiteral)Literal(NativeRuleField.TcpDestinationPort, entries[index])).Port.ToString(CultureInfo.InvariantCulture)
                    : ReadMapHost(entries[index], addressField, ipv4);
                Require(keys.Add(key), entries[index], "import.mapKeyDuplicate");
                pairs.Add(new(key, ReadMapHost(entries[index + 2], addressField, ipv4)));
            }
            return new(ipv4 ? "ipv4" : "ipv6", portKey, pairs.AsReadOnly());
        }

        private static string ReadMapHost(Term term, NativeRuleField field, bool ipv4)
        {
            Require(!term.Text.Contains('/'), term, "import.mapHostRequired");
            var prefix = ((NativeAddressLiteral)Literal(field, term)).Prefix.Value;
            return prefix[..^(ipv4 ? 3 : 4)];
        }

        private static void ReadTranslationMapSelector(Table table, Cursor cursor, RuleData rule, Term origin)
        {
            var selector = cursor.Take();
            var key = cursor.Take();
            cursor.Expect("map");
            var reference = cursor.Take();
            Require(reference.Kind == NativeSourceTokenKind.AtReference &&
                table.TranslationMaps.ContainsKey(reference.Text[1..]), reference, "import.mapUnresolved");
            var map = table.TranslationMaps[reference.Text[1..]];
            Require((rule.Family is null || rule.Family == map.Family) && !rule.Data.ContainsKey("countPackets") &&
                rule.Protocol != "tcpOrUdp" && rule.Alternatives.Count == 0, origin, "import.mapScopeUnsupported");
            if (map.TransportPortKey)
            {
                Require(rule.Action == "dnat" && selector.Text is "tcp" or "udp" && key.Text == "dport" &&
                    (rule.Protocol == "any" || rule.Protocol == selector.Text) && !rule.Data.ContainsKey("destinationPortObject"),
                    selector, "import.mapSelectorUnsupported");
                rule.Protocol = selector.Text;
            }
            else
            {
                Require(rule.Action == "snat" && selector.Text == (map.Family == "ipv4" ? "ip" : "ip6") &&
                    key.Text == "saddr" && !rule.Data.ContainsKey("source") && !rule.Data.ContainsKey("sourcePrefixes") &&
                    !rule.Data.ContainsKey("sourceObject"), selector, "import.mapSelectorUnsupported");
            }
            rule.Family = map.Family;
            rule.TranslationMap = map;
            map.Used = true;
        }

        private static IReadOnlyList<RuleData> ProjectTranslationMap(RuleData rule, Term origin)
        {
            if (rule.TranslationMap is not { } map) { return [rule]; }
            var result = new List<RuleData>(map.Entries.Count);
            if (map.TransportPortKey)
            {
                var eligible = map.Entries.Select(entry => (Port: int.Parse(entry.Key, CultureInfo.InvariantCulture), entry.Address))
                    .Where(entry => (rule.Data["destinationPort"] is not JsonValue scalar || scalar.GetValue<int>() == entry.Port) &&
                        (rule.Data["destinationPorts"] is not JsonArray set || set.Any(value => value!.GetValue<int>() == entry.Port)));
                foreach (var group in eligible.GroupBy(entry => entry.Address, StringComparer.Ordinal))
                {
                    var ports = group.Select(entry => entry.Port).Order().ToArray();
                    var projected = (JsonObject)rule.Data.DeepClone();
                    projected.Remove("destinationPort");
                    projected.Remove("destinationPorts");
                    if (ports.Length == 1) { projected["destinationPort"] = ports[0]; }
                    else { projected["destinationPorts"] = new JsonArray(ports.Select(port => (JsonNode?)JsonValue.Create(port)).ToArray()); }
                    Add(projected, group.Key);
                }
            }
            else
            {
                foreach (var entry in map.Entries)
                {
                    var projected = (JsonObject)rule.Data.DeepClone();
                    projected["source"] = entry.Key + (map.Family == "ipv4" ? "/32" : "/128");
                    Add(projected, entry.Address);
                }
            }
            Require(result.Count != 0, origin, "import.mapNeverMatches");
            return result;

            void Add(JsonObject projected, string address)
            {
                projected["translatedAddress"] = address;
                result.Add(new RuleData
                {
                    Data = projected,
                    Family = rule.Family,
                    Protocol = rule.Protocol,
                    Action = rule.Action,
                });
            }
        }

        // A DNAT-only regular chain leaves the packet unchanged until a
        // translation succeeds and terminates traversal of the base chain.
        // Intersecting each child rule with the pure jump guard preserves both
        // a successful translation and implicit return on a complete miss.
        private static RuleData? IntersectNatJump(RuleData guard, RuleData rule, Term origin)
        {
            Require(!rule.Data.ContainsKey("countPackets") && !rule.Data.ContainsKey("rateLimit") &&
                !rule.Data.Any(pair => pair.Key.StartsWith("negate", StringComparison.Ordinal)),
                origin, "import.natJumpStateOrNegationUnsupported");
            if (guard.Family is not null && rule.Family is not null && guard.Family != rule.Family ||
                guard.Protocol != "any" && rule.Protocol != "any" && guard.Protocol != rule.Protocol) { return null; }
            var data = (JsonObject)rule.Data.DeepClone();
            foreach (var (key, value) in guard.Data)
            {
                if (key is "source" or "sourcePrefixes" or "destination" or "destinationPrefixes" or "destinationPort" or "destinationPorts") { continue; }
                if (data.TryGetPropertyValue(key, out var existing))
                {
                    if (key == "description") { continue; }
                    if (key is "inputInterfaceSelector" or "outputInterfaceSelector")
                    { Require(JsonNode.DeepEquals(existing, value), origin, "import.natJumpSelectorIntersectionUnsupported"); }
                    if (!JsonNode.DeepEquals(existing, value)) { return null; }
                }
                else { data[key] = value?.DeepClone(); }
            }
            if (!IntersectNatPredicate(guard.Data, data, "source", "sourcePrefixes", IntersectNetwork) ||
                !IntersectNatPredicate(guard.Data, data, "destination", "destinationPrefixes", IntersectNetwork) ||
                !IntersectNatPredicate(guard.Data, data, "destinationPort", "destinationPorts",
                    (left, right) => JsonNode.DeepEquals(left, right) ? left : null)) { return null; }
            return new RuleData
            {
                Data = data,
                Family = rule.Family ?? guard.Family,
                Protocol = rule.Protocol == "any" ? guard.Protocol : rule.Protocol,
                Action = rule.Action,
                Jump = rule.Jump,
            };
        }

        private static bool IntersectNatPredicate(JsonObject guard, JsonObject data, string scalar, string plural,
            Func<JsonNode, JsonNode, JsonNode?> intersect)
        {
            var outer = Values(guard);
            if (outer.Length == 0) { return true; }
            var inner = Values(data);
            var values = inner.Length == 0 ? outer :
                outer.SelectMany(left => inner.Select(right => intersect(left, right)).OfType<JsonNode>())
                    .DistinctBy(value => value.ToJsonString()).ToArray();
            if (values.Length == 0) { return false; }
            data.Remove(scalar);
            data.Remove(plural);
            if (values.Length == 1) { data[scalar] = values[0].DeepClone(); }
            else { data[plural] = new JsonArray(values.Select(value => value.DeepClone()).ToArray()); }
            return true;

            JsonNode[] Values(JsonObject source) =>
                source[scalar] is { } value ? [value] : source[plural] is JsonArray array ? array.OfType<JsonNode>().ToArray() : [];
        }

        private static JsonNode? IntersectNetwork(JsonNode left, JsonNode right)
        {
            var outer = IPNetwork.Parse(left.GetValue<string>());
            var inner = IPNetwork.Parse(right.GetValue<string>());
            if (outer.PrefixLength <= inner.PrefixLength && outer.Contains(inner.BaseAddress)) { return right; }
            if (inner.PrefixLength <= outer.PrefixLength && inner.Contains(outer.BaseAddress)) { return left; }
            return null;
        }
    }
}
