using System.Globalization;
using System.Text.Json.Nodes;
using Nergal.Core.Policy;
using Nergal.Core.Controller;

namespace Nergal.Nftables;

public static partial class NativeImportPlanner
{
    private sealed class RuleData
    {
        internal JsonObject Data { get; init; } = [];
        internal Dictionary<string, string[]> Alternatives { get; } = new(StringComparer.Ordinal);
        internal string[]? TransportAlternatives;
        internal string? Family;
        internal string Protocol = "any";
        internal bool ExplicitTransport;
        internal bool CounterHasFamily;
        internal string? Action;
        internal string? Jump;
    }
    private sealed class Cursor(Term[] terms)
    {
        internal int Index;
        internal bool End => Index == terms.Length;
        internal Term Peek => End ? terms[^1] : terms[Index];
        internal Term Take() { Planner.Require(!End, terms[^1], "import.ruleIncomplete"); return terms[Index++]; }
        internal bool Eat(string text) { if (!End && Peek.Text == text) { Index++; return true; } return false; }
        internal void Expect(string text) { var t = Take(); Planner.Require(t.Text == text, t, "import.expressionUnsupported"); }
        internal bool Negation() { if (Eat("!=")) { return true; } _ = Eat("=="); return false; }
        internal Term[] SelectorValues() => Peek.Node.Kind == NativeSourceNodeKind.Braces ? List() : [Take()];
        internal Term[] List()
        {
            var first = Take();
            if (first.Node.Kind == NativeSourceNodeKind.Braces) { return Planner.Comma(first.Children, first); }
            var values = new List<Term> { first };
            while (Eat(",")) { values.Add(Take()); }
            Planner.Require(values.Count <= 64, first, "import.listLimit"); return values.ToArray();
        }
    }

    private sealed partial class Planner
    {
        private IReadOnlyList<RuleData> ReadRules(Table table, Term origin, Term[] terms)
        {
            var rule = ReadRule(table, origin, terms);
            if (rule.Alternatives.Count == 0 && rule.TransportAlternatives is null) { return [rule]; }
            // Equality alternatives are disjoint on an unchanged packet. Never split a
            // meter, counter or jump, which could change state or packet fields.
            Require(rule.Action != "jump" && !rule.Data.ContainsKey("rateLimit") && !rule.Data.ContainsKey("countPackets"), origin, "import.alternativeStatefulUnsupported");

            var variants = new List<JsonObject> { rule.Data };
            foreach (var (property, options) in rule.Alternatives)
            {
                Require(variants.Count * options.Length <= 128, origin, "import.alternativeLimit");
                variants = variants.SelectMany(data => options.Select(option =>
                {
                    var projected = (JsonObject)data.DeepClone();
                    projected[property] = option;
                    return projected;
                })).ToList();
            }
            var protocols = rule.TransportAlternatives ?? [rule.Protocol];
            Require(variants.Count * protocols.Length <= 128, origin, "import.alternativeLimit");
            return variants.SelectMany(data => protocols.Select(protocol => new RuleData
            {
                Data = (JsonObject)data.DeepClone(),
                Family = rule.Family,
                Protocol = protocol,
                ExplicitTransport = rule.ExplicitTransport,
                Action = rule.Action,
                Jump = rule.Jump,
            })).ToArray();
        }

        private RuleData ReadRule(Table table, Term origin, Term[] terms)
        {
            var rule = new RuleData(); var c = new Cursor(terms); var predicates = 0;
            void Set(string key, JsonNode? value, Term term)
            { Require(!rule.Data.ContainsKey(key), term, "import.repeatedMatcherUnsupported"); rule.Data.Add(key, value); }
            void SetAlternatives(string key, string[] values, Term term, bool negated = false)
            {
                Require(values.Length <= 64 && values.Distinct(StringComparer.Ordinal).Count() == values.Length, term, "import.alternativeUnsupported");
                Require(!negated || values.Length == 1, term, "import.alternativeNegationUnsupported");
                Set(key, JsonValue.Create(values[0]), term);
                if (values.Length > 1) { rule.Alternatives.Add(key, values); }
            }
            void Family(string family, Term term)
            { Require(rule.Family is null || rule.Family == family, term, "import.familyConflict"); rule.Family = family; }
            void Protocol(string protocol, Term term)
            { Require(protocol is "tcp" or "udp" or "icmp" or "icmpv6", term, "import.protocolUnsupported"); Require(rule.TransportAlternatives is null && (rule.Protocol == "any" || rule.Protocol == protocol), term, "import.protocolConflict"); rule.Protocol = protocol; }
            while (!c.End)
            {
                var first = c.Take(); var word = first.Text;
                Require(++predicates <= 128, first, "import.ruleLimit");
                var qualified = word == "meta";
                if (qualified)
                { word = c.Take().Text; Require(word is "nfproto" or "l4proto" or "iif" or "iifname" or "oifname" or "ibrname", first, "import.metaExpressionUnsupported"); }
                if (word is "accept" or "drop" or "return" or "reject" or "jump" or "dnat" or "snat" or "masquerade" or "notrack")
                {
                    rule.Action = word;
                    if (word == "reject")
                    {
                        rule.Action = "rejectPortUnreachable";
                        if (c.Eat("with"))
                        {
                            c.Expect("icmpx"); c.Expect("type");
                            var kind = c.Take();
                            Require(kind.Text is "admin-prohibited" or "port-unreachable", kind, "import.rejectTypeUnsupported");
                            if (kind.Text == "admin-prohibited") { rule.Action = "reject"; }
                        }
                    }
                    if (word == "jump") { rule.Jump = Name(c.Take()); }
                    if (word is "dnat" or "snat")
                    {
                        if (!c.End && c.Peek.Text is "ip" or "ip6") { Family(c.Take().Text == "ip" ? "ipv4" : "ipv6", first); }
                        c.Expect("to"); Translation(c, rule, first);
                    }
                    if (c.Eat("comment")) { Set("description", JsonValue.Create(String(c.Take())), first); }
                    Require(c.End, c.Peek, "import.ruleTrailingInput"); return rule;
                }
                switch (word)
                {
                    case "counter":
                        rule.CounterHasFamily = rule.Family is not null;
                        Set("countPackets", JsonValue.Create(true), first);
                        if (c.End || c.Peek.Text == "comment" || c.Eat("continue"))
                        {
                            if (c.Eat("comment")) { Set("description", JsonValue.Create(String(c.Take())), first); }
                            Require(c.End, c.Peek, "import.ruleTrailingInput");
                            rule.Action = "continue";
                            return rule;
                        }
                        Require(c.Peek.Text is "accept" or "drop" or "reject" or "dnat" or "snat" or "masquerade" or "return", first, "import.counterPlacementUnsupported");
                        break;
                    case "nfproto":
                        Require(qualified, first, "import.metaKeywordRequired");
                        Require(!c.Negation(), first, "import.negationUnsupported");
                        var f = String(c.Take()); Require(f is "ipv4" or "ipv6", first, "import.familyUnsupported"); Family(f, first); break;
                    case "l4proto":
                        Require(qualified, first, "import.metaKeywordRequired"); rule.ExplicitTransport = true;
                        Require(!c.Negation(), first, "import.negationUnsupported");
                        var transports = c.SelectorValues().Select(String).ToArray();
                        if (transports.Length == 1)
                        {
                            var p = transports[0]; Protocol(p == "ipv6-icmp" ? "icmpv6" : p, first);
                        }
                        else
                        {
                            Require(rule.Protocol == "any" && rule.TransportAlternatives is null && transports.Length == 2
                                && transports.Contains("tcp", StringComparer.Ordinal) && transports.Contains("udp", StringComparer.Ordinal),
                                first, "import.protocolAlternativesUnsupported");
                            rule.TransportAlternatives = transports;
                        }
                        break;
                    case "iif":
                        var negateIndex = c.Negation();
                        var indexTerm = c.Take();
                        var indexName = ((NativeInterfaceLiteral)Literal(NativeRuleField.InputInterface, indexTerm)).Name;
                        Require(!indexName.All(char.IsAsciiDigit), indexTerm, "import.interfaceIndexUnsupported");
                        Set("inputInterface", JsonValue.Create(indexName), first);
                        Set("bindInputInterfaceIndex", JsonValue.Create(true), first);
                        if (negateIndex) { Set("negateInputInterface", JsonValue.Create(true), first); }
                        break;
                    case "iifname":
                    case "oifname":
                    case "ibrname":
                        var ni = c.Negation();
                        var field = word == "iifname" ? NativeRuleField.InputInterface : word == "oifname" ? NativeRuleField.OutputInterface : NativeRuleField.InputBridge;
                        var names = c.SelectorValues().Select(term => ((NativeInterfaceLiteral)Literal(field, term)).Name).ToArray();
                        var property = word == "iifname" ? "inputInterface" : word == "oifname" ? "outputInterface" : "bridgeName";
                        SetAlternatives(property, names, first, ni); if (ni) { Set("negate" + char.ToUpperInvariant(property[0]) + property[1..], JsonValue.Create(true), first); }
                        break;
                    case "ip":
                    case "ip6":
                        var addressKey = c.Take();
                        if (word == "ip" && addressKey.Text == "protocol")
                        {
                            Require(!c.Negation(), addressKey, "import.negationUnsupported");
                            var headerProtocol = c.Take();
                            // The following typed transport field already requires this IPv4 protocol.
                            Require(headerProtocol.Text is "tcp" or "udp" && !c.End && c.Peek.Text == headerProtocol.Text,
                                headerProtocol, "import.ipv4ProtocolGuardUnsupported");
                            Family("ipv4", first);
                            Protocol(headerProtocol.Text, headerProtocol);
                            break;
                        }
                        Require(addressKey.Text is "saddr" or "daddr", addressKey, "import.addressExpressionUnsupported");
                        Family(word == "ip" ? "ipv4" : "ipv6", first);
                        MatchValues(table, c, rule, first, word == "ip" ? NativeRuleField.IpSource : NativeRuleField.Ip6Source, addressKey.Text == "saddr" ? "source" : "destination", Set); break;
                    case "ether":
                        var key = c.Take();
                        if (key.Text == "type")
                        {
                            Require(!c.Negation(), first, "import.negationUnsupported"); var type = c.Take();
                            Require(type.Text is "ip" or "ip6" or "arp", type, "import.etherTypeUnsupported");
                            Set("etherType", JsonValue.Create(type.Text == "ip" ? "ipv4" : type.Text == "ip6" ? "ipv6" : "arp"), first);
                            if (type.Text is "ip" or "ip6") { Family(type.Text == "ip" ? "ipv4" : "ipv6", first); }
                            break;
                        }
                        Require(key.Text is "saddr" or "daddr", key, "import.etherExpressionUnsupported");
                        MatchValues(table, c, rule, first, NativeRuleField.EtherSource, key.Text == "saddr" ? "sourceMac" : "destinationMac", Set); break;
                    case "tcp":
                    case "udp":
                    case "th":
                        var port = c.Take(); Require(port.Text is "sport" or "dport", port, "import.transportExpressionUnsupported");
                        if (word == "th")
                        { Require(rule.ExplicitTransport && (rule.TransportAlternatives is not null || rule.Protocol is "tcp" or "udp"), first, "import.transportGuardRequired"); }
                        else { Protocol(word, first); }
                        Require(!c.Negation(), first, "import.negationUnsupported");
                        MatchValues(table, c, rule, first, NativeRuleField.TcpDestinationPort, port.Text == "sport" ? "sourcePort" : "destinationPort", Set, false); break;
                    case "icmp":
                    case "icmpv6":
                        c.Expect("type"); Require(!c.Negation(), first, "import.negationUnsupported"); Family(word == "icmp" ? "ipv4" : "ipv6", first); Protocol(word, first);
                        SetAlternatives("icmpType", c.SelectorValues().Select(String).ToArray(), first); break;
                    case "ct":
                        var ct = c.Take(); Require(!c.Negation(), first, "import.negationUnsupported");
                        if (ct.Text == "status") { c.Expect("dnat"); Set("matchOriginalDestinationDnat", JsonValue.Create(true), first); }
                        else if (ct.Text == "original")
                        {
                            var tupleFamily = c.Take();
                            Require(tupleFamily.Text is "ip" or "ip6", tupleFamily, "import.originalTupleFamilyUnsupported");
                            Family(tupleFamily.Text == "ip" ? "ipv4" : "ipv6", tupleFamily);
                            var tupleField = c.Take();
                            Require(tupleField.Text is "saddr" or "daddr", tupleField, "import.originalTupleFieldUnsupported");
                            Require(!c.Negation(), tupleField, "import.negationUnsupported");
                            var addressField = tupleFamily.Text == "ip" ? NativeRuleField.IpSource : NativeRuleField.Ip6Source;
                            var addresses = c.List().Select(term => ((NativeAddressLiteral)Literal(addressField, term)).Prefix.Value);
                            Set(tupleField.Text == "saddr" ? "originalSourcePrefixes" : "originalDestinationPrefixes",
                                new JsonArray(addresses.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray()), tupleField);
                        }
                        else
                        {
                            Require(ct.Text == "state", ct, "import.connectionExpressionUnsupported"); var states = c.List();
                            Require(states.All(s => s.Text is "invalid" or "established" or "related" or "new" or "untracked") && states.Select(s => s.Text).Distinct().Count() == states.Length, first, "import.connectionStateUnsupported");
                            Set("connectionStates", new JsonArray(states.Select(s => (JsonNode?)JsonValue.Create(s.Text)).ToArray()), first);
                        }
                        break;
                    case "fib":
                        c.Expect("saddr"); c.Expect("."); c.Expect("iif"); c.Expect("oif"); c.Expect("=="); c.Expect("0"); Set("matchFibUnreachable", JsonValue.Create(true), first); break;
                    case "meter":
                    case "add":
                    case "update":
                        Require(!rule.Data.ContainsKey("rateLimit"), first, "import.meterRepeated");
                        ReadMeter(table, c, rule, first, word is "add" or "update", word != "add");
                        Require(c.End || c.Peek.Text is "accept" or "drop" or "reject" or "counter", first, "import.meterPlacementUnsupported");
                        break;
                    default: throw new ImportFailure("import.expressionUnsupported", first);
                }
            }
            throw new ImportFailure("import.ruleActionRequired", origin);
        }

        private void MatchValues(Table table, Cursor c, RuleData rule, Term origin, NativeRuleField field, string key,
            Action<string, JsonNode?, Term> set, bool allowNegation = true)
        {
            var negated = allowNegation && c.Negation(); var values = c.List();
            Require(values.Length is >= 1 and <= 64, origin, "import.listLimit");
            if (values.Length == 1 && values[0].Kind == NativeSourceTokenKind.AtReference)
            {
                var referenceTerm = values[0]; Require(table.Sets.TryGetValue(referenceTerm.Text[1..], out var named) && named.Reference is not null, referenceTerm, "import.namedSetUnresolved");
                Require(key is "source" or "destination" or "destinationPort", referenceTerm, "import.referenceScopeUnsupported");
                var reference = named!.Reference!; var expected = field == NativeRuleField.IpSource ? ReusableObjectKind.Ipv4 : field == NativeRuleField.Ip6Source ? ReusableObjectKind.Ipv6 : ReusableObjectKind.Port;
                Require(reference.Content.Kind == expected, referenceTerm, "import.referenceTypeMismatch"); named.Used = true;
                set(key + "Object", ReferenceJson(reference), origin);
            }
            else
            {
                var literals = values.Select(v => Literal(field, v)).ToArray();
                JsonNode? Value(NativeRuleLiteral literal) => literal switch
                {
                    NativeAddressLiteral a => JsonValue.Create(a.Prefix.Value),
                    NativeMacLiteral m => JsonValue.Create(m.Address.Value),
                    NativePortLiteral p => JsonValue.Create((int)p.Port),
                    _ => null,
                };
                var plural = key is "source" or "destination" ? key + "Prefixes" : key + "s";
                set(values.Length == 1 ? key : plural, values.Length == 1 ? Value(literals[0]) : new JsonArray(literals.Select(Value).ToArray()), origin);
            }
            if (negated) { set("negate" + char.ToUpperInvariant(key[0]) + key[1..], JsonValue.Create(true), origin); }
        }

        private static JsonObject ReferenceJson(PolicyObjectReference reference) => new()
        {
            ["id"] = reference.Id.ToString("D"),
            ["version"] = reference.Version,
            ["name"] = reference.Content.Name,
            ["kind"] = reference.Content.Kind == Nergal.Core.Controller.ReusableObjectKind.Ipv4 ? "ipv4" : reference.Content.Kind == Nergal.Core.Controller.ReusableObjectKind.Ipv6 ? "ipv6" : "port",
            ["description"] = reference.Content.Description,
            ["entries"] = new JsonArray(reference.Content.Entries.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray()),
            ["digest"] = reference.Content.Digest,
            ["nativeSet"] = true,
        };

        private static void Translation(Cursor c, RuleData rule, Term origin)
        {
            var target = c.Take(); string address; string? port = null;
            if (target.Node.Kind == NativeSourceNodeKind.Brackets)
            {
                Require(target.Children.Length == 1, target, "import.translationUnsupported"); address = target.Children[0].Text;
                if (!c.End && c.Peek.Text.StartsWith(':')) { port = c.Take().Text[1..]; }
            }
            else
            {
                address = target.Text;
                if (address.Count(ch => ch == ':') == 1) { var split = address.LastIndexOf(':'); port = address[(split + 1)..]; address = address[..split]; }
            }
            Require(!address.Contains('/') && System.Net.IPAddress.TryParse(address, out var ip) && !address.Contains('%'), target, "import.translationUnsupported");
            var family = address.Contains(':') ? "ipv6" : "ipv4";
            Require(rule.Family is null || rule.Family == family, origin, "import.familyConflict"); rule.Family = family;
            // Literal validation uses the same strict numeric reader as the source viewer; translations are single hosts.
            Require(family == "ipv6" || System.Net.IPAddress.Parse(address).ToString() == address, target, "import.translationUnsupported");
            var normalized = new NetworkPrefix(address + (family == "ipv4" ? "/32" : "/128"));
            rule.Data["translatedAddress"] = normalized.Value[..normalized.Value.IndexOf('/')];
            if (port is not null)
            { Require(int.TryParse(port, out var number) && number is >= 1 and <= 65535 && number.ToString(System.Globalization.CultureInfo.InvariantCulture) == port, target, "import.translationPortUnsupported"); rule.Data["translatedPort"] = number; }
        }

        private void ReadMeter(Table table, Cursor c, RuleData rule, Term origin, bool named, bool refresh)
        {
            var name = c.Take(); NamedSet? set = null;
            if (named)
            {
                Require(name.Kind == NativeSourceTokenKind.AtReference && table.Sets.TryGetValue(name.Text[1..], out set) && set.DynamicFamily is not null && !set.Used, name, "import.dynamicMeterUnresolvedOrShared");
                set!.Used = true;
            }
            else { Require(table.Meters.Add(Name(name)), name, "import.sharedMeterUnsupported"); }
            if (c.Eat("size")) { Require(Integer(c.Take()) == 65535, origin, "import.meterSizeUnsupported"); }
            var body = c.Take(); Require(body.Node.Kind == NativeSourceNodeKind.Braces, body, "import.meterUnsupported");
            var m = new Cursor(body.Children); var family = m.Take(); Require(family.Text is "ip" or "ip6", family, "import.meterFamilyUnsupported");
            Require(rule.Family is null || rule.Family == (family.Text == "ip" ? "ipv4" : "ipv6"), family, "import.familyConflict");
            rule.Family = family.Text == "ip" ? "ipv4" : "ipv6";
            Require(set is null || set.DynamicFamily == (family.Text == "ip" ? "ipv4_addr" : "ipv6_addr"), family, "import.meterFamilyUnsupported");
            var key = m.Take(); Require(key.Text is "saddr" or "daddr", key, "import.meterKeyUnsupported");
            m.Expect("timeout"); var timeout = m.Take(); var timeoutSeconds = MeterTimeoutSeconds(timeout);
            m.Expect("limit"); m.Expect("rate"); var rate = m.Take(); var parts = rate.Text.Split('/');
            Require(parts.Length == 2 && int.TryParse(parts[0], out _) && parts[1] is "second" or "minute", rate, "import.meterRateUnsupported");
            var burst = 5; // nftables' implicit packet burst when the clause is omitted.
            if (m.Eat("burst")) { burst = Integer(m.Take()); m.Expect("packets"); }
            Require(m.End, m.Peek, "import.meterTrailingInput");
            rule.Data["rateLimit"] = new JsonObject { ["packetsPerWindow"] = int.Parse(parts[0], CultureInfo.InvariantCulture), ["windowUnit"] = parts[1], ["burst"] = burst, ["entryTimeoutSeconds"] = timeoutSeconds, ["keyKind"] = key.Text == "saddr" ? "sourceAddress" : "destinationAddress", ["refreshEntryTimeout"] = refresh };
        }

        private static int MeterTimeoutSeconds(Term term)
        {
            var text = term.Text;
            var secondsPerUnit = text.EndsWith('s') ? 1 : text.EndsWith('m') ? 60 : 0;
            Require(secondsPerUnit != 0, term, "import.meterTimeoutRequired");
            Require(int.TryParse(text.AsSpan(0, text.Length - 1), NumberStyles.None, CultureInfo.InvariantCulture, out var duration)
                && duration > 0 && duration <= int.MaxValue / secondsPerUnit, term, "import.meterTimeoutRequired");
            return duration * secondsPerUnit;
        }
    }
}
