using System.Text.Json.Nodes;

namespace Nergal.Nftables;

public static partial class NativeImportPlanner
{
    private sealed partial class Planner
    {
        private JsonObject Lower()
        {
            Require(tables.Values.Count(t => t.Role == NativeImportTableRole.Filter) == 1, root!, "import.primaryFilterRequired");
            var bundle = new JsonObject { ["schemaVersion"] = 1 };
            foreach (var table in tables.Values)
            {
                switch (table.Role)
                {
                    case NativeImportTableRole.Filter: bundle["filter"] = Filter(table, false); break;
                    case NativeImportTableRole.Auxiliary: bundle["auxiliaryFilter"] = Filter(table, true); break;
                    case NativeImportTableRole.Nat: bundle["nat"] = Nat(table); break;
                    case NativeImportTableRole.Bridge: bundle["bridge"] = Bridge(table); break;
                }
            }
            return bundle;
        }

        private JsonObject Filter(Table table, bool auxiliary)
        {
            var rules = new JsonArray();
            var result = new JsonObject { ["schemaVersion"] = 2, ["inputDefaultVerdict"] = "accept", ["forwardDefaultVerdict"] = "accept", ["outputDefaultVerdict"] = "accept", ["rules"] = rules };
            int? priority = null; var hooks = new HashSet<string>(StringComparer.Ordinal);
            foreach (var chain in table.Chains.Values)
            {
                Attempt(chain.Origin, () =>
                {
                    var rawHook = chain.Hook is "prerouting" || chain.Hook is "output" && chain.Priority == -300;
                    var rawProperty = chain.Hook == "output" ? "rawOutput" : "rpFilter";
                    Require(chain.Type == "filter" && chain.Hook is "input" or "forward" or "output" or "prerouting" && chain.Priority.HasValue && hooks.Add(rawHook ? rawProperty : chain.Hook), chain.Origin, "import.filterChainUnsupported");
                    if (rawHook)
                    {
                        Require(chain.Priority == -300 && chain.Policy == "accept", chain.Origin, "import.rawChainUnsupported");
                        var raw = new JsonArray(); result[rawProperty] = new JsonObject { ["defaultVerdict"] = "accept", ["rules"] = raw };
                        foreach (var (origin, terms) in chain.Rules)
                        {
                            Attempt(origin, () =>
                            {
                                foreach (var rule in ReadRules(table, origin, terms))
                                {
                                    Require(rule.Action is "accept" or "drop" or "notrack", origin, "import.rawActionUnsupported");
                                    Allowed(rule, origin, "source", "negateSource", "inputInterface", "negateInputInterface", "outputInterface", "negateOutputInterface", "sourcePort", "destinationPort", "matchFibUnreachable", "description");
                                    var data = rule.Data;
                                    data["verdict"] = rule.Action == "notrack" ? "continue" : rule.Action;
                                    if (rule.Action == "notrack") { data["notrack"] = true; }
                                    data["protocol"] = rule.Protocol;
                                    if (rule.Family is not null) { data["family"] = rule.Family; }
                                    raw.Add(data);
                                }
                                Map(origin, "rule", (auxiliary ? "auxiliaryFilter.filter." : "filter.") + rawProperty + ".rules");
                            });
                        }
                        return;
                    }
                    if (auxiliary)
                    { Require(priority is null || priority == chain.Priority, chain.Origin, "import.priorityConflict"); priority = chain.Priority; }
                    else { Require(chain.Priority == 0, chain.Origin, "import.primaryPriorityUnsupported"); }
                    result[chain.Hook + "DefaultVerdict"] = chain.Policy;
                    for (var index = 0; index < chain.Rules.Count; index++)
                    {
                        var (origin, terms) = chain.Rules[index];
                        Attempt(origin, () =>
                        {
                            if (terms.Length == 8 && terms[0].Text == "tcp" && terms[1].Text == "flags" && terms[2].Text == "syn" && terms[3].Text == "tcp" && terms[4].Text == "option" && terms[5].Text == "maxseg" && terms[6].Text == "size" && terms[7].Text == "set")
                            { throw new ImportFailure("import.mssValueRequired", origin); }
                            if (terms.Length == 9 && string.Join(' ', terms.Take(8).Select(t => t.Text)) == "tcp flags syn tcp option maxseg size set")
                            {
                                Require(!auxiliary && chain.Hook == "forward" && index == 0 && result["forwardTcpMssClamp"] is null, origin, "import.mssOrderUnsupported");
                                result["forwardTcpMssClamp"] = Integer(terms[8]); result["forwardTcpMssClampEnabled"] = true; Map(origin, "mss", "filter.forwardTcpMssClamp"); return;
                            }
                            foreach (var rule in ReadRules(table, origin, terms))
                            {
                                Require(rule.Action is "accept" or "drop" or "reject" or "rejectPortUnreachable" or "continue", origin, "import.filterActionUnsupported");
                                Allowed(rule, origin, "source", "destination", "sourcePrefixes", "destinationPrefixes", "sourceObject", "destinationObject", "destinationPort", "destinationPorts", "destinationPortObject", "inputInterface", "bindInputInterfaceIndex", "outputInterface", "negateInputInterface", "negateOutputInterface", "negateSource", "negateDestination", "sourceMac", "sourceMacs", "negateSourceMac", "connectionStates", "icmpType", "rateLimit", "matchOriginalDestinationDnat", "originalSourcePrefixes", "originalDestinationPrefixes", "description", "countPackets");
                                foreach (var family in Families(rule, shareCounter: true))
                                {
                                    var data = (JsonObject)rule.Data.DeepClone(); data["family"] = family; data["protocol"] = rule.Protocol; data["verdict"] = rule.Action; data["chain"] = chain.Hook; rules.Add(data);
                                }
                            }
                            Map(origin, "rule", auxiliary ? "auxiliaryFilter.filter.rules" : "filter.rules");
                        });
                    }
                });
            }
            Require(hooks.Count > 0, table.Origin, "import.filterChainRequired");
            return auxiliary ? new JsonObject { ["priority"] = priority ?? 0, ["filter"] = result } : result;
        }

        private JsonObject Nat(Table table)
        {
            var dnat = new JsonArray(); var snat = new JsonArray(); var hooks = new HashSet<string>(StringComparer.Ordinal);
            foreach (var chain in table.Chains.Values)
            {
                Attempt(chain.Origin, () =>
                {
                    Require(chain.Type == "nat" && chain.Policy == "accept" && chain.Hook is "prerouting" or "output" or "postrouting" && hooks.Add(chain.Hook) && chain.Priority == (chain.Hook == "postrouting" ? 100 : -100), chain.Origin, "import.natChainUnsupported");
                    Require(chain.Hook != "output" || chain.Rules.Count != 0, chain.Origin, "import.emptyNatOutputUnsupported");
                    var destinationNat = chain.Hook is "prerouting" or "output";
                    foreach (var (origin, terms) in chain.Rules)
                    {
                        Attempt(origin, () =>
                        {
                            foreach (var rule in ReadRules(table, origin, terms))
                            {
                                Require(destinationNat ? rule.Action == "dnat" : rule.Action is "snat" or "masquerade" or "return", origin, "import.natActionUnsupported");
                                Require(!rule.Data.ContainsKey("countPackets") || rule.CounterHasFamily, origin, "import.natCounterFamilyRequired");
                                Require(!destinationNat || !rule.Data.ContainsKey("matchOriginalDestinationDnat") &&
                                    !rule.Data.ContainsKey("originalSourcePrefixes") && !rule.Data.ContainsKey("originalDestinationPrefixes"),
                                    origin, "import.matcherScopeUnsupported");
                                Allowed(rule, origin, "source", "destination", "sourcePrefixes", "destinationPrefixes", "sourceObject", "destinationObject", "destinationPort", "destinationPorts", "destinationPortObject", "inputInterface", "outputInterface", "negateInputInterface", "negateOutputInterface", "negateSource", "negateDestination", "translatedAddress", "translatedPort", "description", "countPackets", "matchOriginalDestinationDnat", "originalSourcePrefixes", "originalDestinationPrefixes");
                                foreach (var family in Families(rule))
                                {
                                    var data = (JsonObject)rule.Data.DeepClone(); data["family"] = family; data["protocol"] = rule.Protocol;
                                    if (destinationNat)
                                    {
                                        Rename(data, "destination", "originalDestination"); Rename(data, "destinationPort", "originalPort"); Rename(data, "destinationPorts", "originalPorts"); Rename(data, "destinationPortObject", "originalPortObject");
                                        if (chain.Hook == "output") { data["hook"] = "output"; }
                                        dnat.Add(data);
                                    }
                                    else { data["action"] = rule.Action; snat.Add(data); }
                                }
                            }
                            Map(origin, "rule", destinationNat ? "nat.dnatRules" : "nat.snatRules");
                        });
                    }
                });
            }
            Require(hooks.Count > 0, table.Origin, "import.natChainRequired");
            return new JsonObject { ["schemaVersion"] = 1, ["dnatRules"] = dnat, ["snatRules"] = snat };
        }

        private JsonObject Bridge(Table table)
        {
            var rules = new JsonArray(); var subchains = new JsonArray(); Chain? forward = null;
            var names = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var chain in table.Chains.Values)
            {
                if (chain.Type is not null)
                { Require(forward is null && chain.Type == "filter" && chain.Hook == "forward" && chain.Priority.HasValue, chain.Origin, "import.bridgeChainUnsupported"); forward = chain; }
                else
                {
                    Require(!chain.HasPolicy && chain.Name != "forward", chain.Origin, "import.regularChainUnsupported");
                    var safe = chain.Name.Length <= 32 && char.IsAsciiLetter(chain.Name[0]) && chain.Name.All(c => char.IsAsciiLetterOrDigit(c) || c == '_');
                    names.Add(chain.Name, safe ? chain.Name : "import_chain_" + names.Count.ToString(System.Globalization.CultureInfo.InvariantCulture));
                }
            }
            Require(forward is not null, table.Origin, "import.bridgeForwardRequired");
            foreach (var chain in table.Chains.Values)
            {
                var target = ReferenceEquals(chain, forward) ? rules : new JsonArray();
                foreach (var (origin, terms) in chain.Rules)
                {
                    Attempt(origin, () =>
                    {
                        foreach (var rule in ReadRules(table, origin, terms))
                        {
                            Require(rule.Family is not null || rule.Protocol == "any" || rule.ExplicitTransport, origin, "import.bridgeProtocolContextRequired");
                            Require(rule.Action is "accept" or "drop" or "return" or "jump", origin, "import.bridgeActionUnsupported");
                            Allowed(rule, origin, "inputInterface", "outputInterface", "bridgeName", "sourceMac", "destinationMac", "negateSourceMac", "negateDestinationMac", "etherType", "source", "destination", "sourcePrefixes", "destinationPrefixes", "sourceObject", "destinationObject", "destinationPort", "destinationPorts", "destinationPortObject", "description");
                            var data = rule.Data; data["verdict"] = rule.Action is "accept" or "drop" ? rule.Action : "drop";
                            if (rule.Action == "return") { data["return"] = true; }
                            if (rule.Action == "jump") { Require(rule.Jump is not null && names.ContainsKey(rule.Jump), origin, "import.jumpTargetUnresolved"); data["jumpTarget"] = names[rule.Jump!]; }
                            if (rule.Family is not null) { data["family"] = rule.Family; }
                            data["protocol"] = rule.Protocol; if (data["etherType"] is null) { data["etherType"] = "any"; }
                            target.Add(data);
                        }
                        Map(origin, "rule", "bridge.rules");
                    });
                }
                if (!ReferenceEquals(chain, forward)) { subchains.Add(new JsonObject { ["name"] = names[chain.Name], ["rules"] = target }); }
            }
            return new JsonObject { ["schemaVersion"] = 1, ["priority"] = forward!.Priority!.Value, ["defaultVerdict"] = forward.Policy, ["rules"] = rules, ["subChains"] = subchains };
        }

        private static IEnumerable<string> Families(RuleData rule, bool shareCounter = false) =>
            rule.Family is not null ? [rule.Family] : shareCounter && rule.Data.ContainsKey("countPackets") ? ["dualStack"] : ["ipv4", "ipv6"];
        private static void Rename(JsonObject data, string oldName, string newName)
        { if (data.Remove(oldName, out var value)) { data[newName] = value; } }
        private static void Allowed(RuleData rule, Term origin, params string[] properties)
        { Require(rule.Data.All(p => properties.Contains(p.Key, StringComparer.Ordinal)), origin, "import.matcherScopeUnsupported"); }
    }
}
