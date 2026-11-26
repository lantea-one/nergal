using System.Globalization;
using System.Text;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

// Extended bridge policies retain their own hook and regular-chain semantics.
// Agent replacement must bind their complete native observation and local rollback receipt.
internal static class RouterBridgeCompiler
{
    internal static CompilationResult Compile(BridgePolicy p, NftTableIdentity? identity, BridgePolicy intent)
    {
        var errors = new List<PolicyDiagnostic>();
        var sets = new NftStaticSetPlan(intent.Rules.Concat(intent.SubChains.SelectMany(c => c.Rules)).SelectMany(NftStaticSetPlan.References), errors);
        if (p.SchemaVersion != 1) { errors.Add(new("schema.unsupported", "schemaVersion")); }
        if (p.Priority is < -300 or > 300) { errors.Add(new("priority.outOfRange", "priority")); }
        if (p.DefaultVerdict is not (FilterVerdict.Accept or FilterVerdict.Drop)) { errors.Add(new("verdict.unknown", "defaultVerdict")); }
        var names = new HashSet<string>(StringComparer.Ordinal);
        if (p.SubChains.Count > 32) { errors.Add(new("chain.tooMany", "subChains")); }
        foreach (var chain in p.SubChains)
        {
            if (chain is null || !ValidName(chain.Name) || chain.Name == "forward" || !names.Add(chain.Name))
            { errors.Add(new("chain.invalidName", "subChains")); }
        }
        var chains = new List<(string Name, IReadOnlyList<BridgeFilterRule?> Rules)> { ("forward", p.Rules) };
        chains.AddRange(p.SubChains.Where(c => c is not null).Select(c => (c.Name, c.Rules)));
        foreach (var (name, rules) in chains)
        {
            if (rules.Count > 4096) { errors.Add(new("rule.tooMany", name)); }
            for (var i = 0; i < rules.Count; i++)
            {
                var path = name + ".rules[" + i.ToString(CultureInfo.InvariantCulture) + "]";
                if (rules[i] is not { } r) { errors.Add(new("rule.required", path)); continue; }
                if (!Enum.IsDefined(r.EtherType)) { errors.Add(new("etherType.unknown", path)); }
                if (r.Verdict is not (FilterVerdict.Accept or FilterVerdict.Drop)) { errors.Add(new("verdict.unknown", path)); }
                if ((r.JumpTarget is not null || r.Return) && r.Verdict != FilterVerdict.Drop) { errors.Add(new("bridge.actionConflict", path)); }
                if (r.JumpTarget is not null && (!names.Contains(r.JumpTarget) || r.Return)) { errors.Add(new("jump.invalidTarget", path)); }
                if (r.Return && name == "forward") { errors.Add(new("return.requiresRegularChain", path)); }
                foreach (var iface in new[] { r.InputInterface, r.OutputInterface, r.BridgeName })
                { if (iface is not null && !FilterPolicyValidation.IsValidInterfaceName(iface)) { errors.Add(new("interface.invalid", path)); } }
                RouterFilterValidation.Require(r.NegateSourceMac, r.SourceMac is not null, path + ".negateSourceMac", errors);
                RouterFilterValidation.Require(r.NegateDestinationMac, r.DestinationMac is not null, path + ".negateDestinationMac", errors);
                if (r.Family is { } family && (family is not (IpFamily.IPv4 or IpFamily.IPv6) || (r.EtherType != BridgeEtherType.Any && r.EtherType != (family == IpFamily.IPv4 ? BridgeEtherType.IPv4 : BridgeEtherType.IPv6))))
                { errors.Add(new("bridge.familyMismatch", path)); }
                if ((r.SourcePrefixes is not null || r.DestinationPrefixes is not null) && !r.Family.HasValue) { errors.Add(new("bridge.familyRequired", path + ".family")); }
                if (r.Source is not null && r.SourcePrefixes is not null) { errors.Add(new("set.conflictsWithScalar", path + ".sourcePrefixes")); }
                if (r.Destination is not null && r.DestinationPrefixes is not null) { errors.Add(new("set.conflictsWithScalar", path + ".destinationPrefixes")); }
                if (r.Family is { } setFamily)
                {
                    NftFilterCompiler.ValidatePrefixSet(r.SourcePrefixes, setFamily, path + ".sourcePrefixes", errors);
                    NftFilterCompiler.ValidatePrefixSet(r.DestinationPrefixes, setFamily, path + ".destinationPrefixes", errors);
                }
                if ((r.Source is not null && r.Source.Family != r.Family) || (r.Destination is not null && r.Destination.Family != r.Family))
                { errors.Add(new("network.familyMismatch", path)); }
                if (r.Protocol is not (FilterProtocol.Any or FilterProtocol.Tcp or FilterProtocol.Udp)) { errors.Add(new("protocol.unknown", path)); }
                if ((r.DestinationPort is not null || r.DestinationPorts is not null) && r.Protocol is not (FilterProtocol.Tcp or FilterProtocol.Udp))
                { errors.Add(new("port.requiresTransport", path)); }
                if (r.DestinationPort is < 1 or > 65535) { errors.Add(new("port.outOfRange", path)); }
                if (r.DestinationPorts is { } ports && (r.DestinationPort is not null || ports.Count is < 2 or > 64 ||
                    ports.Any(x => x is < 1 or > 65535) || ports.Distinct().Count() != ports.Count)) { errors.Add(new("bridge.portSetInvalid", path)); }
            }
        }
        if (errors.Count == 0)
        {
            var graph = p.SubChains.ToDictionary(c => c.Name, c => c.Rules.Where(r => r?.JumpTarget is not null).Select(r => r!.JumpTarget!).ToArray(), StringComparer.Ordinal);
            foreach (var name in names)
            { if (!Acyclic(name, graph, new HashSet<string>(StringComparer.Ordinal), 0)) { errors.Add(new("jump.cycleOrDepth", "subChains")); break; } }
        }
        if (errors.Count > 0) { return new(null, errors); }
        var text = new StringBuilder("create table bridge " + NftBridgeCompiler.TableName);
        if (identity is not null) { text.Append(" { comment \"").Append(identity.Comment).Append("\"; }"); }
        text.Append('\n').Append("add chain bridge " + NftBridgeCompiler.TableName + " forward { type filter hook forward priority ")
            .Append(p.Priority.ToString(CultureInfo.InvariantCulture)).Append("; policy ").Append(p.DefaultVerdict == FilterVerdict.Accept ? "accept" : "drop").Append("; }\n");
        foreach (var c in p.SubChains) { text.Append("add chain bridge " + NftBridgeCompiler.TableName + ' ').Append(c.Name).Append('\n'); }
        sets.Append(text, "bridge", NftBridgeCompiler.TableName);
        foreach (var (name, rules) in chains)
        {
            for (var index = 0; index < rules.Count; index++)
            {
                var draft = rules[index];
                var originalRules = name == "forward" ? intent.Rules : intent.SubChains.Single(c => c.Name == name).Rules;
                var r = NftStaticSetPlan.Attach(draft!, originalRules[index]!);
                if (!r.Enabled) { continue; }
                text.Append("add rule bridge " + NftBridgeCompiler.TableName + ' ').Append(name).Append(' ');
                if (r.InputInterface is not null) { text.Append("iifname \"").Append(r.InputInterface).Append("\" "); }
                if (r.OutputInterface is not null) { text.Append("oifname \"").Append(r.OutputInterface).Append("\" "); }
                if (r.BridgeName is not null) { text.Append("meta ibrname \"").Append(r.BridgeName).Append("\" "); }
                if (r.SourceMac is not null) { text.Append("ether saddr ").Append(r.NegateSourceMac ? "!= " : "").Append(r.SourceMac.Value).Append(' '); }
                if (r.DestinationMac is not null) { text.Append("ether daddr ").Append(r.NegateDestinationMac ? "!= " : "").Append(r.DestinationMac.Value).Append(' '); }
                var type = r.Family is { } f ? f == IpFamily.IPv4 ? BridgeEtherType.IPv4 : BridgeEtherType.IPv6 : r.EtherType;
                if (type != BridgeEtherType.Any) { text.Append("ether type ").Append(type == BridgeEtherType.IPv4 ? "ip" : type == BridgeEtherType.IPv6 ? "ip6" : "arp").Append(' '); }
                var family = r.Family == IpFamily.IPv4 ? "ip" : "ip6";
                if (r.SourceObject is { NativeSet: true } sourceSet) { text.Append(family).Append(" saddr @").Append(NftStaticSetPlan.Name(sourceSet)).Append(' '); }
                else if (r.Source is not null) { text.Append(family).Append(" saddr ").Append(r.Source.Value).Append(' '); }
                else if (r.SourcePrefixes is { } sources) { text.Append(family).Append(" saddr { ").Append(string.Join(", ", sources.Select(p => p.Value).Order(StringComparer.Ordinal))).Append(" } "); }
                if (r.DestinationObject is { NativeSet: true } destinationSet) { text.Append(family).Append(" daddr @").Append(NftStaticSetPlan.Name(destinationSet)).Append(' '); }
                else if (r.Destination is not null) { text.Append(family).Append(" daddr ").Append(r.Destination.Value).Append(' '); }
                else if (r.DestinationPrefixes is { } destinations) { text.Append(family).Append(" daddr { ").Append(string.Join(", ", destinations.Select(p => p.Value).Order(StringComparer.Ordinal))).Append(" } "); }
                if (r.Protocol != FilterProtocol.Any)
                {
                    var protocol = r.Protocol == FilterProtocol.Tcp ? "tcp" : "udp";
                    text.Append("meta l4proto ").Append(protocol).Append(' ');
                    if (r.DestinationPortObject is { NativeSet: true } portSet) { text.Append(protocol).Append(" dport @").Append(NftStaticSetPlan.Name(portSet)).Append(' '); }
                    else if (r.DestinationPort is { } port) { text.Append(protocol).Append(" dport ").Append(port.ToString(CultureInfo.InvariantCulture)).Append(' '); }
                    else if (r.DestinationPorts is { } ports) { text.Append(protocol).Append(" dport { ").Append(string.Join(", ", ports.Order())).Append(" } "); }
                }
                text.Append(r.JumpTarget is not null ? "jump " + r.JumpTarget : r.Return ? "return" : r.Verdict == FilterVerdict.Accept ? "accept" : "drop").Append('\n');
            }
        }
        return sets.Finish(text.ToString());
    }

    private static bool ValidName(string? name) => name is { Length: >= 1 and <= 32 } &&
        char.IsAsciiLetter(name[0]) && name.All(c => char.IsAsciiLetterOrDigit(c) || c == '_');
    private static bool Acyclic(string name, Dictionary<string, string[]> graph, HashSet<string> path, int depth)
    {
        if (depth > 8 || !path.Add(name)) { return false; }
        var ok = graph[name].All(child => Acyclic(child, graph, new HashSet<string>(path, StringComparer.Ordinal), depth + 1));
        return ok;
    }
}
