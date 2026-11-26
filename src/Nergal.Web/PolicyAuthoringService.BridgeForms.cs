using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web;

/// <summary>Complete bridge rule form. Actions map explicitly to a verdict, a local jump or a regular-chain return.</summary>
internal sealed record VisualExtendedBridgeInput(string? EtherType, string? Action, string? InputInterface, string? OutputInterface,
    string? BridgeName, string? SourceMac, string? DestinationMac, bool NegateSourceMac, bool NegateDestinationMac,
    string? Family, string? Source, string? Destination, string? Protocol, string? DestinationPorts, string? JumpTarget, string? Description);

internal static partial class PolicyAuthoringService
{
    internal static bool TrySetBridgeSettings(string json, string? operation, int? priority, string? verdict,
        out string? updated, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updated = null;
        if (!TryDecodeBundle(json, out var bundle, out diagnostics) || bundle is null) { return false; }
        if (operation == "remove")
        {
            if (bundle.Bridge is null || bundle.Bridge.Rules.Count != 0 || bundle.Bridge.SubChains.Count != 0 || priority.HasValue || verdict is not null)
            { diagnostics = [new("bridge.removeRequiresEmptyTable", "bridge")]; return false; }
            return TryCompileVisualBundle(new(bundle.SchemaVersion, bundle.Filter, bundle.Nat, null, bundle.AuxiliaryFilter), out updated, out diagnostics);
        }
        if (operation != "set" || priority is null || !TryReadBaseVerdict(verdict, out var parsed))
        { diagnostics = [new("bridge.settingsInvalid", "bridge")]; return false; }
        var bridge = new BridgePolicy(bundle.Bridge?.SchemaVersion ?? 1, parsed, bundle.Bridge?.Rules ?? [], priority.Value, bundle.Bridge?.SubChains);
        return TryCompileVisualBundle(new(bundle.SchemaVersion, bundle.Filter, bundle.Nat, bridge, bundle.AuxiliaryFilter), out updated, out diagnostics);
    }

    internal static bool TrySetBridgeChain(string json, string? operation, string? name,
        out string? updated, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updated = null;
        if (!TryDecodeBundle(json, out var bundle, out diagnostics) || bundle is null) { return false; }
        if (bundle.Bridge is not { } bridge || operation is not ("add" or "remove") || string.IsNullOrWhiteSpace(name))
        { diagnostics = [new("bridge.chainOperationInvalid", "bridge.subChains")]; return false; }
        var chains = bridge.SubChains.ToList();
        var matches = chains.Where(c => c.Name == name).ToArray();
        if (operation == "add")
        {
            if (matches.Length != 0) { diagnostics = [new("bridge.chainDuplicate", "bridge.subChains")]; return false; }
            chains.Add(new(name, []));
        }
        else
        {
            if (matches.Length != 1 || matches[0].Rules.Count != 0)
            { diagnostics = [new("bridge.removeRequiresEmptyChain", "bridge.subChains")]; return false; }
            chains.Remove(matches[0]);
        }
        var next = new BridgePolicy(bridge.SchemaVersion, bridge.DefaultVerdict, bridge.Rules, bridge.Priority, chains);
        return TryCompileVisualBundle(new(bundle.SchemaVersion, bundle.Filter, bundle.Nat, next, bundle.AuxiliaryFilter), out updated, out diagnostics);
    }

    internal static bool TrySetExtendedBridgeRule(string json, string? operation, string? chain, int? index, VisualExtendedBridgeInput input,
        out string? updated, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updated = null;
        if (!TryDecodeBundle(json, out var bundle, out diagnostics) || bundle is null) { return false; }
        if (bundle.Bridge is not { } bridge || operation is not ("add" or "edit" or "remove" or "up" or "down"))
        { diagnostics = [new("bridge.ruleOperationInvalid", "bridge")]; return false; }
        var matches = chain is null ? [] : bridge.SubChains.Where(c => c.Name == chain).ToArray();
        if (chain is not null && matches.Length != 1)
        { diagnostics = [new("bridge.chainNotFound", "bridge.subChains")]; return false; }
        var rules = (chain is null ? bridge.Rules : matches[0].Rules).ToList();
        if (operation == "add" ? index.HasValue : index is null || index < 0 || index >= rules.Count)
        { diagnostics = [new("rule.indexOutOfRange", "bridge.rules")]; return false; }
        if (operation == "remove") { rules.RemoveAt(index!.Value); }
        else if (operation is "up" or "down")
        {
            var from = index!.Value; var to = from + (operation == "up" ? -1 : 1);
            if (to < 0 || to >= rules.Count) { diagnostics = [new("rule.moveOutOfRange", "bridge.rules")]; return false; }
            (rules[from], rules[to]) = (rules[to], rules[from]);
        }
        else
        {
            if (!TryParseExtendedBridgeRule(input, out var rule, out diagnostics)) { return false; }
            if (index is { } existing)
            {
                var previous = rules[existing]!;
                rules[existing] = rule! with
                {
                    Enabled = previous.Enabled,
                    CountPackets = previous.CountPackets,
                    BindInputInterfaceIndex = previous.BindInputInterfaceIndex && rule.InputInterface is not null,
                    DestinationPortObject = previous.DestinationPortObject,
                    SourceObject = previous.SourceObject,
                    DestinationObject = previous.DestinationObject
                };
            }
            else { rules.Add(rule); }
        }
        var chains = bridge.SubChains.Select(c => c.Name == chain ? new BridgeSubChain(c.Name, rules) : c).ToArray();
        var next = new BridgePolicy(bridge.SchemaVersion, bridge.DefaultVerdict, chain is null ? rules : bridge.Rules, bridge.Priority, chains);
        return TryCompileVisualBundle(new(bundle.SchemaVersion, bundle.Filter, bundle.Nat, next, bundle.AuxiliaryFilter), out updated, out diagnostics);
    }

    private static bool TryParseExtendedBridgeRule(VisualExtendedBridgeInput input, out BridgeFilterRule? rule, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        rule = null;
        var errors = new List<PolicyDiagnostic>();
        var ether = input.EtherType switch { "any" => BridgeEtherType.Any, "ipv4" => BridgeEtherType.IPv4, "ipv6" => BridgeEtherType.IPv6, "arp" => BridgeEtherType.Arp, _ => (BridgeEtherType)(-1) };
        IpFamily? family = input.Family switch { "none" => null, "ipv4" => IpFamily.IPv4, "ipv6" => IpFamily.IPv6, _ => (IpFamily)(-1) };
        var protocol = input.Protocol switch { "any" => FilterProtocol.Any, "tcp" => FilterProtocol.Tcp, "udp" => FilterProtocol.Udp, _ => (FilterProtocol)(-1) };
        if (!Enum.IsDefined(ether)) { errors.Add(new("bridge.etherTypeUnknown", "rule.etherType")); }
        if (family.HasValue && !Enum.IsDefined(family.Value)) { errors.Add(new("family.unknown", "rule.family")); }
        if (!Enum.IsDefined(protocol)) { errors.Add(new("protocol.unknown", "rule.protocol")); }
        if (input.Action is not ("accept" or "drop" or "jump" or "return")) { errors.Add(new("bridge.actionUnknown", "rule.action")); }
        var target = EmptyToNull(input.JumpTarget);
        if (input.Action == "jump" ? target is null : target is not null) { errors.Add(new("bridge.jumpTargetInvalid", "rule.jumpTarget")); }
        MacAddress? sourceMac = null, destinationMac = null;
        if (EmptyToNull(input.SourceMac) is { } sm && !MacAddress.TryParse(sm, out sourceMac)) { errors.Add(new("mac.invalid", "rule.sourceMac")); }
        if (EmptyToNull(input.DestinationMac) is { } dm && !MacAddress.TryParse(dm, out destinationMac)) { errors.Add(new("mac.invalid", "rule.destinationMac")); }
        TryParsePrefixField(input.Source, "rule.source", out var source, out var sourcePrefixes, errors);
        TryParsePrefixField(input.Destination, "rule.destination", out var destination, out var destinationPrefixes, errors);
        TryParsePortField(input.DestinationPorts, "rule.destinationPorts", out var port, out var ports, errors);
        if (!TryNormalizeDescription(input.Description, out var description)) { errors.Add(new("rule.descriptionInvalid", "rule.description")); }
        if (errors.Count != 0) { diagnostics = errors; return false; }
        rule = new(ether, input.Action == "accept" ? FilterVerdict.Accept : FilterVerdict.Drop, EmptyToNull(input.InputInterface), EmptyToNull(input.OutputInterface),
            description, EmptyToNull(input.BridgeName), sourceMac, destinationMac, input.NegateSourceMac, input.NegateDestinationMac,
            family, source, destination, protocol, port, ports, target, input.Action == "return");
        diagnostics = [];
        rule = rule with { SourcePrefixes = sourcePrefixes, DestinationPrefixes = destinationPrefixes };
        return true;
    }
}
