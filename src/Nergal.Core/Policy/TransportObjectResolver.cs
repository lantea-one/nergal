using System.Globalization;
using Nergal.Core.Controller;

namespace Nergal.Core.Policy;

/// <summary>Projects embedded immutable port-list versions onto existing NAT and bridge literal matchers without fetching database state.</summary>
/// <remarks>The original policy retains references. Invalid types or conflicting literals produce diagnostics, never partial enforcement.</remarks>
public static class TransportObjectResolver
{
    /// <summary>Returns a defensive NAT projection, retaining all actions, matchers, rule order and enabled state.</summary>
    public static NatPolicy Resolve(NatPolicy policy, ICollection<PolicyObjectDiagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(policy); ArgumentNullException.ThrowIfNull(diagnostics);
        if (!policy.SnatRules.Any(r => r?.DestinationPortObject is not null)) { return policy; }
        return new(policy.SchemaVersion, policy.DnatRules, policy.SnatRules.Select((rule, i) =>
        {
            if (rule?.DestinationPortObject is null) { return rule; }
            var ports = Ports(rule.DestinationPortObject, rule.DestinationPort, rule.DestinationPorts, $"snatRules[{i.ToString(CultureInfo.InvariantCulture)}].destinationPortObject", diagnostics);
            return rule with
            {
                DestinationPort = ports?.Length == 1 ? ports[0] : rule.DestinationPort,
                DestinationPorts = ports?.Length > 1 ? ports : rule.DestinationPorts,
                DestinationPortObject = null
            };
        }));
    }

    /// <summary>Returns a defensive bridge projection, including every regular chain; the jump graph and all other intent remain unchanged.</summary>
    public static BridgePolicy Resolve(BridgePolicy policy, ICollection<PolicyObjectDiagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(policy); ArgumentNullException.ThrowIfNull(diagnostics);
        if (policy.SubChains.Any(c => c is null)) { diagnostics.Add(new("chain.invalidName", "subChains")); return policy; }
        if (!policy.Rules.Concat(policy.SubChains.SelectMany(c => c.Rules)).Any(r => r?.DestinationPortObject is not null)) { return policy; }
        return new(policy.SchemaVersion, policy.DefaultVerdict, Rules(policy.Rules, "rules"), policy.Priority,
            policy.SubChains.Select((c, i) => new BridgeSubChain(c.Name, Rules(c.Rules, $"subChains[{i.ToString(CultureInfo.InvariantCulture)}].rules"))));
        IEnumerable<BridgeFilterRule?> Rules(IReadOnlyList<BridgeFilterRule?> rules, string path) => rules.Select((rule, i) =>
        {
            if (rule?.DestinationPortObject is null) { return rule; }
            var ports = Ports(rule.DestinationPortObject, rule.DestinationPort, rule.DestinationPorts, $"{path}[{i.ToString(CultureInfo.InvariantCulture)}].destinationPortObject", diagnostics);
            return rule with
            {
                DestinationPort = ports?.Length == 1 ? ports[0] : rule.DestinationPort,
                DestinationPorts = ports?.Length > 1 ? ports : rule.DestinationPorts,
                DestinationPortObject = null
            };
        });
    }

    private static int[]? Ports(PolicyObjectReference reference, int? scalar, IReadOnlyList<int>? list, string path, ICollection<PolicyObjectDiagnostic> diagnostics)
    {
        if (scalar.HasValue || list is not null) { diagnostics.Add(new("object.conflictsWithLiteral", path)); }
        if (reference.Content.Kind != ReusableObjectKind.Port) { diagnostics.Add(new("object.kindMismatch", path)); return null; }
        return reference.Content.Entries.Select(p => int.Parse(p, CultureInfo.InvariantCulture)).ToArray();
    }
}
