using System.Globalization;
using Nergal.Core.Controller;

namespace Nergal.Core.Policy;

/// <summary>Projects embedded immutable list versions onto NAT and bridge address/port literal matchers without fetching database state.</summary>
/// <remarks>The original policy retains references. Invalid types or conflicting literals produce diagnostics, never partial enforcement.</remarks>
public static class TransportObjectResolver
{
    /// <summary>Returns a defensive NAT projection, retaining all actions, matchers, rule order and enabled state.</summary>
    public static NatPolicy Resolve(NatPolicy policy, ICollection<PolicyObjectDiagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(policy); ArgumentNullException.ThrowIfNull(diagnostics);
        if (!policy.DnatRules.Any(r => r?.OriginalPortObject is not null || r?.SourceObject is not null || r?.DestinationObject is not null) && !policy.SnatRules.Any(r => r?.DestinationPortObject is not null || r?.SourceObject is not null || r?.DestinationObject is not null)) { return policy; }
        return new(policy.SchemaVersion, policy.DnatRules.Select((rule, i) =>
        {
            if (rule is null) { return rule; }
            var path = $"dnatRules[{i.ToString(CultureInfo.InvariantCulture)}]";
            var source = Prefixes(rule.SourceObject, rule.Source is not null || rule.SourcePrefixes is not null, rule.Family, path + ".sourceObject", diagnostics);
            var destination = Prefixes(rule.DestinationObject, rule.OriginalDestination is not null || rule.DestinationPrefixes is not null, rule.Family, path + ".destinationObject", diagnostics);
            var ports = rule.OriginalPortObject is { } reference ? Ports(reference, rule.OriginalPort, rule.OriginalPorts, path + ".originalPortObject", diagnostics) : null;
            return rule with
            {
                OriginalPort = ports?.Length == 1 ? ports[0] : rule.OriginalPort,
                OriginalPorts = ports?.Length > 1 ? ports : rule.OriginalPorts,
                OriginalPortObject = null,
                Source = source?.Length == 1 ? source[0] : rule.Source,
                SourcePrefixes = source?.Length > 1 ? source : rule.SourcePrefixes,
                SourceObject = null,
                OriginalDestination = destination?.Length == 1 ? destination[0] : rule.OriginalDestination,
                DestinationPrefixes = destination?.Length > 1 ? destination : rule.DestinationPrefixes,
                DestinationObject = null
            };
        }), policy.SnatRules.Select((rule, i) =>
        {
            if (rule is null) { return rule; }
            var path = $"snatRules[{i.ToString(CultureInfo.InvariantCulture)}]";
            var source = Prefixes(rule.SourceObject, rule.Source is not null || rule.SourcePrefixes is not null, rule.Family, path + ".sourceObject", diagnostics);
            var destination = Prefixes(rule.DestinationObject, rule.Destination is not null || rule.DestinationPrefixes is not null, rule.Family, path + ".destinationObject", diagnostics);
            var ports = rule.DestinationPortObject is { } portReference ? Ports(portReference, rule.DestinationPort, rule.DestinationPorts, path + ".destinationPortObject", diagnostics) : null;
            return rule with
            {
                DestinationPort = ports?.Length == 1 ? ports[0] : rule.DestinationPort,
                DestinationPorts = ports?.Length > 1 ? ports : rule.DestinationPorts,
                DestinationPortObject = null,
                Source = source?.Length == 1 ? source[0] : rule.Source,
                SourcePrefixes = source?.Length > 1 ? source : rule.SourcePrefixes,
                Destination = destination?.Length == 1 ? destination[0] : rule.Destination,
                DestinationPrefixes = destination?.Length > 1 ? destination : rule.DestinationPrefixes,
                SourceObject = null,
                DestinationObject = null
            };
        }));
    }

    /// <summary>Returns a defensive bridge projection, including every regular chain; the jump graph and all other intent remain unchanged.</summary>
    public static BridgePolicy Resolve(BridgePolicy policy, ICollection<PolicyObjectDiagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(policy); ArgumentNullException.ThrowIfNull(diagnostics);
        if (policy.SubChains.Any(c => c is null)) { diagnostics.Add(new("chain.invalidName", "subChains")); return policy; }
        if (!policy.Rules.Concat(policy.SubChains.SelectMany(c => c.Rules)).Any(r => r?.DestinationPortObject is not null || r?.SourceObject is not null || r?.DestinationObject is not null)) { return policy; }
        return new(policy.SchemaVersion, policy.DefaultVerdict, Rules(policy.Rules, "rules"), policy.Priority,
            policy.SubChains.Select((c, i) => new BridgeSubChain(c.Name, Rules(c.Rules, $"subChains[{i.ToString(CultureInfo.InvariantCulture)}].rules"))));
        IEnumerable<BridgeFilterRule?> Rules(IReadOnlyList<BridgeFilterRule?> rules, string path) => rules.Select((rule, i) =>
        {
            if (rule is null) { return rule; }
            var rulePath = $"{path}[{i.ToString(CultureInfo.InvariantCulture)}]";
            var source = Prefixes(rule.SourceObject, rule.Source is not null || rule.SourcePrefixes is not null, rule.Family, rulePath + ".sourceObject", diagnostics);
            var destination = Prefixes(rule.DestinationObject, rule.Destination is not null || rule.DestinationPrefixes is not null, rule.Family, rulePath + ".destinationObject", diagnostics);
            var ports = rule.DestinationPortObject is { } reference ? Ports(reference, rule.DestinationPort, rule.DestinationPorts, rulePath + ".destinationPortObject", diagnostics) : null;
            return rule with
            {
                DestinationPort = ports?.Length == 1 ? ports[0] : rule.DestinationPort,
                DestinationPorts = ports?.Length > 1 ? ports : rule.DestinationPorts,
                DestinationPortObject = null,
                Source = source?.Length == 1 ? source[0] : rule.Source,
                SourcePrefixes = source?.Length > 1 ? source : rule.SourcePrefixes,
                Destination = destination?.Length == 1 ? destination[0] : rule.Destination,
                DestinationPrefixes = destination?.Length > 1 ? destination : rule.DestinationPrefixes,
                SourceObject = null,
                DestinationObject = null
            };
        });
    }

    private static NetworkPrefix[]? Prefixes(PolicyObjectReference? reference, bool hasLiteral, IpFamily? family, string path, ICollection<PolicyObjectDiagnostic> diagnostics)
    {
        if (reference is null) { return null; }
        if (hasLiteral) { diagnostics.Add(new("object.conflictsWithLiteral", path)); }
        if (!family.HasValue) { diagnostics.Add(new("object.requiresFamily", path)); return null; }
        var kind = family == IpFamily.IPv4 ? ReusableObjectKind.Ipv4 : ReusableObjectKind.Ipv6;
        if (!Enum.IsDefined(family.Value) || reference.Content.Kind != kind) { diagnostics.Add(new("object.kindMismatch", path)); return null; }
        return reference.Content.Entries.Select(p => new NetworkPrefix(p)).ToArray();
    }

    private static int[]? Ports(PolicyObjectReference reference, int? scalar, IReadOnlyList<int>? list, string path, ICollection<PolicyObjectDiagnostic> diagnostics)
    {
        if (scalar.HasValue || list is not null) { diagnostics.Add(new("object.conflictsWithLiteral", path)); }
        if (reference.Content.Kind != ReusableObjectKind.Port) { diagnostics.Add(new("object.kindMismatch", path)); return null; }
        return reference.Content.Entries.Select(p => int.Parse(p, CultureInfo.InvariantCulture)).ToArray();
    }
}
