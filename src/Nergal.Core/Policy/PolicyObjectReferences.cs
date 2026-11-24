namespace Nergal.Core.Policy;

/// <summary>A pinned object matcher location within a self-contained policy bundle.</summary>
public sealed record PolicyObjectBinding(string Path, PolicyObjectReference Reference);

/// <summary>Enumerates controller references without resolving them or altering policy intent.</summary>
public static class PolicyObjectReferences
{
    /// <summary>Returns filter, NAT and bridge references in stable rule/field order.</summary>
    public static IReadOnlyList<PolicyObjectBinding> Enumerate(FirewallPolicyBundle bundle)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        var result = new List<PolicyObjectBinding>();
        Add(bundle.Filter, "filter"); if (bundle.AuxiliaryFilter is { } aux) { Add(aux.Filter, "auxiliaryFilter.filter"); }
        if (bundle.Nat is { } nat)
        {
            for (var i = 0; i < nat.DnatRules.Count; i++)
            {
                if (nat.DnatRules[i] is not { } rule) { continue; }
                var path = $"nat.dnatRules[{i.ToString(System.Globalization.CultureInfo.InvariantCulture)}]";
                if (rule.SourceObject is { } source) { result.Add(new(path + ".sourceObject", source)); }
                if (rule.DestinationObject is { } destination) { result.Add(new(path + ".destinationObject", destination)); }
                if (rule.OriginalPortObject is { } ports) { result.Add(new(path + ".originalPortObject", ports)); }
            }
            for (var i = 0; i < nat.SnatRules.Count; i++)
            {
                if (nat.SnatRules[i] is not { } rule) { continue; }
                var path = $"nat.snatRules[{i.ToString(System.Globalization.CultureInfo.InvariantCulture)}]";
                if (rule.SourceObject is { } source) { result.Add(new(path + ".sourceObject", source)); }
                if (rule.DestinationObject is { } destination) { result.Add(new(path + ".destinationObject", destination)); }
                if (rule.DestinationPortObject is { } ports) { result.Add(new(path + ".destinationPortObject", ports)); }
            }
        }
        if (bundle.Bridge is { } bridge)
        {
            AddBridge(bridge.Rules, "bridge.rules");
            for (var i = 0; i < bridge.SubChains.Count; i++)
            { if (bridge.SubChains[i] is { } chain) { AddBridge(chain.Rules, $"bridge.subChains[{i.ToString(System.Globalization.CultureInfo.InvariantCulture)}].rules"); } }
        }
        return result.AsReadOnly();
        void AddBridge(IReadOnlyList<BridgeFilterRule?> rules, string path)
        {
            for (var i = 0; i < rules.Count; i++)
            {
                if (rules[i] is not { } rule) { continue; }
                var rulePath = $"{path}[{i.ToString(System.Globalization.CultureInfo.InvariantCulture)}]";
                if (rule.SourceObject is { } source) { result.Add(new(rulePath + ".sourceObject", source)); }
                if (rule.DestinationObject is { } destination) { result.Add(new(rulePath + ".destinationObject", destination)); }
                if (rule.DestinationPortObject is { } ports) { result.Add(new(rulePath + ".destinationPortObject", ports)); }
            }
        }
        void Add(FilterPolicy policy, string prefix)
        {
            for (var i = 0; i < policy.Rules.Count; i++)
            {
                if (policy.Rules[i] is not { } rule) { continue; }
                var path = prefix + ".rules[" + i.ToString(System.Globalization.CultureInfo.InvariantCulture) + "]";
                if (rule.SourceObject is { } source) { result.Add(new(path + ".sourceObject", source)); }
                if (rule.DestinationObject is { } destination) { result.Add(new(path + ".destinationObject", destination)); }
                if (rule.DestinationPortObject is { } ports) { result.Add(new(path + ".destinationPortObject", ports)); }
            }
        }
    }
}
