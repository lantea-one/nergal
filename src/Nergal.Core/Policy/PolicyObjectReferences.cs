namespace Nergal.Core.Policy;

/// <summary>A pinned object matcher location within a self-contained policy bundle.</summary>
public sealed record PolicyObjectBinding(string Path, PolicyObjectReference Reference);

/// <summary>Enumerates controller references without resolving them or altering policy intent.</summary>
public static class PolicyObjectReferences
{
    /// <summary>Returns primary and auxiliary inet filter references in stable rule/field order.</summary>
    public static IReadOnlyList<PolicyObjectBinding> Enumerate(FirewallPolicyBundle bundle)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        var result = new List<PolicyObjectBinding>();
        Add(bundle.Filter, "filter"); if (bundle.AuxiliaryFilter is { } aux) { Add(aux.Filter, "auxiliaryFilter.filter"); }
        return result.AsReadOnly();
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
