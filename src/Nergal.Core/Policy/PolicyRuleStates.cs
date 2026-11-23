using System.Globalization;

namespace Nergal.Core.Policy;

/// <summary>Explicit rule collections supported by versioned enabled-state transformations.</summary>
public enum PolicyRuleScope
{
    /// <summary>Primary inet input/forward/output filter rules.</summary>
    Filter,
    /// <summary>Primary raw prerouting rules.</summary>
    Raw,
    /// <summary>Configured forward SYN MSS clamp (index zero).</summary>
    Mss,
    /// <summary>Independent early inet filter rules.</summary>
    Auxiliary,
    /// <summary>Prerouting destination NAT rules.</summary>
    Dnat,
    /// <summary>Ordered postrouting SNAT/masquerade/return rules.</summary>
    Postrouting,
    /// <summary>Bridge base forward-chain rules.</summary>
    Bridge,
    /// <summary>Rules in one explicitly named bridge regular chain.</summary>
    BridgeChain
}

/// <summary>A rule location and retained enabled state, independent of browser or native host operations.</summary>
public sealed record PolicyRuleState(PolicyRuleScope Scope, int Index, string? Chain, bool Enabled, string Label);

/// <summary>Enumerates and changes rule state without deleting rules, changing order or losing matcher metadata.</summary>
public static class PolicyRuleStates
{
    /// <summary>Lists every authored rule and configured MSS clamp in deterministic collection order.</summary>
    public static IReadOnlyList<PolicyRuleState> Enumerate(FirewallPolicyBundle bundle)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        var states = new List<PolicyRuleState>();
        Add(PolicyRuleScope.Filter, bundle.Filter.Rules.Select(r => r?.Enabled), "Filter");
        if (bundle.Filter.RpFilter is { } raw) { Add(PolicyRuleScope.Raw, raw.Rules.Select(r => r?.Enabled), "Raw prerouting"); }
        if (bundle.Filter.ForwardTcpMssClamp is not null) { states.Add(new(PolicyRuleScope.Mss, 0, null, bundle.Filter.ForwardTcpMssClampEnabled, "Forward SYN MSS clamp")); }
        if (bundle.AuxiliaryFilter is { } auxiliary) { Add(PolicyRuleScope.Auxiliary, auxiliary.Filter.Rules.Select(r => r?.Enabled), "Early inet filter"); }
        if (bundle.Nat is { } nat)
        {
            Add(PolicyRuleScope.Dnat, nat.DnatRules.Select(r => r?.Enabled), "DNAT");
            Add(PolicyRuleScope.Postrouting, nat.SnatRules.Select(r => r?.Enabled), "Postrouting");
        }
        if (bundle.Bridge is { } bridge)
        {
            Add(PolicyRuleScope.Bridge, bridge.Rules.Select(r => r?.Enabled), "Bridge forward");
            foreach (var chain in bridge.SubChains) { Add(PolicyRuleScope.BridgeChain, chain.Rules.Select(r => r?.Enabled), "Bridge " + chain.Name, chain.Name); }
        }
        return states.AsReadOnly();
        void Add(PolicyRuleScope scope, IEnumerable<bool?> values, string label, string? chain = null)
        {
            var index = 0;
            foreach (var value in values)
            {
                if (value.HasValue) { states.Add(new(scope, index, chain, value.Value, label + " rule " + (index + 1).ToString(CultureInfo.InvariantCulture))); }
                index++;
            }
        }
    }

    /// <summary>Returns a defensive bundle with exactly one retained rule state changed.</summary>
    /// <exception cref="ArgumentException">The scope, index or chain does not identify an existing rule.</exception>
    /// <exception cref="ArgumentNullException">Bundle is null.</exception>
    public static FirewallPolicyBundle SetEnabled(FirewallPolicyBundle bundle, PolicyRuleScope scope, int index, string? chain, bool enabled)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        if (!Enumerate(bundle).Any(s => s.Scope == scope && s.Index == index && s.Chain == chain)) { throw new ArgumentException("rule.stateLocationInvalid"); }
        var filter = bundle.Filter; var nat = bundle.Nat; var bridge = bundle.Bridge; var auxiliary = bundle.AuxiliaryFilter;
        switch (scope)
        {
            case PolicyRuleScope.Filter: filter = ChangeFilter(filter, index); break;
            case PolicyRuleScope.Raw:
                var rawRules = filter.RpFilter!.Rules.ToArray(); rawRules[index] = rawRules[index]! with { Enabled = enabled };
                filter = Copy(filter, raw: new(filter.RpFilter.DefaultVerdict, rawRules)); break;
            case PolicyRuleScope.Mss: filter = Copy(filter, mssEnabled: enabled); break;
            case PolicyRuleScope.Auxiliary: auxiliary = new(auxiliary!.Priority, ChangeFilter(auxiliary.Filter, index)); break;
            case PolicyRuleScope.Dnat:
                var dnats = nat!.DnatRules.ToArray(); dnats[index] = dnats[index]! with { Enabled = enabled };
                nat = new(nat.SchemaVersion, dnats, nat.SnatRules); break;
            case PolicyRuleScope.Postrouting:
                var snats = nat!.SnatRules.ToArray(); snats[index] = snats[index]! with { Enabled = enabled };
                nat = new(nat.SchemaVersion, nat.DnatRules, snats); break;
            case PolicyRuleScope.Bridge:
                var rules = bridge!.Rules.ToArray(); rules[index] = rules[index]! with { Enabled = enabled };
                bridge = new(bridge.SchemaVersion, bridge.DefaultVerdict, rules, bridge.Priority, bridge.SubChains); break;
            case PolicyRuleScope.BridgeChain:
                var chains = bridge!.SubChains.Select(c =>
                {
                    if (c.Name != chain) { return c; }
                    var nested = c.Rules.ToArray(); nested[index] = nested[index]! with { Enabled = enabled }; return new BridgeSubChain(c.Name, nested);
                });
                bridge = new(bridge.SchemaVersion, bridge.DefaultVerdict, bridge.Rules, bridge.Priority, chains); break;
            default: throw new ArgumentException("rule.stateLocationInvalid");
        }
        return new(bundle.SchemaVersion, filter, nat, bridge, auxiliary);
        FilterPolicy ChangeFilter(FilterPolicy original, int position)
        {
            var rules = original.Rules.ToArray(); rules[position] = rules[position]! with { Enabled = enabled };
            return Copy(original, rules);
        }
    }

    private static FilterPolicy Copy(FilterPolicy policy, IEnumerable<FilterRule?>? rules = null, RpFilterPolicy? raw = null, bool? mssEnabled = null) =>
        new(policy.SchemaVersion, policy.InputDefaultVerdict, policy.ForwardDefaultVerdict, policy.OutputDefaultVerdict, rules ?? policy.Rules,
            raw ?? policy.RpFilter, policy.ForwardTcpMssClamp, mssEnabled ?? policy.ForwardTcpMssClampEnabled);
}
