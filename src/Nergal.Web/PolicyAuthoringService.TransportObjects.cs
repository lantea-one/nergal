using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web;

internal static partial class PolicyObjectAuthoring
{
    private static bool TrySetTransport(FirewallPolicyBundle bundle, int index, string slot, PolicyObjectReference? reference,
        string scope, string? chain, out string? updated, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updated = null;
        diagnostics = [new("object.matcherInvalid", "object")];
        if (slot != "ports" || (scope == "bridgeChain" ? string.IsNullOrEmpty(chain) : chain is not null)) { return false; }
        FirewallPolicyBundle next;
        if (scope == "postrouting")
        {
            if (bundle.Nat is not { } nat || index < 0 || index >= nat.SnatRules.Count || nat.SnatRules[index] is not { } rule) { return false; }
            if (reference is null && rule.DestinationPortObject is null) { diagnostics = [new("object.referenceMissing", "nat.snatRules")]; return false; }
            var rules = nat.SnatRules.ToArray();
            rules[index] = rule with { DestinationPort = null, DestinationPorts = null, DestinationPortObject = reference };
            next = new(bundle.SchemaVersion, bundle.Filter, new(nat.SchemaVersion, nat.DnatRules, rules), bundle.Bridge, bundle.AuxiliaryFilter);
        }
        else
        {
            if (bundle.Bridge is not { } bridge) { return false; }
            var matches = bridge.SubChains.Where(c => c.Name == chain).ToArray();
            if (scope == "bridgeChain" && matches.Length != 1) { return false; }
            var rules = (scope == "bridge" ? bridge.Rules : matches[0].Rules).ToArray();
            if (index < 0 || index >= rules.Length || rules[index] is not { } rule) { return false; }
            if (reference is null && rule.DestinationPortObject is null) { diagnostics = [new("object.referenceMissing", "bridge")]; return false; }
            rules[index] = rule with { DestinationPort = null, DestinationPorts = null, DestinationPortObject = reference };
            var chains = bridge.SubChains.Select(c => scope == "bridgeChain" && c.Name == chain ? new BridgeSubChain(c.Name, rules) : c);
            var changed = new BridgePolicy(bridge.SchemaVersion, bridge.DefaultVerdict, scope == "bridge" ? rules : bridge.Rules, bridge.Priority, chains);
            next = new(bundle.SchemaVersion, bundle.Filter, bundle.Nat, changed, bundle.AuxiliaryFilter);
        }
        var compiled = NftPolicyBundleCompiler.Compile(next);
        diagnostics = compiled.Diagnostics;
        if (!compiled.IsSuccess) { return false; }
        updated = PolicyAuthoringService.EncodeBundle(next);
        return true;
    }
}
