using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web;

internal static class PolicyObjectAuthoring
{
    internal static bool TrySet(string json, int index, string slot, PolicyObjectReference? reference, out string? updated, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updated = null;
        if (!PolicyAuthoringService.TryDecodeBundle(json, out var bundle, out diagnostics) || bundle is null) { return false; }
        if (index < 0 || index >= bundle.Filter.Rules.Count || bundle.Filter.Rules[index] is not { } rule || slot is not ("source" or "destination" or "ports"))
        { diagnostics = [new("object.matcherInvalid", "filter.rules")]; return false; }
        var existing = slot switch { "source" => rule.SourceObject, "destination" => rule.DestinationObject, _ => rule.DestinationPortObject };
        if (reference is null && existing is null) { diagnostics = [new("object.referenceMissing", "filter.rules")]; return false; }
        var changed = slot switch
        {
            "source" => rule with { Source = null, SourcePrefixes = null, SourceObject = reference },
            "destination" => rule with { Destination = null, DestinationPrefixes = null, DestinationObject = reference },
            _ => rule with { DestinationPort = null, DestinationPorts = null, DestinationPortObject = reference }
        };
        // Removing a negated matcher must remove its negation too; retaining it would be invalid, never a broad implicit accept.
        if (reference is null)
        {
            changed = slot switch { "source" => changed with { NegateSource = false }, "destination" => changed with { NegateDestination = false }, _ => changed };
        }
        var rules = bundle.Filter.Rules.ToArray(); rules[index] = changed;
        var filter = new FilterPolicy(2, bundle.Filter.InputDefaultVerdict, bundle.Filter.ForwardDefaultVerdict, bundle.Filter.OutputDefaultVerdict, rules, bundle.Filter.RpFilter, bundle.Filter.ForwardTcpMssClamp);
        var next = new FirewallPolicyBundle(bundle.SchemaVersion, filter, bundle.Nat, bundle.Bridge, bundle.AuxiliaryFilter);
        var compiled = NftPolicyBundleCompiler.Compile(next);
        diagnostics = compiled.Diagnostics;
        if (!compiled.IsSuccess) { return false; }
        updated = PolicyAuthoringService.EncodeBundle(next); return true;
    }
}
