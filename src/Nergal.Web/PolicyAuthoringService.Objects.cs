using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web;

internal static class PolicyObjectAuthoring
{
    internal static bool TrySet(string json, int index, string slot, PolicyObjectReference? reference, out string? updated, out IReadOnlyList<PolicyDiagnostic> diagnostics, string scope = "primary")
    {
        updated = null;
        if (!PolicyAuthoringService.TryDecodeBundle(json, out var bundle, out diagnostics) || bundle is null) { return false; }
        if (scope is not ("primary" or "auxiliary")) { diagnostics = [new("object.scopeInvalid", "scope")]; return false; }
        var path = scope == "auxiliary" ? "auxiliaryFilter.filter.rules" : "filter.rules";
        var current = scope switch { "primary" => bundle.Filter, "auxiliary" => bundle.AuxiliaryFilter?.Filter, _ => null };
        if (current is null || index < 0 || index >= current.Rules.Count || current.Rules[index] is not { } rule || slot is not ("source" or "destination" or "ports"))
        { diagnostics = [new("object.matcherInvalid", path)]; return false; }
        var existing = slot switch { "source" => rule.SourceObject, "destination" => rule.DestinationObject, _ => rule.DestinationPortObject };
        if (reference is null && existing is null) { diagnostics = [new("object.referenceMissing", path)]; return false; }
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
        var rules = current.Rules.ToArray(); rules[index] = changed;
        var filter = new FilterPolicy(current.SchemaVersion == 1 ? 2 : current.SchemaVersion, current.InputDefaultVerdict, current.ForwardDefaultVerdict, current.OutputDefaultVerdict, rules, current.RpFilter, current.ForwardTcpMssClamp, current.ForwardTcpMssClampEnabled);
        var next = scope == "primary"
            ? new FirewallPolicyBundle(bundle.SchemaVersion, filter, bundle.Nat, bundle.Bridge, bundle.AuxiliaryFilter)
            : new FirewallPolicyBundle(bundle.SchemaVersion, bundle.Filter, bundle.Nat, bundle.Bridge, new(bundle.AuxiliaryFilter!.Priority, filter));
        var compiled = NftPolicyBundleCompiler.Compile(next);
        diagnostics = compiled.Diagnostics;
        if (!compiled.IsSuccess) { return false; }
        updated = PolicyAuthoringService.EncodeBundle(next); return true;
    }
}
