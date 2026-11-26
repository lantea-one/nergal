using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web;

internal static partial class PolicyAuthoringService
{
    internal static bool TrySetAuxiliaryDefaults(string json, string? operation, int? priority, string? inputDefault,
        string? forwardDefault, string? outputDefault, out string? updated, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updated = null;
        if (!TryDecodeBundle(json, out var bundle, out diagnostics) || bundle is null) { return false; }
        if (operation == "remove")
        {
            if (bundle.AuxiliaryFilter is null || bundle.AuxiliaryFilter.Filter.Rules.Count != 0 || bundle.AuxiliaryFilter.Filter.RegularChains.Count != 0 ||
                bundle.AuxiliaryFilter.Filter.RpFilter is not null || bundle.AuxiliaryFilter.Filter.RawOutput is not null ||
                priority.HasValue || inputDefault is not null || forwardDefault is not null || outputDefault is not null)
            { diagnostics = [new("auxiliary.removeRequiresEmptyTable", "auxiliaryFilter")]; return false; }
            return TryCompileVisualBundle(new(bundle.SchemaVersion, bundle.Filter, bundle.Nat, bundle.Bridge), out updated, out diagnostics);
        }
        if (operation != "set" || priority is null || !TryReadBaseVerdict(inputDefault, out var input) ||
            !TryReadBaseVerdict(forwardDefault, out var forward) || !TryReadBaseVerdict(outputDefault, out var output))
        { diagnostics = [new("auxiliary.defaultsInvalid", "auxiliaryFilter")]; return false; }
        var previous = bundle.AuxiliaryFilter?.Filter;
        var auxiliary = new AuxiliaryFilterPolicy(priority.Value, new(previous?.SchemaVersion ?? 2, input, forward, output, previous?.Rules ?? [],
            previous?.RpFilter, previous?.ForwardTcpMssClamp, previous?.ForwardTcpMssClampEnabled ?? true, previous?.RawOutput, previous?.RegularChains));
        return TryCompileVisualBundle(new(bundle.SchemaVersion, bundle.Filter, bundle.Nat, bundle.Bridge, auxiliary), out updated, out diagnostics);
    }

    internal static bool TrySetAuxiliaryRule(string json, string? operation, int? index, VisualFilterRuleInput input,
        VisualFilterConditionsInput conditions, out string? updated, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updated = null;
        if (!TryDecodeBundle(json, out var bundle, out diagnostics) || bundle is null) { return false; }
        if (bundle.AuxiliaryFilter is not { } auxiliary || operation is not ("add" or "edit" or "remove" or "up" or "down"))
        { diagnostics = [new("auxiliary.operationInvalid", "auxiliaryFilter")]; return false; }
        var rules = auxiliary.Filter.Rules.ToList();
        if (operation == "add" ? index.HasValue : index is null || index < 0 || index >= rules.Count)
        { diagnostics = [new("rule.indexOutOfRange", "auxiliaryFilter.rules")]; return false; }
        if (operation == "remove") { rules.RemoveAt(index!.Value); }
        else if (operation is "up" or "down")
        {
            var from = index!.Value; var to = from + (operation == "up" ? -1 : 1);
            if (to < 0 || to >= rules.Count) { diagnostics = [new("rule.moveOutOfRange", "auxiliaryFilter.rules")]; return false; }
            (rules[from], rules[to]) = (rules[to], rules[from]);
        }
        else
        {
            if (index is { } existingIndex && rules[existingIndex]?.Verdict == FilterVerdict.ClampRouteMss)
            { diagnostics = [new("mss.routeRuleUsesStructuredEditor", "auxiliaryFilter.filter.rules")]; return false; }
            if (!TryParseVisualRule(input, out var rule, out diagnostics) || rule is null) { return false; }
            if (index is { } position && rules[position] is { } previous)
            {
                if (previous.Chain == FilterChainKind.Regular || previous.Verdict == FilterVerdict.Jump)
                { diagnostics = [new("filter.regularChainRequiresTypedEdit", "rules")]; return false; }
                rule = rule with
                {
                    Enabled = previous.Enabled,
                    CountPackets = previous.CountPackets,
                    OriginalSourcePrefixes = previous.OriginalSourcePrefixes,
                    OriginalDestinationPrefixes = previous.OriginalDestinationPrefixes,
                    BindInputInterfaceIndex = previous.BindInputInterfaceIndex && rule.InputInterface is not null,
                    SourceObject = previous.SourceObject,
                    DestinationObject = previous.DestinationObject,
                    DestinationPortObject = previous.DestinationPortObject,
                    RateLimit = rule.RateLimit is null ? null : rule.RateLimit with { RefreshEntryTimeout = conditions.RefreshEntryTimeout ?? previous.RateLimit?.RefreshEntryTimeout ?? false },
                };
            }
            if (!TryApplyVisualConditions(rule, conditions, out rule, out diagnostics)) { return false; }
            if (index is { } existing) { rules[existing] = rule; } else { rules.Add(rule); }
        }
        var filter = new FilterPolicy(auxiliary.Filter.SchemaVersion, auxiliary.Filter.InputDefaultVerdict, auxiliary.Filter.ForwardDefaultVerdict,
            auxiliary.Filter.OutputDefaultVerdict, rules, auxiliary.Filter.RpFilter, auxiliary.Filter.ForwardTcpMssClamp, auxiliary.Filter.ForwardTcpMssClampEnabled, auxiliary.Filter.RawOutput, auxiliary.Filter.RegularChains);
        return TryCompileVisualBundle(new(bundle.SchemaVersion, bundle.Filter, bundle.Nat, bundle.Bridge, new(auxiliary.Priority, filter)), out updated, out diagnostics);
    }

    private static bool TryReadBaseVerdict(string? value, out FilterVerdict verdict)
    {
        verdict = value == "accept" ? FilterVerdict.Accept : FilterVerdict.Drop;
        return value is "accept" or "drop";
    }
}
