using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web;

/// <summary>Explicit matcher-only edit; existing addresses, ports, list pins and lifecycle state are retained.</summary>
internal sealed record VisualFilterConditionsInput(string? SourceMacs, bool NegateSourceMac, bool NegateSource,
    bool NegateDestination, bool NegateInputInterface, bool NegateOutputInterface, string? RateLimitKey, bool? RefreshEntryTimeout = null);

/// <summary>Complete postrouting form. Empty optional matchers mean any; translation is allowed only for explicit SNAT.</summary>
internal sealed record VisualPostroutingInput(string? Family, string? Action, string? Source, string? Destination,
    string? TranslatedAddress, string? InputInterface, string? OutputInterface, string? Protocol, string? DestinationPorts,
    bool NegateSource, bool NegateDestination, bool NegateInputInterface, bool NegateOutputInterface, string? Description);

internal static partial class PolicyAuthoringService
{
    internal static bool TryUpdateFilterConditions(string json, int index, VisualFilterConditionsInput input,
        out string? updated, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updated = null;
        if (!TryDecodeBundle(json, out var bundle, out diagnostics) || bundle is null) { return false; }
        if (index < 0 || index >= bundle.Filter.Rules.Count || bundle.Filter.Rules[index] is not { } previous)
        { diagnostics = [new("rule.indexOutOfRange", "filter.rules")]; return false; }
        if (!TryApplyVisualConditions(previous, input, out var rule, out diagnostics)) { return false; }
        var rules = bundle.Filter.Rules.ToArray();
        rules[index] = rule;
        var filter = new FilterPolicy(bundle.Filter.SchemaVersion == 1 ? 2 : bundle.Filter.SchemaVersion, bundle.Filter.InputDefaultVerdict, bundle.Filter.ForwardDefaultVerdict,
            bundle.Filter.OutputDefaultVerdict, rules, bundle.Filter.RpFilter, bundle.Filter.ForwardTcpMssClamp, bundle.Filter.ForwardTcpMssClampEnabled);
        return TryCompileVisualBundle(new(bundle.SchemaVersion, filter, bundle.Nat, bundle.Bridge, bundle.AuxiliaryFilter), out updated, out diagnostics);
    }

    private static bool TryApplyVisualConditions(FilterRule previous, VisualFilterConditionsInput input,
        out FilterRule? rule, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        rule = null;
        var macs = new List<MacAddress>();
        foreach (var token in (input.SourceMacs ?? "").Split([',', ' ', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!MacAddress.TryParse(token, out var mac)) { diagnostics = [new("mac.invalid", "rule.sourceMacs")]; return false; }
            macs.Add(mac!);
        }
        if (input.RateLimitKey is not ("sourceAddress" or "destinationAddress"))
        { diagnostics = [new("rateLimit.keyUnknown", "rule.rateLimit.keyKind")]; return false; }
        var key = input.RateLimitKey == "destinationAddress" ? RateLimitKeyKind.DestinationAddress : RateLimitKeyKind.SourceAddress;
        if (previous.RateLimit is null && (key != RateLimitKeyKind.SourceAddress || input.RefreshEntryTimeout == true))
        { diagnostics = [new("rateLimit.required", "rule.rateLimit")]; return false; }
        rule = previous with
        {
            SourceMac = macs.Count == 1 ? macs[0] : null,
            SourceMacs = macs.Count > 1 ? macs : null,
            NegateSourceMac = input.NegateSourceMac,
            NegateSource = input.NegateSource,
            NegateDestination = input.NegateDestination,
            NegateInputInterface = input.NegateInputInterface,
            NegateOutputInterface = input.NegateOutputInterface,
            RateLimit = previous.RateLimit is null ? null : previous.RateLimit with { KeyKind = key, RefreshEntryTimeout = input.RefreshEntryTimeout ?? previous.RateLimit.RefreshEntryTimeout },
        };
        diagnostics = [];
        return true;
    }

    internal static bool TrySetPostrouting(string json, int? index, VisualPostroutingInput input,
        out string? updated, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updated = null;
        if (!TryDecodeBundle(json, out var bundle, out diagnostics) || bundle is null) { return false; }
        var rules = bundle.Nat?.SnatRules.ToList() ?? [];
        if (index is { } i && (i < 0 || i >= rules.Count || rules[i] is null))
        { diagnostics = [new("rule.indexOutOfRange", "nat.snatRules")]; return false; }
        if (!TryParseFamily(input.Family, out var family))
        { diagnostics = [new("family.unknown", "nat.snatRules")]; return false; }
        var action = input.Action switch
        {
            "snat" => NatPostroutingAction.Snat,
            "masquerade" => NatPostroutingAction.Masquerade,
            "return" => NatPostroutingAction.Return,
            _ => (NatPostroutingAction)(-1),
        };
        var protocol = input.Protocol switch
        {
            "any" => FilterProtocol.Any,
            "tcp" => FilterProtocol.Tcp,
            "udp" => FilterProtocol.Udp,
            _ => (FilterProtocol)(-1),
        };
        var errors = new List<PolicyDiagnostic>();
        if (!Enum.IsDefined(action)) { errors.Add(new("nat.actionUnknown", "rule.action")); }
        if (!Enum.IsDefined(protocol)) { errors.Add(new("protocol.unknown", "rule.protocol")); }
        TryParsePrefixField(input.Source, "rule.source", out var source, out var sourcePrefixes, errors);
        TryParsePrefixField(input.Destination, "rule.destination", out var destination, out var destinationPrefixes, errors);
        TryParsePortField(input.DestinationPorts, "rule.destinationPorts", out var port, out var ports, errors);
        if (!TryNormalizeDescription(input.Description, out var description)) { errors.Add(new("rule.descriptionInvalid", "rule.description")); }
        if (errors.Count != 0) { diagnostics = errors; return false; }
        var rule = new SnatRule(family, source, EmptyToNull(input.TranslatedAddress), destination,
            EmptyToNull(input.OutputInterface), description, action, EmptyToNull(input.InputInterface), protocol, port, ports,
            input.NegateSource, input.NegateDestination, input.NegateInputInterface, input.NegateOutputInterface,
            index is not { } position || rules[position]!.Enabled, index is { } old ? rules[old]!.DestinationPortObject : null,
            sourcePrefixes, destinationPrefixes, index is { } oldSource ? rules[oldSource]!.SourceObject : null,
            index is { } oldDestination ? rules[oldDestination]!.DestinationObject : null);
        if (index is { } existing) { rules[existing] = rule; } else { rules.Add(rule); }
        var nat = new NatPolicy(NatPolicy.CurrentSchemaVersion, bundle.Nat?.DnatRules ?? [], rules);
        return TryCompileVisualBundle(new(bundle.SchemaVersion, bundle.Filter, nat, bundle.Bridge, bundle.AuxiliaryFilter), out updated, out diagnostics);
    }

    private static string? EmptyToNull(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static bool TryCompileVisualBundle(FirewallPolicyBundle bundle, out string? updated, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        var compiled = NftPolicyBundleCompiler.Compile(bundle);
        diagnostics = compiled.Diagnostics;
        updated = compiled.IsSuccess ? EncodeBundle(bundle) : null;
        return compiled.IsSuccess;
    }
}
