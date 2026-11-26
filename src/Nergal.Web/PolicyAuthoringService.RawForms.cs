using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web;

/// <summary>Complete raw prerouting rule draft; a null family matches either IP family.</summary>
internal sealed record VisualRawRuleInput(string? Family, string? Verdict, string? Protocol, string? Source,
    bool NegateSource, string? InputInterface, bool NegateInputInterface, int? SourcePort, int? DestinationPort,
    bool MatchFibUnreachable, string? Description);

internal static partial class PolicyAuthoringService
{
    internal static bool TrySetRawRule(string json, int? index, string operation, VisualRawRuleInput input,
        out string? updated, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updated = null;
        if (!TryDecodeBundle(json, out var bundle, out diagnostics) || bundle is null) { return false; }
        var rules = bundle.Filter.RpFilter?.Rules.ToList() ?? [];
        if (operation is not ("add" or "edit" or "remove" or "up" or "down") ||
            (operation == "add" ? index.HasValue : index is null || index < 0 || index >= rules.Count))
        { diagnostics = [new("rpfilter.operationInvalid", "filter.rpFilter.rules")]; return false; }
        if (operation is "up" or "down")
        {
            var from = index!.Value;
            var to = from + (operation == "up" ? -1 : 1);
            if (to < 0 || to >= rules.Count) { diagnostics = [new("rule.moveOutOfRange", "filter.rpFilter.rules")]; return false; }
            (rules[from], rules[to]) = (rules[to], rules[from]);
        }
        else if (operation == "remove") { rules.RemoveAt(index!.Value); }
        else
        {
            IpFamily? family = input.Family switch { "any" => null, "ipv4" => IpFamily.IPv4, "ipv6" => IpFamily.IPv6, _ => (IpFamily)(-1) };
            var verdict = input.Verdict switch { "accept" => FilterVerdict.Accept, "drop" => FilterVerdict.Drop, "notrack" => FilterVerdict.Continue, _ => (FilterVerdict)(-1) };
            var protocol = input.Protocol switch { "any" => FilterProtocol.Any, "tcp" => FilterProtocol.Tcp, "udp" => FilterProtocol.Udp, _ => (FilterProtocol)(-1) };
            var errors = new List<PolicyDiagnostic>();
            if (family.HasValue && !Enum.IsDefined(family.Value)) { errors.Add(new("family.unknown", "rule.family")); }
            if (!Enum.IsDefined(verdict)) { errors.Add(new("verdict.unknown", "rule.verdict")); }
            if (!Enum.IsDefined(protocol)) { errors.Add(new("protocol.unknown", "rule.protocol")); }
            NetworkPrefix? source = null;
            try { if (!string.IsNullOrWhiteSpace(input.Source)) { source = new(input.Source.Trim()); } }
            catch (ArgumentException) { errors.Add(new("network.invalid", "rule.source")); }
            if (!TryNormalizeDescription(input.Description, out var description)) { errors.Add(new("rule.descriptionInvalid", "rule.description")); }
            if (errors.Count != 0) { diagnostics = errors; return false; }
            var rule = new RpFilterRule(verdict, family, protocol, source, input.NegateSource, EmptyToNull(input.InputInterface),
                input.NegateInputInterface, input.SourcePort, input.DestinationPort, input.MatchFibUnreachable, description,
                index is not { } i || rules[i]!.Enabled, Notrack: verdict == FilterVerdict.Continue);
            if (index is { } existing) { rules[existing] = rule; } else { rules.Add(rule); }
        }
        return TryCompileRawSettings(bundle, new(bundle.Filter.RpFilter?.DefaultVerdict ?? FilterVerdict.Accept, rules),
            bundle.Filter.ForwardTcpMssClamp, bundle.Filter.ForwardTcpMssClampEnabled, out updated, out diagnostics);
    }

    internal static bool TrySetRawDefault(string json, string? verdict, out string? updated, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updated = null;
        if (!TryDecodeBundle(json, out var bundle, out diagnostics) || bundle is null) { return false; }
        if (verdict == "remove")
        {
            if (bundle.Filter.RpFilter is null || bundle.Filter.RpFilter.Rules.Count != 0)
            { diagnostics = [new("rpfilter.removeRequiresEmptyChain", "filter.rpFilter")]; return false; }
            return TryCompileRawSettings(bundle, null, bundle.Filter.ForwardTcpMssClamp, bundle.Filter.ForwardTcpMssClampEnabled, out updated, out diagnostics);
        }
        if (verdict is not ("accept" or "drop")) { diagnostics = [new("verdict.unknown", "filter.rpFilter.defaultVerdict")]; return false; }
        return TryCompileRawSettings(bundle, new(verdict == "accept" ? FilterVerdict.Accept : FilterVerdict.Drop, bundle.Filter.RpFilter?.Rules ?? []),
            bundle.Filter.ForwardTcpMssClamp, bundle.Filter.ForwardTcpMssClampEnabled, out updated, out diagnostics);
    }

    internal static bool TrySetMss(string json, string? operation, int? size, out string? updated, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updated = null;
        if (!TryDecodeBundle(json, out var bundle, out diagnostics) || bundle is null) { return false; }
        if (operation is not ("set" or "remove") || (operation == "set" ? size is null : size.HasValue))
        { diagnostics = [new("mss.formInvalid", "filter.forwardTcpMssClamp")]; return false; }
        var enabled = operation == "remove" || bundle.Filter.ForwardTcpMssClamp is null || bundle.Filter.ForwardTcpMssClampEnabled;
        return TryCompileRawSettings(bundle, bundle.Filter.RpFilter, size, enabled, out updated, out diagnostics);
    }

    internal static bool TrySetDnatConditions(string json, int index, bool source, bool destination, bool inputInterface,
        out string? updated, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updated = null;
        if (!TryDecodeBundle(json, out var bundle, out diagnostics) || bundle is null) { return false; }
        if (bundle.Nat is null || index < 0 || index >= bundle.Nat.DnatRules.Count || bundle.Nat.DnatRules[index] is not { } previous)
        { diagnostics = [new("rule.indexOutOfRange", "nat.dnatRules")]; return false; }
        var rules = bundle.Nat.DnatRules.ToArray();
        rules[index] = previous with { NegateSource = source, NegateDestination = destination, NegateInputInterface = inputInterface };
        var nat = new NatPolicy(bundle.Nat.SchemaVersion, rules, bundle.Nat.SnatRules);
        return TryCompileVisualBundle(new(bundle.SchemaVersion, bundle.Filter, nat, bundle.Bridge, bundle.AuxiliaryFilter), out updated, out diagnostics);
    }

    internal static bool TryMoveNatRule(string json, string? kind, int index, int direction,
        out string? updated, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updated = null;
        if (!TryDecodeBundle(json, out var bundle, out diagnostics) || bundle is null) { return false; }
        if (bundle.Nat is null || kind is not ("dnat" or "postrouting") || direction is not (-1 or 1))
        { diagnostics = [new("nat.moveInvalid", "nat")]; return false; }
        var dnats = bundle.Nat.DnatRules.ToArray();
        var snats = bundle.Nat.SnatRules.ToArray();
        var count = kind == "dnat" ? dnats.Length : snats.Length;
        if (index < 0 || index >= count || (direction == -1 ? index == 0 : index == count - 1))
        { diagnostics = [new("rule.moveOutOfRange", "nat")]; return false; }
        var target = index + direction;
        if (kind == "dnat") { (dnats[index], dnats[target]) = (dnats[target], dnats[index]); }
        else { (snats[index], snats[target]) = (snats[target], snats[index]); }
        return TryCompileVisualBundle(new(bundle.SchemaVersion, bundle.Filter, new(bundle.Nat.SchemaVersion, dnats, snats), bundle.Bridge, bundle.AuxiliaryFilter), out updated, out diagnostics);
    }

    private static bool TryCompileRawSettings(FirewallPolicyBundle bundle, RpFilterPolicy? raw, int? mss, bool mssEnabled,
        out string? updated, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        var filter = new FilterPolicy(bundle.Filter.SchemaVersion == 1 ? 2 : bundle.Filter.SchemaVersion, bundle.Filter.InputDefaultVerdict, bundle.Filter.ForwardDefaultVerdict,
            bundle.Filter.OutputDefaultVerdict, bundle.Filter.Rules, raw, mss, mssEnabled, bundle.Filter.RawOutput, bundle.Filter.RegularChains);
        return TryCompileVisualBundle(new(bundle.SchemaVersion, filter, bundle.Nat, bundle.Bridge, bundle.AuxiliaryFilter), out updated, out diagnostics);
    }
}
