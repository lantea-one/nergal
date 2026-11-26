using System.Globalization;
using System.Text;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

// Keep extended validation beside the compiler: no string reaches native syntax
// unless every matcher and cross-field dependency has been checked.
internal static class RouterFilterValidation
{
    internal static void Validate(FilterPolicy policy, List<PolicyDiagnostic> errors)
    {
        if (!policy.ForwardTcpMssClampEnabled && policy.ForwardTcpMssClamp is null) { errors.Add(new("mss.stateWithoutClamp", "forwardTcpMssClampEnabled")); }
        if (policy.ForwardTcpMssClamp is { } mss)
        {
            if (policy.SchemaVersion != 2) { errors.Add(new("mss.requiresSchema2", "forwardTcpMssClamp")); }
            if (mss is < 536 or > 1460) { errors.Add(new("mss.outOfRange", "forwardTcpMssClamp")); }
        }

        for (var i = 0; i < policy.Rules.Count; i++)
        {
            if (policy.Rules[i] is not { } r) { continue; }
            var path = $"rules[{i.ToString(CultureInfo.InvariantCulture)}]";
            var extended = r.Verdict is FilterVerdict.Reject or FilterVerdict.RejectPortUnreachable || r.NegateSource || r.NegateDestination ||
                r.NegateInputInterface || r.NegateOutputInterface || r.SourceMac is not null ||
                r.SourceMacs is not null || r.NegateSourceMac;
            if (policy.SchemaVersion != 2 && extended) { errors.Add(new("router.requiresSchema2", path)); }
            Require(r.NegateSource, r.Source is not null || r.SourcePrefixes is not null, path + ".negateSource", errors);
            Require(r.NegateDestination, r.Destination is not null || r.DestinationPrefixes is not null, path + ".negateDestination", errors);
            Require(r.NegateInputInterface, r.InputInterface is not null, path + ".negateInputInterface", errors);
            Require(r.NegateOutputInterface, r.OutputInterface is not null, path + ".negateOutputInterface", errors);
            Require(r.NegateSourceMac, r.SourceMac is not null || r.SourceMacs is not null, path + ".negateSourceMac", errors);
            if ((r.SourceMac is not null || r.SourceMacs is not null) && r.Chain == FilterChainKind.Output)
            { errors.Add(new("mac.chainMismatch", path + ".sourceMac")); }
            if (r.SourceMac is not null && r.SourceMacs is not null) { errors.Add(new("set.conflictsWithScalar", path + ".sourceMacs")); }
            if (r.SourceMacs is { } macs)
            {
                if (macs.Count < 2) { errors.Add(new("set.minElements", path + ".sourceMacs")); }
                if (macs.Count > 64) { errors.Add(new("set.tooManyElements", path + ".sourceMacs")); }
                if (macs.Any(m => m is null)) { errors.Add(new("set.nullElement", path + ".sourceMacs")); }
                if (macs.Distinct().Count() != macs.Count) { errors.Add(new("set.duplicate", path + ".sourceMacs")); }
            }
            if (r.RateLimit is { } rate && !Enum.IsDefined(rate.KeyKind))
            { errors.Add(new("rateLimit.keyUnknown", path + ".rateLimit.keyKind")); }
        }

        ValidateRawChain(policy.SchemaVersion, policy.RpFilter, false, errors);
        ValidateRawChain(policy.SchemaVersion, policy.RawOutput, true, errors);
    }

    private static void ValidateRawChain(int schemaVersion, RpFilterPolicy? rp, bool output, List<PolicyDiagnostic> errors)
    {
        if (rp is null) { return; }
        var chainPath = output ? "rawOutput" : "rpFilter";
        if (schemaVersion != 2) { errors.Add(new("rpfilter.requiresSchema2", chainPath)); }
        if (rp.DefaultVerdict is not (FilterVerdict.Accept or FilterVerdict.Drop))
        { errors.Add(new("verdict.unknown", chainPath + ".defaultVerdict")); }
        else if (rp.DefaultVerdict != FilterVerdict.Accept && (output || rp.Rules.Any(r => r?.Notrack == true)))
        { errors.Add(new("raw.requiresAcceptDefault", chainPath + ".defaultVerdict")); }
        if (rp.Rules.Count > 4096) { errors.Add(new("rpfilter.tooManyRules", chainPath + ".rules")); return; }
        for (var i = 0; i < rp.Rules.Count; i++)
        {
            var path = $"{chainPath}.rules[{i.ToString(CultureInfo.InvariantCulture)}]";
            if (rp.Rules[i] is not { } r) { errors.Add(new("rule.required", path)); continue; }
            if (r.Notrack && r.Verdict != FilterVerdict.Continue)
            { errors.Add(new("raw.notrackRequiresContinue", path + ".verdict")); }
            else if (!r.Notrack && r.Verdict is not (FilterVerdict.Accept or FilterVerdict.Drop))
            { errors.Add(new("verdict.unknown", path + ".verdict")); }
            if (r.Family is { } family && family is not (IpFamily.IPv4 or IpFamily.IPv6)) { errors.Add(new("family.unknown", path + ".family")); }
            if (r.Protocol is not (FilterProtocol.Any or FilterProtocol.Tcp or FilterProtocol.Udp))
            { errors.Add(new("protocol.unknown", path + ".protocol")); }
            if (r.Source is not null && r.Source.Family != r.Family) { errors.Add(new("network.familyMismatch", path + ".source")); }
            if (r.InputInterface is not null && !FilterPolicyValidation.IsValidInterfaceName(r.InputInterface))
            { errors.Add(new("interface.invalid", path + ".inputInterface")); }
            if (r.OutputInterface is not null && !FilterPolicyValidation.IsValidInterfaceName(r.OutputInterface))
            { errors.Add(new("interface.invalid", path + ".outputInterface")); }
            if (output && r.InputInterface is not null) { errors.Add(new("interface.chainMismatch", path + ".inputInterface")); }
            if (!output && r.OutputInterface is not null) { errors.Add(new("interface.chainMismatch", path + ".outputInterface")); }
            if (output && r.MatchFibUnreachable) { errors.Add(new("fib.chainMismatch", path + ".matchFibUnreachable")); }
            Require(r.NegateOutputInterface, r.OutputInterface is not null, path + ".negateOutputInterface", errors);
            Require(r.NegateSource, r.Source is not null, path + ".negateSource", errors);
            Require(r.NegateInputInterface, r.InputInterface is not null, path + ".negateInputInterface", errors);
            foreach (var (port, name) in new[] { (r.SourcePort, "sourcePort"), (r.DestinationPort, "destinationPort") })
            {
                if (port is < 1 or > 65535) { errors.Add(new("port.outOfRange", path + "." + name)); }
                if (port.HasValue && r.Protocol is not (FilterProtocol.Tcp or FilterProtocol.Udp))
                { errors.Add(new("port.requiresTransport", path + "." + name)); }
            }
            if (r.Description is { } description && (description.Length > 160 || description.Any(char.IsControl)))
            { errors.Add(new("description.invalid", path + ".description")); }
        }
    }

    internal static void Require(bool negate, bool hasMatcher, string path, List<PolicyDiagnostic> errors)
    {
        if (negate && !hasMatcher) { errors.Add(new("negation.requiresMatcher", path)); }
    }

    internal static void AppendRawRule(StringBuilder text, RpFilterRule r, bool output)
    {
        text.Append("add rule inet " + NftFilterCompiler.TableName).Append(output ? " raw_output " : " rpfilter ");
        if (r.Family is { } family) { text.Append("meta nfproto ").Append(family == IpFamily.IPv4 ? "ipv4 " : "ipv6 "); }
        if (r.InputInterface is not null)
        { text.Append("iifname ").Append(r.NegateInputInterface ? "!= " : "").Append('"').Append(r.InputInterface).Append("\" "); }
        if (r.OutputInterface is not null)
        { text.Append("oifname ").Append(r.NegateOutputInterface ? "!= " : "").Append('"').Append(r.OutputInterface).Append("\" "); }
        if (r.Source is not null)
        { text.Append(r.Family == IpFamily.IPv4 ? "ip saddr " : "ip6 saddr ").Append(r.NegateSource ? "!= " : "").Append(r.Source.Value).Append(' '); }
        var protocol = r.Protocol == FilterProtocol.Tcp ? "tcp" : "udp";
        if (r.Protocol != FilterProtocol.Any && r.SourcePort is null && r.DestinationPort is null)
        { text.Append("meta l4proto ").Append(protocol).Append(' '); }
        if (r.SourcePort is { } sport) { text.Append(protocol).Append(" sport ").Append(sport.ToString(CultureInfo.InvariantCulture)).Append(' '); }
        if (r.DestinationPort is { } dport) { text.Append(protocol).Append(" dport ").Append(dport.ToString(CultureInfo.InvariantCulture)).Append(' '); }
        if (r.MatchFibUnreachable) { text.Append("fib saddr . iif oif == 0 "); }
        text.Append(r.Notrack ? "notrack\n" : r.Verdict == FilterVerdict.Accept ? "accept\n" : "drop\n");
    }
}
