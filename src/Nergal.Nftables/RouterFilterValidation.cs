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
            var extended = r.Verdict == FilterVerdict.Reject || r.NegateSource || r.NegateDestination ||
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

        if (policy.RpFilter is not { } rp) { return; }
        if (policy.SchemaVersion != 2) { errors.Add(new("rpfilter.requiresSchema2", "rpFilter")); }
        if (rp.DefaultVerdict is not (FilterVerdict.Accept or FilterVerdict.Drop))
        { errors.Add(new("verdict.unknown", "rpFilter.defaultVerdict")); }
        if (rp.Rules.Count > 4096) { errors.Add(new("rpfilter.tooManyRules", "rpFilter.rules")); }
        for (var i = 0; i < rp.Rules.Count; i++)
        {
            var path = $"rpFilter.rules[{i.ToString(CultureInfo.InvariantCulture)}]";
            if (rp.Rules[i] is not { } r) { errors.Add(new("rule.required", path)); continue; }
            if (r.Verdict is not (FilterVerdict.Accept or FilterVerdict.Drop)) { errors.Add(new("verdict.unknown", path + ".verdict")); }
            if (r.Family is { } family && !Enum.IsDefined(family)) { errors.Add(new("family.unknown", path + ".family")); }
            if (r.Protocol is not (FilterProtocol.Any or FilterProtocol.Tcp or FilterProtocol.Udp))
            { errors.Add(new("protocol.unknown", path + ".protocol")); }
            if (r.Source is not null && r.Source.Family != r.Family) { errors.Add(new("network.familyMismatch", path + ".source")); }
            if (r.InputInterface is not null && !FilterPolicyValidation.IsValidInterfaceName(r.InputInterface))
            { errors.Add(new("interface.invalid", path + ".inputInterface")); }
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

    internal static void AppendRpFilterRule(StringBuilder text, RpFilterRule r)
    {
        text.Append("add rule inet " + NftFilterCompiler.TableName + " rpfilter ");
        if (r.Family is { } family) { text.Append("meta nfproto ").Append(family == IpFamily.IPv4 ? "ipv4 " : "ipv6 "); }
        if (r.InputInterface is not null)
        { text.Append("iifname ").Append(r.NegateInputInterface ? "!= " : "").Append('"').Append(r.InputInterface).Append("\" "); }
        if (r.Source is not null)
        { text.Append(r.Family == IpFamily.IPv4 ? "ip saddr " : "ip6 saddr ").Append(r.NegateSource ? "!= " : "").Append(r.Source.Value).Append(' '); }
        var protocol = r.Protocol == FilterProtocol.Tcp ? "tcp" : "udp";
        if (r.Protocol != FilterProtocol.Any && r.SourcePort is null && r.DestinationPort is null)
        { text.Append("meta l4proto ").Append(protocol).Append(' '); }
        if (r.SourcePort is { } sport) { text.Append(protocol).Append(" sport ").Append(sport.ToString(CultureInfo.InvariantCulture)).Append(' '); }
        if (r.DestinationPort is { } dport) { text.Append(protocol).Append(" dport ").Append(dport.ToString(CultureInfo.InvariantCulture)).Append(' '); }
        if (r.MatchFibUnreachable) { text.Append("fib saddr . iif oif == 0 "); }
        text.Append(r.Verdict == FilterVerdict.Accept ? "accept\n" : "drop\n");
    }
}
