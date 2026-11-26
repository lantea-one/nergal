using System.Globalization;
using System.Text;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

/// <summary>Compiles dual-stack DNAT and ordered postrouting translation/exemption policies without executing commands or observing host state.</summary>
public static class NftNatCompiler
{
    /// <summary>The reserved inet NAT table name. Preexisting tables are never adopted or overwritten.</summary>
    public const string TableName = "nergal_nat";

    /// <summary>Validates all DNAT and SNAT rules before emitting a deterministic create-only native batch.</summary>
    /// <param name="policy">A typed NAT snapshot; unknown or mismatched rules fail closed.</param>
    /// <returns>A complete candidate batch or ordered diagnostics with no partial output.</returns>
    /// <exception cref="ArgumentNullException">The policy is null.</exception>
    public static CompilationResult Compile(NatPolicy policy) => CompileCore(policy, null);

    /// <summary>Compiles a create-only NAT candidate carrying a canonical owner/resource marker.</summary>
    /// <param name="policy">A typed NAT snapshot.</param>
    /// <param name="identity">Canonical owner/resource table marker.</param>
    /// <exception cref="ArgumentNullException">Policy or identity is null.</exception>
    public static CompilationResult Compile(NatPolicy policy, NftTableIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return CompileCore(policy, identity);
    }

    private static CompilationResult CompileCore(NatPolicy policy, NftTableIdentity? identity)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var intent = policy;
        var referenceErrors = new List<PolicyObjectDiagnostic>();
        policy = TransportObjectResolver.Resolve(policy, referenceErrors);
        if (referenceErrors.Count != 0) { return new(null, referenceErrors.Select(d => new PolicyDiagnostic(d.Code, d.Path)).ToArray()); }

        var errors = new List<PolicyDiagnostic>();
        var sets = new NftStaticSetPlan(intent.DnatRules.SelectMany(NftStaticSetPlan.References).Concat(intent.SnatRules.SelectMany(NftStaticSetPlan.References)), errors);
        if (policy.SchemaVersion != NatPolicy.CurrentSchemaVersion)
        {
            errors.Add(new("schema.unsupported", "schemaVersion"));
        }

        RouterNatValidation.Validate(policy, errors);

        var normalizedDnat = new List<(DnatRule Rule, string NormalizedAddr)>(policy.DnatRules.Count);
        for (var index = 0; index < policy.DnatRules.Count; index++)
        {
            var path = "dnatRules[" + index.ToString(CultureInfo.InvariantCulture) + "]";
            var rule = policy.DnatRules[index];
            if (rule is null)
            {
                errors.Add(new("nat.ruleRequired", path));
                continue;
            }

            if (rule.Family is not (IpFamily.IPv4 or IpFamily.IPv6))
            {
                errors.Add(new("family.unknown", path + ".family"));
            }

            if (!Enum.IsDefined(rule.Protocol))
            {
                errors.Add(new("protocol.unknown", path + ".protocol"));
            }
            else if (rule.Protocol is not (FilterProtocol.Any or FilterProtocol.Tcp or FilterProtocol.Udp))
            {
                errors.Add(new("nat.protocolUnsupported", path + ".protocol"));
            }

            if (!Enum.IsDefined(rule.Hook))
            {
                errors.Add(new("nat.hookUnsupported", path + ".hook"));
            }
            if (rule.Hook == DnatHook.Output && (rule.InputInterface is not null || rule.InputInterfaceSelector is not null))
            {
                errors.Add(new("interface.chainMismatch", path + ".inputInterface"));
            }

            if (rule.OriginalDestination is null && rule.DestinationPrefixes is null)
            {
                errors.Add(new("nat.originalDestinationRequired", path + ".originalDestination"));
            }
            else if (rule.OriginalDestination is { } originalDestination && originalDestination.Family != rule.Family)
            {
                errors.Add(new("network.familyMismatch", path + ".originalDestination"));
            }

            if (rule.Source is not null && rule.Source.Family != rule.Family)
            {
                errors.Add(new("network.familyMismatch", path + ".source"));
            }

            if (rule.InputInterface is not null && !FilterPolicyValidation.IsValidInterfaceName(rule.InputInterface))
            {
                errors.Add(new("interface.invalid", path + ".inputInterface"));
            }

            string? normalizedTarget = null;
            if (!FilterPolicyValidation.TryParseSingleIpAddress(rule.TranslatedAddress, out _, out var targetFamily, out normalizedTarget))
            {
                errors.Add(new("nat.translatedAddressInvalid", path + ".translatedAddress"));
            }
            else if (targetFamily != rule.Family)
            {
                errors.Add(new("nat.translatedFamilyMismatch", path + ".translatedAddress"));
            }

            if (rule.OriginalPort is < 1 or > 65535)
            {
                errors.Add(new("port.outOfRange", path + ".originalPort"));
            }

            if (rule.OriginalPort.HasValue && rule.Protocol is not (FilterProtocol.Tcp or FilterProtocol.Udp))
            {
                errors.Add(new("port.requiresTransport", path + ".originalPort"));
            }

            if (rule.TranslatedPort is < 1 or > 65535)
            {
                errors.Add(new("port.outOfRange", path + ".translatedPort"));
            }

            if (rule.TranslatedPort.HasValue && rule.Protocol is not (FilterProtocol.Tcp or FilterProtocol.Udp))
            {
                errors.Add(new("port.requiresTransport", path + ".translatedPort"));
            }

            if (normalizedTarget is not null)
            {
                normalizedDnat.Add((rule, normalizedTarget));
            }
        }

        var normalizedSnat = new List<(SnatRule Rule, string NormalizedAddr)>(policy.SnatRules.Count);
        for (var index = 0; index < policy.SnatRules.Count; index++)
        {
            var path = "snatRules[" + index.ToString(CultureInfo.InvariantCulture) + "]";
            var rule = policy.SnatRules[index];
            if (rule is null)
            {
                errors.Add(new("nat.ruleRequired", path));
                continue;
            }

            if (rule.Family is not (IpFamily.IPv4 or IpFamily.IPv6))
            {
                errors.Add(new("family.unknown", path + ".family"));
            }

            NftOriginalTuple.ValidateOriginalPrefixes(rule.OriginalSourcePrefixes, rule.Family, rule.MatchOriginalDestinationDnat, path + ".originalSourcePrefixes", errors);
            NftOriginalTuple.ValidateOriginalPrefixes(rule.OriginalDestinationPrefixes, rule.Family, rule.MatchOriginalDestinationDnat, path + ".originalDestinationPrefixes", errors);
            if (rule.Source is null && rule.SourcePrefixes is null && !rule.MatchOriginalDestinationDnat && rule.Action == NatPostroutingAction.Snat)
            {
                errors.Add(new("nat.sourceRequired", path + ".source"));
            }
            else if (rule.Source is not null && rule.Source.Family != rule.Family)
            {
                errors.Add(new("network.familyMismatch", path + ".source"));
            }

            if (rule.Destination is not null && rule.Destination.Family != rule.Family)
            {
                errors.Add(new("network.familyMismatch", path + ".destination"));
            }

            if (rule.OutputInterface is not null && !FilterPolicyValidation.IsValidInterfaceName(rule.OutputInterface))
            {
                errors.Add(new("interface.invalid", path + ".outputInterface"));
            }

            string? normalizedTarget = null;
            if (rule.Action != NatPostroutingAction.Snat) { normalizedTarget = ""; }
            else if (!FilterPolicyValidation.TryParseSingleIpAddress(rule.TranslatedAddress, out _, out var targetFamily, out normalizedTarget))
            {
                errors.Add(new("nat.translatedAddressInvalid", path + ".translatedAddress"));
            }
            else if (targetFamily != rule.Family)
            {
                errors.Add(new("nat.translatedFamilyMismatch", path + ".translatedAddress"));
            }

            if (normalizedTarget is not null)
            {
                normalizedSnat.Add((rule, normalizedTarget));
            }
        }

        if (errors.Count != 0)
        {
            return new(null, errors);
        }

        var text = new StringBuilder("create table inet " + TableName);
        if (identity is not null)
        {
            text.Append(" { comment \"").Append(identity.Comment).Append("\"; }");
        }

        text.Append('\n');
        text.Append("add chain inet " + TableName + " prerouting { type nat hook prerouting priority dstnat; policy accept; }\n");
        if (normalizedDnat.Any(entry => entry.Rule is { Enabled: true, Hook: DnatHook.Output }))
        {
            text.Append("add chain inet " + TableName + " output { type nat hook output priority dstnat; policy accept; }\n");
        }
        text.Append("add chain inet " + TableName + " postrouting { type nat hook postrouting priority srcnat; policy accept; }\n");

        sets.Append(text, "inet", TableName);
        // Group like the kernel listing while retaining first-match order within each hook.
        var activeDnat = normalizedDnat.Select((r, i) => (Rule: NftStaticSetPlan.Attach(r.Rule, intent.DnatRules[i]!), r.NormalizedAddr))
            .Where(r => r.Rule.Enabled).OrderBy(r => r.Rule.Hook);
        foreach (var (rule, addr) in activeDnat)
        {
            var familyToken = rule.Family == IpFamily.IPv4 ? "ip" : "ip6";
            var chainName = rule.Hook == DnatHook.Output ? "output" : "prerouting";
            text.Append("add rule inet " + TableName + " ").Append(chainName).Append(" meta nfproto ")
                .Append(rule.Family == IpFamily.IPv4 ? "ipv4" : "ipv6").Append(' ');

            NftInterfaceNames.Append(text, "iifname", rule.InputInterface, rule.InputInterfaceSelector, rule.NegateInputInterface);

            if (rule.SourceObject is { NativeSet: true } sourceSet)
            { text.Append(familyToken).Append(" saddr ").Append(rule.NegateSource ? "!= " : "").Append('@').Append(NftStaticSetPlan.Name(sourceSet)).Append(' '); }
            else if (rule.Source is not null)
            {
                text.Append(familyToken).Append(" saddr ").Append(rule.NegateSource ? "!= " : "").Append(rule.Source.Value).Append(' ');
            }

            else if (rule.SourcePrefixes is { } sources)
            { text.Append(familyToken).Append(" saddr ").Append(rule.NegateSource ? "!= " : "").Append("{ ").Append(string.Join(", ", sources.Select(p => p.Value).Order(StringComparer.Ordinal))).Append(" } "); }
            text.Append(familyToken).Append(" daddr ").Append(rule.NegateDestination ? "!= " : "");
            if (rule.DestinationObject is { NativeSet: true } destinationSet) { text.Append('@').Append(NftStaticSetPlan.Name(destinationSet)).Append(' '); }
            else if (rule.OriginalDestination is { } original) { text.Append(original.Value).Append(' '); }
            else { text.Append("{ ").Append(string.Join(", ", rule.DestinationPrefixes!.Select(p => p.Value).Order(StringComparer.Ordinal))).Append(" } "); }

            if (rule.Protocol != FilterProtocol.Any)
            {
                var proto = rule.Protocol == FilterProtocol.Tcp ? "tcp" : "udp";
                text.Append("meta l4proto ").Append(proto).Append(' ');
                if (rule.OriginalPortObject is { NativeSet: true } portSet) { text.Append(proto).Append(" dport @").Append(NftStaticSetPlan.Name(portSet)).Append(' '); }
                else if (rule.OriginalPort.HasValue)
                {
                    text.Append(proto).Append(" dport ").Append(rule.OriginalPort.Value.ToString(CultureInfo.InvariantCulture)).Append(' ');
                }
                else if (rule.OriginalPorts is { } ports) { text.Append(proto).Append(" dport { ").Append(string.Join(", ", ports.Order())).Append(" } "); }
            }

            if (rule.CountPackets) { text.Append("counter "); }
            text.Append("dnat ").Append(familyToken).Append(" to ");
            if (rule.TranslatedPort.HasValue)
            {
                if (rule.Family == IpFamily.IPv6)
                {
                    text.Append('[').Append(addr).Append("]:").Append(rule.TranslatedPort.Value.ToString(CultureInfo.InvariantCulture));
                }
                else
                {
                    text.Append(addr).Append(':').Append(rule.TranslatedPort.Value.ToString(CultureInfo.InvariantCulture));
                }
            }
            else
            {
                text.Append(addr);
            }

            text.Append('\n');
        }

        foreach (var (rule, addr) in normalizedSnat.Select((r, i) => (Rule: NftStaticSetPlan.Attach(r.Rule, intent.SnatRules[i]!), r.NormalizedAddr)).Where(r => r.Rule.Enabled))
        {
            var familyToken = rule.Family == IpFamily.IPv4 ? "ip" : "ip6";
            text.Append("add rule inet " + TableName + " postrouting meta nfproto ")
                .Append(rule.Family == IpFamily.IPv4 ? "ipv4" : "ipv6").Append(' ');

            NftInterfaceNames.Append(text, "iifname", rule.InputInterface, rule.InputInterfaceSelector, rule.NegateInputInterface);
            NftInterfaceNames.Append(text, "oifname", rule.OutputInterface, rule.OutputInterfaceSelector, rule.NegateOutputInterface);

            if (rule.SourceObject is { NativeSet: true } sourceSet)
            { text.Append(familyToken).Append(" saddr ").Append(rule.NegateSource ? "!= " : "").Append('@').Append(NftStaticSetPlan.Name(sourceSet)).Append(' '); }
            else if (rule.Source is not null)
            { text.Append(familyToken).Append(" saddr ").Append(rule.NegateSource ? "!= " : "").Append(rule.Source.Value).Append(' '); }
            else if (rule.SourcePrefixes is { } sources)
            { text.Append(familyToken).Append(" saddr ").Append(rule.NegateSource ? "!= " : "").Append("{ ").Append(string.Join(", ", sources.Select(p => p.Value).Order(StringComparer.Ordinal))).Append(" } "); }

            if (rule.DestinationObject is { NativeSet: true } destinationSet)
            { text.Append(familyToken).Append(" daddr ").Append(rule.NegateDestination ? "!= " : "").Append('@').Append(NftStaticSetPlan.Name(destinationSet)).Append(' '); }
            else if (rule.Destination is not null)
            {
                text.Append(familyToken).Append(" daddr ").Append(rule.NegateDestination ? "!= " : "").Append(rule.Destination.Value).Append(' ');
            }

            else if (rule.DestinationPrefixes is { } destinations)
            { text.Append(familyToken).Append(" daddr ").Append(rule.NegateDestination ? "!= " : "").Append("{ ").Append(string.Join(", ", destinations.Select(p => p.Value).Order(StringComparer.Ordinal))).Append(" } "); }

            if (rule.Protocol != FilterProtocol.Any)
            {
                var proto = rule.Protocol == FilterProtocol.Tcp ? "tcp" : "udp";
                text.Append("meta l4proto ").Append(proto).Append(' ');
                if (rule.DestinationPortObject is { NativeSet: true } portSet) { text.Append(proto).Append(" dport @").Append(NftStaticSetPlan.Name(portSet)).Append(' '); }
                else if (rule.DestinationPort is { } port) { text.Append(proto).Append(" dport ").Append(port.ToString(CultureInfo.InvariantCulture)).Append(' '); }
                else if (rule.DestinationPorts is { } ports)
                { text.Append(proto).Append(" dport { ").Append(string.Join(", ", ports.Order().Select(p => p.ToString(CultureInfo.InvariantCulture)))).Append(" } "); }
            }
            if (rule.MatchOriginalDestinationDnat)
            {
                text.Append("ct status dnat ");
                NftOriginalTuple.AppendOriginalPrefixes(text, rule.Family, "saddr", rule.OriginalSourcePrefixes);
                NftOriginalTuple.AppendOriginalPrefixes(text, rule.Family, "daddr", rule.OriginalDestinationPrefixes);
            }
            if (rule.CountPackets) { text.Append("counter "); }
            if (rule.Action == NatPostroutingAction.Snat) { text.Append("snat ").Append(familyToken).Append(" to ").Append(addr); }
            else { text.Append(rule.Action == NatPostroutingAction.Masquerade ? "masquerade" : "return"); }
            text.Append('\n');
        }

        var result = sets.Finish(text.ToString());
        var selectors = policy.DnatRules.Any(r => r is { Enabled: true, InputInterfaceSelector: not null }) ||
            policy.SnatRules.Any(r => r is { Enabled: true } && (r.InputInterfaceSelector is not null || r.OutputInterfaceSelector is not null));
        if (result.Candidate is null || result.ObservationBudget > 0 || !selectors) { return result; }
        var budget = NftStaticSetPlan.Estimate(result.Candidate);
        return budget > 65536
            ? new(null, [new("selector.nativeObservationTooLarge", "nat")])
            : new(result.Candidate, [], budget);
    }
}
