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
        var errors = new List<PolicyDiagnostic>();
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

            if (!Enum.IsDefined(rule.Family))
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

            if (rule.OriginalDestination is null)
            {
                errors.Add(new("nat.originalDestinationRequired", path + ".originalDestination"));
            }
            else if (rule.OriginalDestination.Family != rule.Family)
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

            if (!Enum.IsDefined(rule.Family))
            {
                errors.Add(new("family.unknown", path + ".family"));
            }

            if (rule.Source is null && rule.Action == NatPostroutingAction.Snat)
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
        text.Append("add chain inet " + TableName + " postrouting { type nat hook postrouting priority srcnat; policy accept; }\n");

        foreach (var (rule, addr) in normalizedDnat)
        {
            var familyToken = rule.Family == IpFamily.IPv4 ? "ip" : "ip6";
            text.Append("add rule inet " + TableName + " prerouting meta nfproto ")
                .Append(rule.Family == IpFamily.IPv4 ? "ipv4" : "ipv6").Append(' ');

            if (rule.InputInterface is not null)
            {
                text.Append("iifname ").Append(rule.NegateInputInterface ? "!= " : "").Append("\"").Append(rule.InputInterface).Append("\" ");
            }

            if (rule.Source is not null)
            {
                text.Append(familyToken).Append(" saddr ").Append(rule.NegateSource ? "!= " : "").Append(rule.Source.Value).Append(' ');
            }

            text.Append(familyToken).Append(" daddr ").Append(rule.NegateDestination ? "!= " : "").Append(rule.OriginalDestination!.Value).Append(' ');

            if (rule.Protocol != FilterProtocol.Any)
            {
                var proto = rule.Protocol == FilterProtocol.Tcp ? "tcp" : "udp";
                text.Append("meta l4proto ").Append(proto).Append(' ');
                if (rule.OriginalPort.HasValue)
                {
                    text.Append(proto).Append(" dport ").Append(rule.OriginalPort.Value.ToString(CultureInfo.InvariantCulture)).Append(' ');
                }
            }

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

        foreach (var (rule, addr) in normalizedSnat)
        {
            var familyToken = rule.Family == IpFamily.IPv4 ? "ip" : "ip6";
            text.Append("add rule inet " + TableName + " postrouting meta nfproto ")
                .Append(rule.Family == IpFamily.IPv4 ? "ipv4" : "ipv6").Append(' ');

            if (rule.InputInterface is not null)
            { text.Append("iifname ").Append(rule.NegateInputInterface ? "!= " : "").Append('"').Append(rule.InputInterface).Append("\" "); }
            if (rule.OutputInterface is not null)
            {
                text.Append("oifname ").Append(rule.NegateOutputInterface ? "!= " : "").Append("\"").Append(rule.OutputInterface).Append("\" ");
            }

            if (rule.Source is not null)
            { text.Append(familyToken).Append(" saddr ").Append(rule.NegateSource ? "!= " : "").Append(rule.Source.Value).Append(' '); }

            if (rule.Destination is not null)
            {
                text.Append(familyToken).Append(" daddr ").Append(rule.NegateDestination ? "!= " : "").Append(rule.Destination.Value).Append(' ');
            }

            if (rule.Protocol != FilterProtocol.Any)
            {
                var proto = rule.Protocol == FilterProtocol.Tcp ? "tcp" : "udp";
                text.Append("meta l4proto ").Append(proto).Append(' ');
                if (rule.DestinationPort is { } port) { text.Append(proto).Append(" dport ").Append(port.ToString(CultureInfo.InvariantCulture)).Append(' '); }
                if (rule.DestinationPorts is { } ports)
                { text.Append(proto).Append(" dport { ").Append(string.Join(", ", ports.Order().Select(p => p.ToString(CultureInfo.InvariantCulture)))).Append(" } "); }
            }
            if (rule.Action == NatPostroutingAction.Snat) { text.Append("snat ").Append(familyToken).Append(" to ").Append(addr); }
            else { text.Append(rule.Action == NatPostroutingAction.Masquerade ? "masquerade" : "return"); }
            text.Append('\n');
        }

        return new(text.ToString(), []);
    }
}
