using System.Globalization;
using System.Text;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

/// <summary>Compiles schema 1 input filtering without executing commands or observing host state.</summary>
public static class NftFilterCompiler
{
    /// <summary>The sole reserved inet table. Existing tables are never adopted or replaced.</summary>
    public const string TableName = "nergal_filter";

    /// <summary>Validates all rules before emitting a deterministic create-only native batch.</summary>
    /// <param name="policy">A typed snapshot; unknown values and unsupported combinations fail closed.</param>
    /// <returns>A complete candidate or stable diagnostics with no candidate.</returns>
    /// <exception cref="ArgumentNullException">The policy is null.</exception>
    public static CompilationResult Compile(FilterPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var errors = new List<PolicyDiagnostic>();
        if (policy.SchemaVersion != 1)
        {
            errors.Add(new("schema.unsupported", "schemaVersion"));
        }

        if (!Enum.IsDefined(policy.DefaultVerdict))
        {
            errors.Add(new("verdict.unknown", "defaultVerdict"));
        }

        for (var index = 0; index < policy.Rules.Count; index++)
        {
            var path = "rules[" + index.ToString(CultureInfo.InvariantCulture) + "]";
            var rule = policy.Rules[index];
            if (rule is null)
            {
                errors.Add(new("rule.required", path));
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

            if (!Enum.IsDefined(rule.Verdict))
            {
                errors.Add(new("verdict.unknown", path + ".verdict"));
            }

            if (rule.Source is not null && rule.Source.Family != rule.Family)
            {
                errors.Add(new("network.familyMismatch", path + ".source"));
            }

            if (rule.Destination is not null && rule.Destination.Family != rule.Family)
            {
                errors.Add(new("network.familyMismatch", path + ".destination"));
            }

            if ((rule.Protocol == FilterProtocol.Icmp && rule.Family != IpFamily.IPv4) ||
                (rule.Protocol == FilterProtocol.IcmpV6 && rule.Family != IpFamily.IPv6))
            {
                errors.Add(new("protocol.familyMismatch", path + ".protocol"));
            }

            if (rule.DestinationPort is < 1 or > 65535)
            {
                errors.Add(new("port.outOfRange", path + ".destinationPort"));
            }

            if (rule.DestinationPort.HasValue && rule.Protocol is not (FilterProtocol.Tcp or FilterProtocol.Udp))
            {
                errors.Add(new("port.requiresTransport", path + ".destinationPort"));
            }
        }

        if (errors.Count != 0)
        {
            return new(null, errors);
        }

        // create fails on collision: neither an existing reserved table nor foreign tables are changed.
        var text = new StringBuilder("create table inet " + TableName + "\n");
        text.Append("add chain inet " + TableName + " input { type filter hook input priority 0; policy ")
            .Append(Verdict(policy.DefaultVerdict)).Append("; }\n");
        foreach (var draft in policy.Rules)
        {
            var rule = draft!;
            var family = rule.Family == IpFamily.IPv4 ? "ip" : "ip6";
            text.Append("add rule inet " + TableName + " input meta nfproto ")
                .Append(rule.Family == IpFamily.IPv4 ? "ipv4" : "ipv6").Append(' ');
            if (rule.Source is not null)
            {
                text.Append(family).Append(" saddr ").Append(rule.Source.Value).Append(' ');
            }

            if (rule.Destination is not null)
            {
                text.Append(family).Append(" daddr ").Append(rule.Destination.Value).Append(' ');
            }

            if (rule.Protocol != FilterProtocol.Any)
            {
                var protocol = rule.Protocol switch
                {
                    FilterProtocol.Tcp => "tcp",
                    FilterProtocol.Udp => "udp",
                    FilterProtocol.Icmp => "icmp",
                    FilterProtocol.IcmpV6 => "ipv6-icmp",
                    _ => throw new InvalidOperationException("Unvalidated protocol."),
                };
                text.Append("meta l4proto ").Append(protocol).Append(' ');
                if (rule.DestinationPort.HasValue)
                {
                    text.Append(protocol).Append(" dport ").Append(rule.DestinationPort.Value.ToString(CultureInfo.InvariantCulture)).Append(' ');
                }
            }

            text.Append(Verdict(rule.Verdict)).Append('\n');
        }

        return new(text.ToString(), []);
    }

    private static string Verdict(FilterVerdict verdict) => verdict switch
    {
        FilterVerdict.Accept => "accept",
        FilterVerdict.Drop => "drop",
        _ => throw new InvalidOperationException("Unvalidated verdict."),
    };
}
