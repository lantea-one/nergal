using System.Globalization;
using System.Text;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

/// <summary>Compiles schema 1 and schema 2 inet filtering without executing commands or observing host state.</summary>
public static class NftFilterCompiler
{
    /// <summary>The sole reserved inet table. Existing tables are never adopted or replaced.</summary>
    public const string TableName = "nergal_filter";

    private static readonly FilterChainKind[] ChainOrder =
    [
        FilterChainKind.Input,
        FilterChainKind.Forward,
        FilterChainKind.Output,
    ];

    /// <summary>Validates all rules before emitting a deterministic create-only native batch.</summary>
    /// <param name="policy">A typed snapshot; unknown values and unsupported combinations fail closed.</param>
    /// <returns>A complete candidate or stable diagnostics with no candidate.</returns>
    /// <exception cref="ArgumentNullException">The policy is null.</exception>
    public static CompilationResult Compile(FilterPolicy policy)
    {
        return CompileCore(policy, null);
    }

    /// <summary>Compiles a create-only candidate with a typed identity marker; the marker is not ownership proof.</summary>
    /// <exception cref="ArgumentNullException">Policy or identity is null.</exception>
    public static CompilationResult Compile(FilterPolicy policy, NftTableIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return CompileCore(policy, identity);
    }

    private static CompilationResult CompileCore(FilterPolicy policy, NftTableIdentity? identity)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var errors = new List<PolicyDiagnostic>();
        if (policy.SchemaVersion is not (1 or 2))
        {
            errors.Add(new("schema.unsupported", "schemaVersion"));
        }

        if (policy.SchemaVersion == 1)
        {
            if (!Enum.IsDefined(policy.DefaultVerdict))
            {
                errors.Add(new("verdict.unknown", "defaultVerdict"));
            }

            if (policy.ForwardDefaultVerdict != FilterVerdict.Drop)
            {
                errors.Add(new("chain.requiresSchema2", "forwardDefaultVerdict"));
            }

            if (policy.OutputDefaultVerdict != FilterVerdict.Drop)
            {
                errors.Add(new("chain.requiresSchema2", "outputDefaultVerdict"));
            }
        }
        else
        {
            if (!Enum.IsDefined(policy.InputDefaultVerdict))
            {
                errors.Add(new("verdict.unknown", "inputDefaultVerdict"));
            }

            if (!Enum.IsDefined(policy.ForwardDefaultVerdict))
            {
                errors.Add(new("verdict.unknown", "forwardDefaultVerdict"));
            }

            if (!Enum.IsDefined(policy.OutputDefaultVerdict))
            {
                errors.Add(new("verdict.unknown", "outputDefaultVerdict"));
            }
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

            if (policy.SchemaVersion == 1)
            {
                if (rule.Chain != FilterChainKind.Input)
                {
                    errors.Add(new("chain.requiresSchema2", path + ".chain"));
                }

                if (rule.InputInterface is not null)
                {
                    errors.Add(new("interface.requiresSchema2", path + ".inputInterface"));
                }

                if (rule.OutputInterface is not null)
                {
                    errors.Add(new("interface.requiresSchema2", path + ".outputInterface"));
                }

                if (rule.ConnectionStates != ConnectionStateFlags.None)
                {
                    errors.Add(new("connectionState.requiresSchema2", path + ".connectionStates"));
                }

                if (rule.IcmpType is not null)
                {
                    errors.Add(new("icmpType.requiresSchema2", path + ".icmpType"));
                }

                if (rule.RateLimit is not null)
                {
                    errors.Add(new("rateLimit.requiresSchema2", path + ".rateLimit"));
                }

                if (rule.MatchOriginalDestinationDnat)
                {
                    errors.Add(new("ctStatus.requiresSchema2", path + ".matchOriginalDestinationDnat"));
                }
            }
            else
            {
                if (!Enum.IsDefined(rule.Chain))
                {
                    errors.Add(new("chain.unknown", path + ".chain"));
                }

                if (rule.InputInterface is not null)
                {
                    if (!FilterPolicyValidation.IsValidInterfaceName(rule.InputInterface))
                    {
                        errors.Add(new("interface.invalid", path + ".inputInterface"));
                    }
                    else if (rule.Chain == FilterChainKind.Output)
                    {
                        errors.Add(new("interface.chainMismatch", path + ".inputInterface"));
                    }
                }

                if (rule.OutputInterface is not null)
                {
                    if (!FilterPolicyValidation.IsValidInterfaceName(rule.OutputInterface))
                    {
                        errors.Add(new("interface.invalid", path + ".outputInterface"));
                    }
                    else if (rule.Chain == FilterChainKind.Input)
                    {
                        errors.Add(new("interface.chainMismatch", path + ".outputInterface"));
                    }
                }

                if ((rule.ConnectionStates & ~FilterPolicyValidation.AllConnectionStates) != 0)
                {
                    errors.Add(new("connectionState.unknown", path + ".connectionStates"));
                }

                if (rule.IcmpType is not null)
                {
                    if (rule.Protocol is not (FilterProtocol.Icmp or FilterProtocol.IcmpV6))
                    {
                        errors.Add(new("icmpType.requiresIcmp", path + ".icmpType"));
                    }
                    else if (!FilterIcmpTypes.IsSupported(rule.Protocol, rule.IcmpType))
                    {
                        errors.Add(new("icmpType.unsupported", path + ".icmpType"));
                    }
                }

                if (rule.RateLimit is { } rateLimit)
                {
                    if (!Enum.IsDefined(rateLimit.WindowUnit))
                    {
                        errors.Add(new("rateLimit.unitUnknown", path + ".rateLimit.windowUnit"));
                    }

                    if (rateLimit.PacketsPerWindow is < 1 or > 1_000_000)
                    {
                        errors.Add(new("rateLimit.rateOutOfRange", path + ".rateLimit.packetsPerWindow"));
                    }

                    if (rateLimit.Burst is < 1 or > 10_000)
                    {
                        errors.Add(new("rateLimit.burstOutOfRange", path + ".rateLimit.burst"));
                    }

                    if (rateLimit.EntryTimeoutSeconds is < 1 or > 86_400)
                    {
                        errors.Add(new("rateLimit.timeoutOutOfRange", path + ".rateLimit.entryTimeoutSeconds"));
                    }
                }
            }
        }

        if (errors.Count != 0)
        {
            return new(null, errors);
        }

        // create fails on collision: neither an existing reserved table nor foreign tables are changed.
        var text = new StringBuilder("create table inet " + TableName);
        if (identity is not null)
        {
            text.Append(" { comment \"").Append(identity.Comment).Append("\"; }");
        }

        text.Append('\n');
        text.Append("add chain inet " + TableName + " input { type filter hook input priority 0; policy ")
            .Append(Verdict(policy.InputDefaultVerdict)).Append("; }\n");

        if (policy.SchemaVersion == 1)
        {
            foreach (var draft in policy.Rules)
            {
                AppendRule(text, draft!, null);
            }

            return new(text.ToString(), []);
        }

        text.Append("add chain inet " + TableName + " forward { type filter hook forward priority 0; policy ")
            .Append(Verdict(policy.ForwardDefaultVerdict)).Append("; }\n");
        text.Append("add chain inet " + TableName + " output { type filter hook output priority 0; policy ")
            .Append(Verdict(policy.OutputDefaultVerdict)).Append("; }\n");

        var orderedRules = new List<(FilterRule Rule, string? SetName)>(policy.Rules.Count);
        var setIndex = 0;
        foreach (var chain in ChainOrder)
        {
            foreach (var draft in policy.Rules)
            {
                var rule = draft!;
                if (rule.Chain != chain)
                {
                    continue;
                }

                string? setName = null;
                if (rule.RateLimit is not null)
                {
                    setName = "nergal_rl_" + setIndex.ToString(CultureInfo.InvariantCulture);
                    setIndex++;
                    var addrType = rule.Family == IpFamily.IPv4 ? "ipv4_addr" : "ipv6_addr";
                    text.Append("add set inet " + TableName + ' ').Append(setName)
                        .Append(" { type ").Append(addrType).Append("; size 65535; flags dynamic,timeout; }\n");
                }

                orderedRules.Add((rule, setName));
            }
        }

        foreach (var (rule, setName) in orderedRules)
        {
            AppendRule(text, rule, setName);
        }

        return new(text.ToString(), []);
    }

    private static void AppendRule(StringBuilder text, FilterRule rule, string? rateLimitSetName)
    {
        var family = rule.Family == IpFamily.IPv4 ? "ip" : "ip6";
        text.Append("add rule inet " + TableName + ' ')
            .Append(ChainToken(rule.Chain))
            .Append(" meta nfproto ")
            .Append(rule.Family == IpFamily.IPv4 ? "ipv4" : "ipv6").Append(' ');

        if (rule.InputInterface is not null)
        {
            text.Append("iifname \"").Append(rule.InputInterface).Append("\" ");
        }

        if (rule.OutputInterface is not null)
        {
            text.Append("oifname \"").Append(rule.OutputInterface).Append("\" ");
        }

        if (rule.Source is not null)
        {
            text.Append(family).Append(" saddr ").Append(rule.Source.Value).Append(' ');
        }

        if (rule.Destination is not null)
        {
            text.Append(family).Append(" daddr ").Append(rule.Destination.Value).Append(' ');
        }

        if (rule.MatchOriginalDestinationDnat)
        {
            text.Append("ct status dnat ");
        }

        if (rule.ConnectionStates != ConnectionStateFlags.None)
        {
            text.Append("ct state ").Append(ConnectionStateToken(rule.ConnectionStates)).Append(' ');
        }

        if (rule.IcmpType is not null)
        {
            var payloadProto = rule.Protocol == FilterProtocol.Icmp ? "icmp" : "icmpv6";
            text.Append(payloadProto).Append(" type ").Append(rule.IcmpType).Append(' ');
        }
        else if (rule.Protocol != FilterProtocol.Any)
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

        if (rule.RateLimit is { } rateLimit && rateLimitSetName is not null)
        {
            var unit = rateLimit.WindowUnit switch
            {
                RateLimitTimeUnit.Second => "second",
                RateLimitTimeUnit.Minute => "minute",
                _ => throw new InvalidOperationException("Unvalidated rate-limit unit."),
            };
            text.Append("add @").Append(rateLimitSetName)
                .Append(" { ").Append(family).Append(" saddr timeout ")
                .Append(rateLimit.EntryTimeoutSeconds.ToString(CultureInfo.InvariantCulture)).Append("s limit rate ")
                .Append(rateLimit.PacketsPerWindow.ToString(CultureInfo.InvariantCulture)).Append('/').Append(unit)
                .Append(" burst ").Append(rateLimit.Burst.ToString(CultureInfo.InvariantCulture)).Append(" packets } ");
        }

        text.Append(Verdict(rule.Verdict)).Append('\n');
    }

    private static string ChainToken(FilterChainKind chain) => chain switch
    {
        FilterChainKind.Input => "input",
        FilterChainKind.Forward => "forward",
        FilterChainKind.Output => "output",
        _ => throw new InvalidOperationException("Unvalidated chain."),
    };

    private static string ConnectionStateToken(ConnectionStateFlags states)
    {
        // Kernel bitmask order in nftables JSON: invalid, established, related, new.
        var parts = new List<string>(4);
        if ((states & ConnectionStateFlags.Invalid) != 0)
        {
            parts.Add("invalid");
        }

        if ((states & ConnectionStateFlags.Established) != 0)
        {
            parts.Add("established");
        }

        if ((states & ConnectionStateFlags.Related) != 0)
        {
            parts.Add("related");
        }

        if ((states & ConnectionStateFlags.New) != 0)
        {
            parts.Add("new");
        }

        return string.Join(',', parts);
    }

    private static string Verdict(FilterVerdict verdict) => verdict switch
    {
        FilterVerdict.Accept => "accept",
        FilterVerdict.Drop => "drop",
        _ => throw new InvalidOperationException("Unvalidated verdict."),
    };
}
