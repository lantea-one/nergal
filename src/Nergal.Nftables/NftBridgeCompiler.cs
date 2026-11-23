using System.Globalization;
using System.Text;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

/// <summary>Compiles L2 bridge forward filtering policies into create-only <c>bridge nergal_bridge</c> batches.</summary>
public static class NftBridgeCompiler
{
    /// <summary>The reserved bridge table name. Preexisting tables are never adopted or overwritten.</summary>
    public const string TableName = "nergal_bridge";

    /// <summary>Validates all bridge rules before emitting a deterministic create-only native batch.</summary>
    /// <param name="policy">A typed bridge snapshot; unknown or invalid rules fail closed.</param>
    /// <returns>A complete candidate batch or ordered diagnostics with no candidate.</returns>
    /// <exception cref="ArgumentNullException">The policy is null.</exception>
    public static CompilationResult Compile(BridgePolicy policy) => CompileCore(policy, null);

    /// <summary>Compiles a create-only bridge candidate carrying a canonical owner/resource marker.</summary>
    /// <param name="policy">A typed bridge snapshot.</param>
    /// <param name="identity">Canonical owner/resource table marker.</param>
    /// <exception cref="ArgumentNullException">Policy or identity is null.</exception>
    public static CompilationResult Compile(BridgePolicy policy, NftTableIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return CompileCore(policy, identity);
    }

    private static CompilationResult CompileCore(BridgePolicy policy, NftTableIdentity? identity)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var referenceErrors = new List<PolicyObjectDiagnostic>();
        policy = TransportObjectResolver.Resolve(policy, referenceErrors);
        if (referenceErrors.Count != 0) { return new(null, referenceErrors.Select(d => new PolicyDiagnostic(d.Code, d.Path)).ToArray()); }

        if (policy.HasExtendedRules) { return RouterBridgeCompiler.Compile(policy, identity); }
        var errors = new List<PolicyDiagnostic>();
        if (policy.SchemaVersion != BridgePolicy.CurrentSchemaVersion)
        {
            errors.Add(new("schema.unsupported", "schemaVersion"));
        }

        if (policy.DefaultVerdict is not (FilterVerdict.Accept or FilterVerdict.Drop))
        {
            errors.Add(new("verdict.unknown", "defaultVerdict"));
        }

        for (var index = 0; index < policy.Rules.Count; index++)
        {
            var path = "rules[" + index.ToString(CultureInfo.InvariantCulture) + "]";
            var rule = policy.Rules[index];
            if (rule is null)
            {
                errors.Add(new("bridge.ruleRequired", path));
                continue;
            }

            if (!Enum.IsDefined(rule.EtherType))
            {
                errors.Add(new("etherType.unknown", path + ".etherType"));
            }

            if (rule.Verdict is not (FilterVerdict.Accept or FilterVerdict.Drop))
            {
                errors.Add(new("verdict.unknown", path + ".verdict"));
            }

            if (rule.InputInterface is not null && !FilterPolicyValidation.IsValidInterfaceName(rule.InputInterface))
            {
                errors.Add(new("interface.invalid", path + ".inputInterface"));
            }

            if (rule.OutputInterface is not null && !FilterPolicyValidation.IsValidInterfaceName(rule.OutputInterface))
            {
                errors.Add(new("interface.invalid", path + ".outputInterface"));
            }
        }

        if (errors.Count != 0)
        {
            return new(null, errors);
        }

        var text = new StringBuilder("create table bridge " + TableName);
        if (identity is not null)
        {
            text.Append(" { comment \"").Append(identity.Comment).Append("\"; }");
        }

        text.Append('\n');
        text.Append("add chain bridge " + TableName + " forward { type filter hook forward priority -200; policy ")
            .Append(VerdictToken(policy.DefaultVerdict)).Append("; }\n");

        foreach (var draft in policy.Rules)
        {
            var rule = draft!;
            if (!rule.Enabled) { continue; }
            text.Append("add rule bridge " + TableName + " forward ");
            if (rule.InputInterface is not null)
            {
                text.Append("iifname \"").Append(rule.InputInterface).Append("\" ");
            }

            if (rule.OutputInterface is not null)
            {
                text.Append("oifname \"").Append(rule.OutputInterface).Append("\" ");
            }

            if (rule.EtherType != BridgeEtherType.Any)
            {
                text.Append("ether type ").Append(EtherTypeToken(rule.EtherType)).Append(' ');
            }

            text.Append(VerdictToken(rule.Verdict)).Append('\n');
        }

        return new(text.ToString(), []);
    }

    private static string EtherTypeToken(BridgeEtherType etherType) => etherType switch
    {
        BridgeEtherType.IPv4 => "ip",
        BridgeEtherType.IPv6 => "ip6",
        BridgeEtherType.Arp => "arp",
        _ => throw new InvalidOperationException("Unvalidated ether type."),
    };

    private static string VerdictToken(FilterVerdict verdict) => verdict switch
    {
        FilterVerdict.Accept => "accept",
        FilterVerdict.Drop => "drop",
        _ => throw new InvalidOperationException("Unvalidated verdict."),
    };
}
