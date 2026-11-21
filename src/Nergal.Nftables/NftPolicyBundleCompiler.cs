using System.Text;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

/// <summary>Compiles coordinated multi-table nftables transactions across filter, NAT, and bridge tables.</summary>
/// <remarks>Every table is validated before any native text is emitted. Atomic replacements delete only previously owned reserved Nergal tables and never flush the host ruleset.</remarks>
public static class NftPolicyBundleCompiler
{
    /// <summary>Validates all bundle tables before emitting a deterministic multi-table create-only batch.</summary>
    /// <param name="bundle">Coordinated policy bundle.</param>
    /// <returns>Complete batch candidate or component-prefixed diagnostics with no partial output.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="bundle"/> is null.</exception>
    public static CompilationResult Compile(FirewallPolicyBundle bundle) => CompileCore(bundle, null, false, false, false, false);

    /// <summary>Validates all bundle tables and emits a tagged multi-table create-only batch.</summary>
    /// <param name="bundle">Coordinated policy bundle.</param>
    /// <param name="identity">Canonical owner/resource table marker applied to every Nergal table.</param>
    /// <exception cref="ArgumentNullException">Bundle or identity is null.</exception>
    public static CompilationResult Compile(FirewallPolicyBundle bundle, NftTableIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return CompileCore(bundle, identity, false, false, false, false);
    }

    /// <summary>Validates all bundle tables and emits one atomic delete-and-recreate multi-table batch.</summary>
    /// <param name="bundle">Target replacement policy bundle.</param>
    /// <param name="identity">Canonical owner/resource identity tagging every Nergal table.</param>
    /// <param name="filterExists">Whether <c>inet nergal_filter</c> currently exists under verified ownership.</param>
    /// <param name="natExists">Whether <c>inet nergal_nat</c> currently exists under verified ownership.</param>
    /// <param name="bridgeExists">Whether <c>bridge nergal_bridge</c> currently exists under verified ownership.</param>
    /// <returns>Single-transaction native batch or component-prefixed diagnostics.</returns>
    /// <exception cref="ArgumentNullException">Bundle or identity is null.</exception>
    public static CompilationResult CompileAtomicReplacement(
        FirewallPolicyBundle bundle,
        NftTableIdentity identity,
        bool filterExists,
        bool natExists,
        bool bridgeExists)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return CompileCore(bundle, identity, true, filterExists, natExists, bridgeExists);
    }

    private static CompilationResult CompileCore(
        FirewallPolicyBundle bundle,
        NftTableIdentity? identity,
        bool isAtomicReplacement,
        bool filterExists,
        bool natExists,
        bool bridgeExists)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        var errors = new List<PolicyDiagnostic>();
        if (bundle.SchemaVersion != FirewallPolicyBundle.CurrentSchemaVersion)
        {
            errors.Add(new("schema.unsupported", "schemaVersion"));
        }

        var filterResult = identity is null
            ? NftFilterCompiler.Compile(bundle.Filter)
            : NftFilterCompiler.Compile(bundle.Filter, identity);
        foreach (var diagnostic in filterResult.Diagnostics)
        {
            errors.Add(new(diagnostic.Code, "filter." + diagnostic.Path));
        }

        CompilationResult? natResult = null;
        if (bundle.Nat is not null)
        {
            natResult = identity is null
                ? NftNatCompiler.Compile(bundle.Nat)
                : NftNatCompiler.Compile(bundle.Nat, identity);
            foreach (var diagnostic in natResult.Diagnostics)
            {
                errors.Add(new(diagnostic.Code, "nat." + diagnostic.Path));
            }
        }

        CompilationResult? bridgeResult = null;
        if (bundle.Bridge is not null)
        {
            bridgeResult = identity is null
                ? NftBridgeCompiler.Compile(bundle.Bridge)
                : NftBridgeCompiler.Compile(bundle.Bridge, identity);
            foreach (var diagnostic in bridgeResult.Diagnostics)
            {
                errors.Add(new(diagnostic.Code, "bridge." + diagnostic.Path));
            }
        }

        if (errors.Count != 0)
        {
            return new(null, errors);
        }

        var text = new StringBuilder();
        if (isAtomicReplacement)
        {
            if (bridgeExists)
            {
                text.Append("delete table bridge ").Append(NftBridgeCompiler.TableName).Append('\n');
            }

            if (natExists)
            {
                text.Append("delete table inet ").Append(NftNatCompiler.TableName).Append('\n');
            }

            if (filterExists)
            {
                text.Append("delete table inet ").Append(NftFilterCompiler.TableName).Append('\n');
            }
        }

        text.Append(filterResult.Candidate);
        if (natResult is not null)
        {
            text.Append(natResult.Candidate);
        }

        if (bridgeResult is not null)
        {
            text.Append(bridgeResult.Candidate);
        }

        return new(text.ToString(), []);
    }
}
