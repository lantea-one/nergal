namespace Nergal.Core.Policy;

/// <summary>Ethernet frame payload protocols matched on the bridge forward hook.</summary>
public enum BridgeEtherType
{
    /// <summary>Any Ethernet frame protocol.</summary>
    Any,
    /// <summary>IPv4 frames (<c>ether type ip</c>).</summary>
    IPv4,
    /// <summary>IPv6 frames (<c>ether type ip6</c>).</summary>
    IPv6,
    /// <summary>Address Resolution Protocol frames (<c>ether type arp</c>).</summary>
    Arp,
}

/// <summary>An immutable L2 bridge forwarding rule evaluated in <c>bridge nergal_bridge</c>.</summary>
/// <param name="EtherType">The matched Ethernet protocol (<see cref="BridgeEtherType"/>).</param>
/// <param name="Verdict">Terminal allow or drop verdict.</param>
/// <param name="InputInterface">Optional ingress bridge port name (<c>iifname</c>).</param>
/// <param name="OutputInterface">Optional egress bridge port name (<c>oifname</c>).</param>
public sealed record BridgeFilterRule(
    BridgeEtherType EtherType,
    FilterVerdict Verdict,
    string? InputInterface = null,
    string? OutputInterface = null);

/// <summary>An immutable, versioned snapshot of ordered L2 bridge forward rules.</summary>
public sealed class BridgePolicy
{
    /// <summary>Current supported bridge policy schema version.</summary>
    public const int CurrentSchemaVersion = 1;

    /// <summary>Snapshots bridge forwarding rules without discarding invalid entries.</summary>
    /// <param name="schemaVersion">Must be 1 for the current bridge compiler.</param>
    /// <param name="defaultVerdict">Decision for unmatched bridge-forwarded frames.</param>
    /// <param name="rules">Ordered bridge rules; null entries are retained for compiler diagnostics.</param>
    /// <exception cref="ArgumentNullException">The rules collection is null.</exception>
    public BridgePolicy(int schemaVersion, FilterVerdict defaultVerdict, IEnumerable<BridgeFilterRule?> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        SchemaVersion = schemaVersion;
        DefaultVerdict = defaultVerdict;
        Rules = Array.AsReadOnly(rules.ToArray());
    }

    /// <summary>Gets the schema version validated prior to compilation.</summary>
    public int SchemaVersion { get; }

    /// <summary>Gets the explicit default verdict for unmatched bridge frames.</summary>
    public FilterVerdict DefaultVerdict { get; }

    /// <summary>Gets the defensive, ordered bridge rule snapshot.</summary>
    public IReadOnlyList<BridgeFilterRule?> Rules { get; }

    /// <summary>Computes the semantic backend features required by this bridge policy.</summary>
    public IReadOnlySet<FirewallFeature> GetRequiredFeatures()
    {
        return new HashSet<FirewallFeature>
        {
            FirewallFeature.BridgeFiltering,
            FirewallFeature.ForeignTablePreservation,
        };
    }
}
