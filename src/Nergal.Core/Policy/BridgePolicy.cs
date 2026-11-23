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
/// <param name="Description">Optional human-readable operator note (max 160 printable characters; metadata only).</param>
/// <param name="BridgeName">Ingress bridge master name (<c>meta ibrname</c>).</param>
/// <param name="SourceMac">Optional source MAC restriction.</param>
/// <param name="DestinationMac">Optional destination MAC restriction.</param>
/// <param name="NegateSourceMac">Negate the source MAC restriction.</param>
/// <param name="NegateDestinationMac">Negate the destination MAC restriction.</param>
/// <param name="Family">Optional IP family for L3 matching.</param>
/// <param name="Source">Optional source IP prefix; requires a family.</param>
/// <param name="Destination">Optional destination IP prefix; requires a family.</param>
/// <param name="Protocol">Any, TCP, or UDP for L4 matching.</param>
/// <param name="DestinationPort">Optional TCP/UDP destination port.</param>
/// <param name="DestinationPorts">Optional bounded destination port set.</param>
/// <param name="JumpTarget">Optional regular-chain target; mutually exclusive with Return.</param>
/// <param name="Return">Return to the caller, only inside regular chains. When true, or when JumpTarget is set, Verdict must be Drop as a neutral draft value.</param>
/// <param name="Enabled">Whether this validated rule contributes to native enforcement; false retains all intent and order.</param>
public sealed record BridgeFilterRule(
    BridgeEtherType EtherType,
    FilterVerdict Verdict,
    string? InputInterface = null,
    string? OutputInterface = null,
    string? Description = null,
    string? BridgeName = null,
    MacAddress? SourceMac = null,
    MacAddress? DestinationMac = null,
    bool NegateSourceMac = false,
    bool NegateDestinationMac = false,
    IpFamily? Family = null,
    NetworkPrefix? Source = null,
    NetworkPrefix? Destination = null,
    FilterProtocol Protocol = FilterProtocol.Any,
    int? DestinationPort = null,
    IReadOnlyList<int>? DestinationPorts = null,
    string? JumpTarget = null,
    bool Return = false,
    bool Enabled = true);

/// <summary>A named, non-base bridge chain. Only local declared jump targets are permitted.</summary>
public sealed class BridgeSubChain
{
    /// <summary>Snapshots rules in a regular chain; compiler validates the name and jump graph.</summary>
    public BridgeSubChain(string name, IEnumerable<BridgeFilterRule?> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        Name = name;
        Rules = BridgePolicy.SnapshotRules(rules);
    }
    /// <summary>Gets the local chain name, never an external table or command.</summary>
    public string Name { get; }
    /// <summary>Gets an immutable ordered rule snapshot.</summary>
    public IReadOnlyList<BridgeFilterRule?> Rules { get; }
}

/// <summary>An immutable, versioned snapshot of ordered L2 bridge forward rules.</summary>
public sealed class BridgePolicy
{
    /// <summary>Current supported bridge policy schema version.</summary>
    public const int CurrentSchemaVersion = 1;

    /// <summary>Snapshots bridge forwarding rules without discarding invalid entries.</summary>
    /// <param name="schemaVersion">Must be 1 for the current bridge compiler.</param>
    /// <param name="defaultVerdict">Decision for unmatched bridge-forwarded frames.</param>
    /// <param name="rules">Ordered bridge rules; null entries are retained for compiler diagnostics.</param>
    /// <param name="priority">Forward hook priority; defaults to the existing -200.</param>
    /// <param name="subChains">Optional local regular chains; cycles and missing targets are rejected.</param>
    /// <exception cref="ArgumentNullException">The rules collection is null.</exception>
    public BridgePolicy(int schemaVersion, FilterVerdict defaultVerdict, IEnumerable<BridgeFilterRule?> rules, int priority = -200, IEnumerable<BridgeSubChain>? subChains = null)
    {
        ArgumentNullException.ThrowIfNull(rules);
        SchemaVersion = schemaVersion;
        DefaultVerdict = defaultVerdict;
        Rules = SnapshotRules(rules);
        Priority = priority;
        SubChains = Array.AsReadOnly((subChains ?? []).ToArray());
    }

    /// <summary>Gets the schema version validated prior to compilation.</summary>
    public int SchemaVersion { get; }

    /// <summary>Gets the explicit default verdict for unmatched bridge frames.</summary>
    public FilterVerdict DefaultVerdict { get; }

    /// <summary>Gets the defensive, ordered bridge rule snapshot.</summary>
    public IReadOnlyList<BridgeFilterRule?> Rules { get; }

    /// <summary>Gets whether the policy uses extended bridge matching or regular-chain control flow.</summary>
    public bool HasExtendedRules => Priority != -200 || SubChains.Count > 0 || Rules.Any(r => r is not null &&
        (r.BridgeName is not null || r.SourceMac is not null || r.DestinationMac is not null || r.NegateSourceMac || r.NegateDestinationMac ||
         r.Family is not null || r.Source is not null || r.Destination is not null || r.Protocol != FilterProtocol.Any ||
         r.DestinationPort is not null || r.DestinationPorts is not null || r.JumpTarget is not null || r.Return));

    /// <summary>Gets the forward base-chain priority (-300..300).</summary>
    public int Priority { get; }
    /// <summary>Gets declared local regular chains, in declaration order.</summary>
    public IReadOnlyList<BridgeSubChain> SubChains { get; }

    internal static IReadOnlyList<BridgeFilterRule?> SnapshotRules(IEnumerable<BridgeFilterRule?> rules) =>
        Array.AsReadOnly(rules.Select(r => r is null ? null : r with
        { DestinationPorts = r.DestinationPorts is null ? null : Array.AsReadOnly(r.DestinationPorts.ToArray()) }).ToArray());

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
