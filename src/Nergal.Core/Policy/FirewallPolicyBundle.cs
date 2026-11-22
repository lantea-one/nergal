namespace Nergal.Core.Policy;

/// <summary>Coordinated immutable host policy bundle spanning inet filter, optional inet NAT, and optional bridge tables.</summary>
public sealed class FirewallPolicyBundle
{
    /// <summary>Current supported policy bundle schema version.</summary>
    public const int CurrentSchemaVersion = 1;

    /// <summary>Creates a coordinated policy bundle.</summary>
    /// <param name="schemaVersion">Bundle schema version (must be 1).</param>
    /// <param name="filter">Required host/forwarding filter policy targeting <c>inet nergal_filter</c>.</param>
    /// <param name="nat">Optional dual-stack NAT policy targeting <c>inet nergal_nat</c>.</param>
    /// <param name="bridge">Optional L2 bridge filtering policy targeting <c>bridge nergal_bridge</c>.</param>
    /// <param name="auxiliaryFilter">Optional independent early inet filter table, preview-only.</param>
    /// <exception cref="ArgumentNullException"><paramref name="filter"/> is null.</exception>
    public FirewallPolicyBundle(
        int schemaVersion,
        FilterPolicy filter,
        NatPolicy? nat = null,
        BridgePolicy? bridge = null,
        AuxiliaryFilterPolicy? auxiliaryFilter = null)
    {
        ArgumentNullException.ThrowIfNull(filter);
        SchemaVersion = schemaVersion;
        Filter = filter;
        Nat = nat;
        Bridge = bridge;
        AuxiliaryFilter = auxiliaryFilter;
    }

    /// <summary>Gets the bundle schema version.</summary>
    public int SchemaVersion { get; }

    /// <summary>Gets the required inet filter policy.</summary>
    public FilterPolicy Filter { get; }

    /// <summary>Gets the optional dual-stack NAT policy.</summary>
    public NatPolicy? Nat { get; }

    /// <summary>Gets the optional L2 bridge filtering policy.</summary>
    public BridgePolicy? Bridge { get; }

    /// <summary>Gets an optional independent early inet filter table (compiler preview only).</summary>
    public AuxiliaryFilterPolicy? AuxiliaryFilter { get; }

    /// <summary>Gets whether this bundle requires agent observation/rollback support not implemented yet.</summary>
    public bool RequiresExtendedApplySupport => AuxiliaryFilter is not null || Bridge?.HasExtendedRules == true;

    /// <summary>Aggregates all semantic backend requirements across every configured table in the bundle.</summary>
    public IReadOnlySet<FirewallFeature> GetRequiredFeatures()
    {
        var features = new HashSet<FirewallFeature>(Filter.GetRequiredFeatures());
        if (Nat is not null)
        {
            features.UnionWith(Nat.GetRequiredFeatures());
        }

        if (Bridge is not null)
        {
            features.UnionWith(Bridge.GetRequiredFeatures());
        }

        if (Nat is not null || Bridge is not null || AuxiliaryFilter is not null)
        {
            features.Add(FirewallFeature.AtomicMultiTableCommit);
        }

        if (AuxiliaryFilter is not null) { features.UnionWith(AuxiliaryFilter.Filter.GetRequiredFeatures()); }
        if (RequiresExtendedApplySupport) { features.Add(FirewallFeature.AuxiliaryFiltering); }
        return features;
    }
}
