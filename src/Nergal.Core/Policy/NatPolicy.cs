namespace Nergal.Core.Policy;

/// <summary>An immutable destination NAT rule evaluated in the inet prerouting hook.</summary>
/// <param name="Family">The explicit IP family.</param>
/// <param name="Protocol">Protocol to match (<see cref="FilterProtocol.Any"/>, <see cref="FilterProtocol.Tcp"/>, or <see cref="FilterProtocol.Udp"/>).</param>
/// <param name="OriginalDestination">Canonical destination network matched prior to translation.</param>
/// <param name="TranslatedAddress">Single canonical translated destination IP address matching <paramref name="Family"/>.</param>
/// <param name="OriginalPort">Optional original TCP/UDP destination port in 1–65535.</param>
/// <param name="TranslatedPort">Optional translated TCP/UDP destination port in 1–65535; requires TCP or UDP.</param>
/// <param name="InputInterface">Optional ingress interface name (<c>iifname</c>).</param>
/// <param name="Source">Optional canonical source network restriction.</param>
/// <param name="Description">Optional human-readable operator note (max 160 printable characters; metadata only).</param>
public sealed record DnatRule(
    IpFamily Family,
    FilterProtocol Protocol,
    NetworkPrefix OriginalDestination,
    string TranslatedAddress,
    int? OriginalPort = null,
    int? TranslatedPort = null,
    string? InputInterface = null,
    NetworkPrefix? Source = null,
    string? Description = null);

/// <summary>An immutable explicit source NAT rule evaluated in the inet postrouting hook.</summary>
/// <param name="Family">The explicit IP family.</param>
/// <param name="Source">Canonical source network matched for source translation.</param>
/// <param name="TranslatedAddress">Explicit single canonical translated source IP address (never implicit masquerade).</param>
/// <param name="Destination">Optional canonical destination network restriction.</param>
/// <param name="OutputInterface">Optional egress interface name (<c>oifname</c>).</param>
/// <param name="Description">Optional human-readable operator note (max 160 printable characters; metadata only).</param>
public sealed record SnatRule(
    IpFamily Family,
    NetworkPrefix Source,
    string TranslatedAddress,
    NetworkPrefix? Destination = null,
    string? OutputInterface = null,
    string? Description = null);

/// <summary>An immutable, versioned snapshot of ordered dual-stack DNAT and explicit SNAT rules.</summary>
public sealed class NatPolicy
{
    /// <summary>Current supported NAT policy schema version.</summary>
    public const int CurrentSchemaVersion = 1;

    /// <summary>Snapshots ordered DNAT and SNAT rules without discarding invalid entries.</summary>
    /// <param name="schemaVersion">Must be 1 for the current NAT compiler.</param>
    /// <param name="dnatRules">Ordered prerouting destination NAT rules; null entries remain for diagnostics.</param>
    /// <param name="snatRules">Ordered postrouting explicit source NAT rules; null entries remain for diagnostics.</param>
    /// <exception cref="ArgumentNullException">Either rule collection is null.</exception>
    public NatPolicy(int schemaVersion, IEnumerable<DnatRule?> dnatRules, IEnumerable<SnatRule?> snatRules)
    {
        ArgumentNullException.ThrowIfNull(dnatRules);
        ArgumentNullException.ThrowIfNull(snatRules);
        SchemaVersion = schemaVersion;
        DnatRules = Array.AsReadOnly(dnatRules.ToArray());
        SnatRules = Array.AsReadOnly(snatRules.ToArray());
    }

    /// <summary>Gets the schema version validated prior to compilation.</summary>
    public int SchemaVersion { get; }

    /// <summary>Gets the defensive ordered prerouting DNAT rule snapshot.</summary>
    public IReadOnlyList<DnatRule?> DnatRules { get; }

    /// <summary>Gets the defensive ordered postrouting explicit SNAT rule snapshot.</summary>
    public IReadOnlyList<SnatRule?> SnatRules { get; }

    /// <summary>Computes the semantic backend features required by this NAT policy.</summary>
    public IReadOnlySet<FirewallFeature> GetRequiredFeatures()
    {
        var features = new HashSet<FirewallFeature>
        {
            FirewallFeature.ForeignTablePreservation,
        };
        if (DnatRules.Count > 0)
        {
            features.Add(FirewallFeature.DestinationNat);
        }

        if (SnatRules.Count > 0)
        {
            features.Add(FirewallFeature.ExplicitSourceNat);
        }

        return features;
    }
}
