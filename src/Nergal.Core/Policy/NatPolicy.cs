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
/// <param name="NegateSource">Negate the source restriction; requires a source matcher.</param>
/// <param name="NegateDestination">Negate the destination restriction.</param>
/// <param name="NegateInputInterface">Negate the ingress restriction; requires an interface.</param>
/// <param name="Enabled">Whether this validated rule contributes to native enforcement; false retains all intent and order.</param>
public sealed record DnatRule(
    IpFamily Family,
    FilterProtocol Protocol,
    NetworkPrefix OriginalDestination,
    string TranslatedAddress,
    int? OriginalPort = null,
    int? TranslatedPort = null,
    string? InputInterface = null,
    NetworkPrefix? Source = null,
    string? Description = null,
    bool NegateSource = false,
    bool NegateDestination = false,
    bool NegateInputInterface = false,
    bool Enabled = true);

/// <summary>Postrouting action; exemptions return before later NAT rules.</summary>
public enum NatPostroutingAction
{
    /// <summary>Translate to an explicit address.</summary>
    Snat,
    /// <summary>Translate to the current output-interface address.</summary>
    Masquerade,
    /// <summary>Stop this NAT chain without translation.</summary>
    Return,
}

/// <summary>An immutable ordered source NAT or exemption rule evaluated in the inet postrouting hook.</summary>
/// <param name="Family">The explicit IP family.</param>
/// <param name="Source">Canonical source network matched for source translation.</param>
/// <param name="TranslatedAddress">Single translated address for explicit SNAT; must be null for masquerade or return.</param>
/// <param name="Destination">Optional canonical destination network restriction.</param>
/// <param name="OutputInterface">Optional egress interface name (<c>oifname</c>).</param>
/// <param name="Description">Optional human-readable operator note (max 160 printable characters; metadata only).</param>
/// <param name="Action">Explicit SNAT, masquerade, or return exemption.</param>
/// <param name="InputInterface">Optional ingress interface restriction.</param>
/// <param name="Protocol">Any, TCP, or UDP.</param>
/// <param name="DestinationPort">Optional TCP/UDP destination port.</param>
/// <param name="DestinationPorts">Optional destination port set; mutually exclusive with the scalar.</param>
/// <param name="NegateSource">Negate the source restriction; requires a matcher.</param>
/// <param name="NegateDestination">Negate the destination restriction; requires a matcher.</param>
/// <param name="NegateInputInterface">Negate the ingress restriction; requires an interface.</param>
/// <param name="NegateOutputInterface">Negate the egress restriction; requires an interface.</param>
/// <param name="Enabled">Whether this validated rule contributes to native enforcement; false retains all intent and order.</param>
/// <param name="DestinationPortObject">Optional immutable port-list version; mutually exclusive with literal destination ports. Compilation validates its type and every existing matcher constraint.</param>
public sealed record SnatRule(
    IpFamily Family,
    NetworkPrefix? Source,
    string? TranslatedAddress,
    NetworkPrefix? Destination = null,
    string? OutputInterface = null,
    string? Description = null,
    NatPostroutingAction Action = NatPostroutingAction.Snat,
    string? InputInterface = null,
    FilterProtocol Protocol = FilterProtocol.Any,
    int? DestinationPort = null,
    IReadOnlyList<int>? DestinationPorts = null,
    bool NegateSource = false,
    bool NegateDestination = false,
    bool NegateInputInterface = false,
    bool NegateOutputInterface = false,
    bool Enabled = true,
    PolicyObjectReference? DestinationPortObject = null);

/// <summary>An immutable, versioned snapshot of ordered dual-stack DNAT and postrouting actions.</summary>
public sealed class NatPolicy
{
    /// <summary>Current supported NAT policy schema version.</summary>
    public const int CurrentSchemaVersion = 1;

    /// <summary>Snapshots ordered DNAT and postrouting rules without discarding invalid entries.</summary>
    /// <param name="schemaVersion">Must be 1 for the current NAT compiler.</param>
    /// <param name="dnatRules">Ordered prerouting destination NAT rules; null entries remain for diagnostics.</param>
    /// <param name="snatRules">Ordered postrouting source NAT and exemption rules; null entries remain for diagnostics.</param>
    /// <exception cref="ArgumentNullException">Either rule collection is null.</exception>
    public NatPolicy(int schemaVersion, IEnumerable<DnatRule?> dnatRules, IEnumerable<SnatRule?> snatRules)
    {
        ArgumentNullException.ThrowIfNull(dnatRules);
        ArgumentNullException.ThrowIfNull(snatRules);
        SchemaVersion = schemaVersion;
        DnatRules = Array.AsReadOnly(dnatRules.ToArray());
        SnatRules = Array.AsReadOnly(snatRules.Select(r => r is null ? null : r with
        {
            DestinationPorts = r.DestinationPorts is null ? null : Array.AsReadOnly(r.DestinationPorts.ToArray()),
        }).ToArray());
    }

    /// <summary>Gets the schema version validated prior to compilation.</summary>
    public int SchemaVersion { get; }

    /// <summary>Gets the defensive ordered prerouting DNAT rule snapshot.</summary>
    public IReadOnlyList<DnatRule?> DnatRules { get; }

    /// <summary>Gets the defensive ordered postrouting action snapshot.</summary>
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

        if (SnatRules.Any(r => r?.Action == NatPostroutingAction.Snat))
        {
            features.Add(FirewallFeature.ExplicitSourceNat);
        }

        if (SnatRules.Any(r => r is not null && r.Action != NatPostroutingAction.Snat)) { features.Add(FirewallFeature.MasqueradeAndNatExemptions); }
        if (DnatRules.Any(r => r is not null && (r.NegateSource || r.NegateDestination || r.NegateInputInterface)) ||
            SnatRules.Any(r => r is not null && (r.NegateSource || r.NegateDestination || r.NegateInputInterface || r.NegateOutputInterface)))
        { features.Add(FirewallFeature.RouterFiltering); }
        return features;
    }
}
