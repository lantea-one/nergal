namespace Nergal.Core.Policy;

/// <summary>Address family of a rule; every rule explicitly selects one IP version.</summary>
public enum IpFamily
{
    /// <summary>IPv4 traffic.</summary>
    IPv4,
    /// <summary>IPv6 traffic.</summary>
    IPv6,
}

/// <summary>Terminal stateless filtering decisions supported by schema version 1.</summary>
public enum FilterVerdict
{
    /// <summary>Permit traffic, subject to other owners' base chains.</summary>
    Accept,
    /// <summary>Silently discard traffic.</summary>
    Drop,
}

/// <summary>Protocols supported without semantic approximation.</summary>
public enum FilterProtocol
{
    /// <summary>Any protocol in the selected IP family.</summary>
    Any,
    /// <summary>TCP, optionally restricted to one destination port.</summary>
    Tcp,
    /// <summary>UDP, optionally restricted to one destination port.</summary>
    Udp,
    /// <summary>ICMP for IPv4 only, without type restrictions.</summary>
    Icmp,
    /// <summary>ICMPv6 for IPv6 only, without type restrictions.</summary>
    IcmpV6,
}

/// <summary>Filter base chains supported by policy schema versions 1 and 2.</summary>
public enum FilterChainKind
{
    /// <summary>Traffic destined to the local host (`hook input`).</summary>
    Input,
    /// <summary>Routed traffic traversing the host between interfaces (`hook forward`).</summary>
    Forward,
    /// <summary>Traffic originating from the local host (`hook output`).</summary>
    Output,
}

/// <summary>Connection-tracking states matched against kernel conntrack state in schema version 2.</summary>
[Flags]
public enum ConnectionStateFlags
{
    /// <summary>No connection-state restriction (stateless match).</summary>
    None = 0,
    /// <summary>Initial packet establishing a tracked flow.</summary>
    New = 1,
    /// <summary>Packet matching an already established two-way flow.</summary>
    Established = 2,
    /// <summary>Packet starting a flow related to an existing tracked flow.</summary>
    Related = 4,
    /// <summary>Packet that cannot be associated with a known valid connection.</summary>
    Invalid = 8,
}

/// <summary>Supported rate-limit window units for per-source dynamic sets.</summary>
public enum RateLimitTimeUnit
{
    /// <summary>Packets permitted per second.</summary>
    Second,
    /// <summary>Packets permitted per minute.</summary>
    Minute,
}

/// <summary>Per-source token-bucket rate limit backed by a native dynamic nftables set.</summary>
/// <param name="PacketsPerWindow">Positive packet allowance per <paramref name="WindowUnit"/> (1–1000000).</param>
/// <param name="WindowUnit">Rate time unit (<see cref="RateLimitTimeUnit.Second"/> or <see cref="RateLimitTimeUnit.Minute"/>).</param>
/// <param name="Burst">Positive token-bucket burst size in packets (1–10000).</param>
/// <param name="EntryTimeoutSeconds">Idle timeout in seconds before evicting per-source state (1–86400).</param>
public sealed record PerSourceRateLimit(
    int PacketsPerWindow,
    RateLimitTimeUnit WindowUnit,
    int Burst,
    int EntryTimeoutSeconds = 60);

/// <summary>An immutable rule draft; cross-field validity is assessed by the compiler.</summary>
/// <param name="Family">The explicit IP family.</param>
/// <param name="Protocol">The protocol; unknown enum values are rejected.</param>
/// <param name="Verdict">The terminal decision.</param>
/// <param name="Source">An optional canonical source network.</param>
/// <param name="Destination">An optional canonical destination network.</param>
/// <param name="DestinationPort">A TCP/UDP port in 1–65535, or null for all ports.</param>
/// <param name="Chain">Target base filter chain; schema 1 permits only <see cref="FilterChainKind.Input"/>.</param>
/// <param name="InputInterface">Optional ingress interface name (<c>iifname</c>), valid on <see cref="FilterChainKind.Input"/> and <see cref="FilterChainKind.Forward"/>.</param>
/// <param name="OutputInterface">Optional egress interface name (<c>oifname</c>), valid on <see cref="FilterChainKind.Forward"/> and <see cref="FilterChainKind.Output"/>.</param>
/// <param name="ConnectionStates">Optional conntrack state mask (`None` for stateless match; schema 2 only).</param>
/// <param name="IcmpType">Optional canonical ICMP/ICMPv6 type name (schema 2 only).</param>
/// <param name="RateLimit">Optional per-source token-bucket rate limit backed by a dynamic set (schema 2 only).</param>
public sealed record FilterRule(
    IpFamily Family,
    FilterProtocol Protocol,
    FilterVerdict Verdict,
    NetworkPrefix? Source = null,
    NetworkPrefix? Destination = null,
    int? DestinationPort = null,
    FilterChainKind Chain = FilterChainKind.Input,
    string? InputInterface = null,
    string? OutputInterface = null,
    ConnectionStateFlags ConnectionStates = ConnectionStateFlags.None,
    string? IcmpType = null,
    PerSourceRateLimit? RateLimit = null);

/// <summary>An immutable, versioned snapshot of ordered host and forwarding filter rules.</summary>
public sealed class FilterPolicy
{
    /// <summary>Snapshots rules without silently discarding invalid drafts; forward/output default to drop when omitted.</summary>
    /// <param name="schemaVersion">1 for input-only stateless filtering; 2 for multi-chain stateful filtering.</param>
    /// <param name="defaultVerdict">Decision for unmatched input traffic.</param>
    /// <param name="rules">Ordered rules; null entries are retained for diagnostics.</param>
    /// <exception cref="ArgumentNullException">The collection is null.</exception>
    public FilterPolicy(int schemaVersion, FilterVerdict defaultVerdict, IEnumerable<FilterRule?> rules)
        : this(schemaVersion, defaultVerdict, FilterVerdict.Drop, FilterVerdict.Drop, rules)
    {
    }

    /// <summary>Snapshots rules with explicit per-chain default verdicts for input, forward, and output hooks.</summary>
    /// <param name="schemaVersion">Schema version (1 requires Drop for forward/output and input-only rules; 2 enables all base chains).</param>
    /// <param name="inputDefaultVerdict">Decision for unmatched traffic on the input hook.</param>
    /// <param name="forwardDefaultVerdict">Decision for unmatched traffic on the forward hook.</param>
    /// <param name="outputDefaultVerdict">Decision for unmatched traffic on the output hook.</param>
    /// <param name="rules">Ordered rules; null entries are retained for diagnostics.</param>
    /// <exception cref="ArgumentNullException">The collection is null.</exception>
    public FilterPolicy(
        int schemaVersion,
        FilterVerdict inputDefaultVerdict,
        FilterVerdict forwardDefaultVerdict,
        FilterVerdict outputDefaultVerdict,
        IEnumerable<FilterRule?> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        SchemaVersion = schemaVersion;
        InputDefaultVerdict = inputDefaultVerdict;
        ForwardDefaultVerdict = forwardDefaultVerdict;
        OutputDefaultVerdict = outputDefaultVerdict;
        Rules = Array.AsReadOnly(rules.ToArray());
    }

    /// <summary>Gets the schema version, validated before compilation.</summary>
    public int SchemaVersion { get; }

    /// <summary>Gets the explicit unmatched-input decision.</summary>
    public FilterVerdict DefaultVerdict => InputDefaultVerdict;

    /// <summary>Gets the explicit unmatched-input decision.</summary>
    public FilterVerdict InputDefaultVerdict { get; }

    /// <summary>Gets the explicit unmatched-forward decision.</summary>
    public FilterVerdict ForwardDefaultVerdict { get; }

    /// <summary>Gets the explicit unmatched-output decision.</summary>
    public FilterVerdict OutputDefaultVerdict { get; }

    /// <summary>Gets the defensive, ordered snapshot; no automatic permit rules exist.</summary>
    public IReadOnlyList<FilterRule?> Rules { get; }

    /// <summary>Computes the semantic backend features required by this filter policy.</summary>
    public IReadOnlySet<FirewallFeature> GetRequiredFeatures()
    {
        var features = new HashSet<FirewallFeature>
        {
            FirewallFeature.DualStackFiltering,
            FirewallFeature.ForeignTablePreservation,
        };
        if (Rules.Any(rule => rule?.RateLimit is not null))
        {
            features.Add(FirewallFeature.PerSourceRateLimiting);
        }

        return features;
    }
}
