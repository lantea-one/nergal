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

/// <summary>An immutable rule draft; cross-field validity is assessed by the compiler.</summary>
/// <param name="Family">The explicit IP family.</param>
/// <param name="Protocol">The protocol; unknown enum values are rejected.</param>
/// <param name="Verdict">The terminal decision.</param>
/// <param name="Source">An optional canonical source network.</param>
/// <param name="Destination">An optional canonical destination network.</param>
/// <param name="DestinationPort">A TCP/UDP port in 1–65535, or null for all ports.</param>
public sealed record FilterRule(
    IpFamily Family,
    FilterProtocol Protocol,
    FilterVerdict Verdict,
    NetworkPrefix? Source = null,
    NetworkPrefix? Destination = null,
    int? DestinationPort = null);

/// <summary>An immutable, versioned snapshot of ordered host input-filter rules.</summary>
public sealed class FilterPolicy
{
    /// <summary>Snapshots rules without silently discarding invalid drafts.</summary>
    /// <param name="schemaVersion">Must be 1 for the current compiler.</param>
    /// <param name="defaultVerdict">Decision for unmatched input traffic.</param>
    /// <param name="rules">Ordered rules; null entries are retained for diagnostics.</param>
    /// <exception cref="ArgumentNullException">The collection is null.</exception>
    public FilterPolicy(int schemaVersion, FilterVerdict defaultVerdict, IEnumerable<FilterRule?> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        SchemaVersion = schemaVersion;
        DefaultVerdict = defaultVerdict;
        Rules = Array.AsReadOnly(rules.ToArray());
    }

    /// <summary>Gets the schema version, validated before compilation.</summary>
    public int SchemaVersion { get; }

    /// <summary>Gets the explicit unmatched-input decision.</summary>
    public FilterVerdict DefaultVerdict { get; }

    /// <summary>Gets the defensive, ordered snapshot; no automatic permit rules exist.</summary>
    public IReadOnlyList<FilterRule?> Rules { get; }
}
