namespace Nergal.Core.Policy;

/// <summary>Address family of a rule.</summary>
public enum IpFamily
{
    /// <summary>IPv4 traffic.</summary>
    IPv4,
    /// <summary>IPv6 traffic.</summary>
    IPv6,
    /// <summary>One inet filter rule matching both IP versions, with family-independent predicates.</summary>
    DualStack,
}

/// <summary>Filtering decisions supported by policy rules.</summary>
public enum FilterVerdict
{
    /// <summary>Permit traffic, subject to other owners' base chains.</summary>
    Accept,
    /// <summary>Silently discard traffic.</summary>
    Drop,
    /// <summary>Actively reject traffic with ICMP/ICMPv6 administratively prohibited (<c>reject with icmpx type admin-prohibited</c>; schema 2 only).</summary>
    Reject,
    /// <summary>Evaluate the following rule after a counted filter match or a raw NOTRACK statement (schema 2 only).</summary>
    Continue,
    /// <summary>Actively reject with ICMP/ICMPv6 port unreachable, the default inet reject (schema 2 only).</summary>
    RejectPortUnreachable,
    /// <summary>Set the TCP SYN MSS from the native route MTU and continue evaluating the forward chain.</summary>
    ClampRouteMss,
    /// <summary>Call the declared table-local regular chain and resume at the next rule on return.</summary>
    Jump,
    /// <summary>Resume the calling chain at its next rule. Valid only in a regular chain.</summary>
    Return,
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
    /// <summary>A single protocol set matching TCP and UDP, optionally guarding a generic transport destination port.</summary>
    TcpOrUdp,
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
    /// <summary>A declared, unhooked chain identified by FilterRule.RegularChain.</summary>
    Regular,
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
    /// <summary>Packet explicitly excluded from connection tracking.</summary>
    Untracked = 16,
}

/// <summary>Supported rate-limit window units for per-source dynamic sets.</summary>
public enum RateLimitTimeUnit
{
    /// <summary>Packets permitted per second.</summary>
    Second,
    /// <summary>Packets permitted per minute.</summary>
    Minute,
}

/// <summary>Address key tracked by a dynamic nftables rate-limit meter.</summary>
public enum RateLimitKeyKind
{
    /// <summary>Rate-limit per source IP address (<c>saddr</c>).</summary>
    SourceAddress = 0,
    /// <summary>Rate-limit per destination IP address (<c>daddr</c>).</summary>
    DestinationAddress = 1,
}

/// <summary>Per-address token-bucket rate limit backed by a native dynamic nftables set.</summary>
/// <param name="PacketsPerWindow">Positive packet allowance per <paramref name="WindowUnit"/> (1–1000000).</param>
/// <param name="WindowUnit">Rate time unit (<see cref="RateLimitTimeUnit.Second"/> or <see cref="RateLimitTimeUnit.Minute"/>).</param>
/// <param name="Burst">Positive token-bucket burst size in packets (1–10000).</param>
/// <param name="EntryTimeoutSeconds">Entry lifetime in seconds (1–86400); refresh behavior is selected explicitly by RefreshEntryTimeout.</param>
/// <param name="KeyKind">Whether the meter keys on source address (<c>saddr</c>) or destination address (<c>daddr</c>).</param>
/// <param name="RefreshEntryTimeout">True preserves native update/meter idle-expiry semantics; false retains legacy add creation-expiry behavior.</param>
public sealed record PerSourceRateLimit(
    int PacketsPerWindow,
    RateLimitTimeUnit WindowUnit,
    int Burst,
    int EntryTimeoutSeconds = 60,
    RateLimitKeyKind KeyKind = RateLimitKeyKind.SourceAddress,
    bool RefreshEntryTimeout = false);

/// <summary>An ordered rule in an owned prerouting or output base chain at raw priority (-300).</summary>
/// <param name="Verdict">Accept or drop, or Continue for a standalone NOTRACK statement.</param>
/// <param name="Family">Optional explicit IP family when matching <paramref name="Source"/> or family-specific traffic.</param>
/// <param name="Protocol">Optional L4 protocol (<see cref="FilterProtocol.Any"/>, <see cref="FilterProtocol.Tcp"/>, or <see cref="FilterProtocol.Udp"/>).</param>
/// <param name="Source">Optional canonical source prefix restriction.</param>
/// <param name="NegateSource">When true, negates <paramref name="Source"/> (<c>!=</c>).</param>
/// <param name="InputInterface">Optional ingress interface name (<c>iifname</c>).</param>
/// <param name="NegateInputInterface">When true, negates <paramref name="InputInterface"/> (<c>iifname !=</c>).</param>
/// <param name="SourcePort">Optional TCP/UDP source port (e.g., UDP 68 for DHCP client bypass).</param>
/// <param name="DestinationPort">Optional TCP/UDP destination port.</param>
/// <param name="MatchFibUnreachable">When true, emits <c>fib saddr . iif oif == 0</c> reverse-path lookup.</param>
/// <param name="Description">Optional human-readable operator note (max 160 printable characters; metadata only).</param>
/// <param name="Enabled">Whether this validated rule contributes to native enforcement; false retains all intent and order.</param>
/// <param name="Notrack">Disable connection tracking for matching packets and continue to the next rule. Requires the Continue verdict.</param>
/// <param name="OutputInterface">Optional exact egress interface name in the raw output hook.</param>
/// <param name="NegateOutputInterface">Negates the egress interface matcher when present.</param>
public sealed record RpFilterRule(
    FilterVerdict Verdict,
    IpFamily? Family = null,
    FilterProtocol Protocol = FilterProtocol.Any,
    NetworkPrefix? Source = null,
    bool NegateSource = false,
    string? InputInterface = null,
    bool NegateInputInterface = false,
    int? SourcePort = null,
    int? DestinationPort = null,
    bool MatchFibUnreachable = false,
    string? Description = null,
    bool Enabled = true,
    bool Notrack = false,
    string? OutputInterface = null,
    bool NegateOutputInterface = false);

/// <summary>Configuration for one optional raw base chain in an owned inet filter table.</summary>
public sealed class RpFilterPolicy
{
    /// <summary>Snapshots the ordered raw rules, including disabled intent.</summary>
    /// <param name="defaultVerdict">Base chain default policy. Raw output and chains with NOTRACK require Accept.</param>
    /// <param name="rules">Ordered rules evaluated on the selected hook.</param>
    /// <exception cref="ArgumentNullException">The rules collection is null.</exception>
    public RpFilterPolicy(FilterVerdict defaultVerdict, IEnumerable<RpFilterRule?> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        DefaultVerdict = defaultVerdict;
        Rules = Array.AsReadOnly(rules.ToArray());
    }

    /// <summary>Gets the base chain default policy.</summary>
    public FilterVerdict DefaultVerdict { get; }

    /// <summary>Gets the ordered raw rules.</summary>
    public IReadOnlyList<RpFilterRule?> Rules { get; }
}

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
/// <param name="MatchOriginalDestinationDnat">Matches packets whose conntrack entry indicates destination NAT (<c>ct status dnat</c>; schema 2 only).</param>
/// <param name="SourcePrefixes">Optional inline source CIDR set (2–64 distinct prefixes; mutually exclusive with <paramref name="Source"/>; schema 2 only).</param>
/// <param name="DestinationPrefixes">Optional inline destination CIDR set (2–64 distinct prefixes; mutually exclusive with <paramref name="Destination"/>; schema 2 only).</param>
/// <param name="DestinationPorts">Optional inline TCP/UDP destination port set (2–64 distinct ports in 1–65535; mutually exclusive with <paramref name="DestinationPort"/>; schema 2 only).</param>
/// <param name="Description">Optional human-readable operator note (max 160 printable characters; metadata only).</param>
/// <param name="NegateInputInterface">When true, negates <paramref name="InputInterface"/> (<c>iifname !=</c>; schema 2 only).</param>
/// <param name="NegateOutputInterface">When true, negates <paramref name="OutputInterface"/> (<c>oifname !=</c>; schema 2 only).</param>
/// <param name="NegateSource">When true, negates <paramref name="Source"/> or <paramref name="SourcePrefixes"/> (<c>!=</c>; schema 2 only).</param>
/// <param name="NegateDestination">When true, negates <paramref name="Destination"/> or <paramref name="DestinationPrefixes"/> (<c>!=</c>; schema 2 only).</param>
/// <param name="SourceMac">Optional L2 source MAC address (<c>ether saddr</c>; mutually exclusive with <paramref name="SourceMacs"/>; schema 2 only).</param>
/// <param name="SourceMacs">Optional inline L2 source MAC address set (2–64 distinct MACs; mutually exclusive with <paramref name="SourceMac"/>; schema 2 only).</param>
/// <param name="NegateSourceMac">When true, negates <paramref name="SourceMac"/> or <paramref name="SourceMacs"/> (<c>ether saddr !=</c>; schema 2 only).</param>
/// <param name="SourceObject">Optional pinned address-list reference, exclusive with source literals.</param>
/// <param name="DestinationObject">Optional pinned address-list reference, exclusive with destination literals.</param>
/// <param name="DestinationPortObject">Optional pinned port-list reference, exclusive with destination-port literals.</param>
/// <param name="Enabled">Whether this validated rule contributes to native enforcement; false retains all intent and order.</param>
/// <param name="CountPackets">Count packets and bytes after all matches and any meter, then evaluate the verdict (schema 2 only). A dual-stack rule has one shared counter.</param>
/// <param name="OriginalSourcePrefixes">Optional original-direction source addresses for a DNAT connection.</param>
/// <param name="OriginalDestinationPrefixes">Optional original-direction destination addresses for a DNAT connection.</param>
/// <param name="BindInputInterfaceIndex">Resolve the input interface name to its index at install time, using native `iif` instead of `iifname`.</param>
/// <param name="RegularChain">Declared chain containing this rule when Chain is Regular.</param>
/// <param name="JumpTarget">Declared regular chain called by a Jump verdict in this table.</param>
/// <param name="InputInterfaceSelector">Optional input name prefix or set, mutually exclusive with the scalar input name.</param>
/// <param name="OutputInterfaceSelector">Optional output name prefix or set, mutually exclusive with the scalar output name.</param>
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
    PerSourceRateLimit? RateLimit = null,
    bool MatchOriginalDestinationDnat = false,
    IReadOnlyList<NetworkPrefix>? SourcePrefixes = null,
    IReadOnlyList<NetworkPrefix>? DestinationPrefixes = null,
    IReadOnlyList<int>? DestinationPorts = null,
    string? Description = null,
    bool NegateInputInterface = false,
    bool NegateOutputInterface = false,
    bool NegateSource = false,
    bool NegateDestination = false,
    MacAddress? SourceMac = null,
    IReadOnlyList<MacAddress>? SourceMacs = null,
    bool NegateSourceMac = false,
    PolicyObjectReference? SourceObject = null,
    PolicyObjectReference? DestinationObject = null,
    PolicyObjectReference? DestinationPortObject = null,
    bool Enabled = true,
    bool CountPackets = false,
    IReadOnlyList<NetworkPrefix>? OriginalSourcePrefixes = null,
    IReadOnlyList<NetworkPrefix>? OriginalDestinationPrefixes = null,
    bool BindInputInterfaceIndex = false,
    string? RegularChain = null,
    string? JumpTarget = null,
    InterfaceNameSelector? InputInterfaceSelector = null,
    InterfaceNameSelector? OutputInterfaceSelector = null)
{
    /// <summary>Whether one native rule must preserve an interface or protocol selector.</summary>
    public bool UsesNativeSelectors => InputInterfaceSelector is not null || OutputInterfaceSelector is not null || Protocol == FilterProtocol.TcpOrUdp;

    /// <inheritdoc />
    public bool Equals(FilterRule? other)
    {
        if (ReferenceEquals(this, other))
        {
            return true;
        }

        if (other is null)
        {
            return false;
        }

        return Family == other.Family &&
            Protocol == other.Protocol &&
            Verdict == other.Verdict &&
            Equals(Source, other.Source) &&
            Equals(Destination, other.Destination) &&
            DestinationPort == other.DestinationPort &&
            Chain == other.Chain && RegularChain == other.RegularChain && JumpTarget == other.JumpTarget &&
            string.Equals(InputInterface, other.InputInterface, StringComparison.Ordinal) &&
            string.Equals(OutputInterface, other.OutputInterface, StringComparison.Ordinal) &&
            ConnectionStates == other.ConnectionStates &&
            string.Equals(IcmpType, other.IcmpType, StringComparison.Ordinal) &&
            Equals(RateLimit, other.RateLimit) &&
            MatchOriginalDestinationDnat == other.MatchOriginalDestinationDnat &&
            SequenceEqual(OriginalSourcePrefixes, other.OriginalSourcePrefixes) &&
            SequenceEqual(OriginalDestinationPrefixes, other.OriginalDestinationPrefixes) &&
            SequenceEqual(SourcePrefixes, other.SourcePrefixes) &&
            SequenceEqual(DestinationPrefixes, other.DestinationPrefixes) &&
            SequenceEqual(DestinationPorts, other.DestinationPorts) &&
            string.Equals(Description, other.Description, StringComparison.Ordinal) &&
            NegateInputInterface == other.NegateInputInterface &&
            BindInputInterfaceIndex == other.BindInputInterfaceIndex &&
            Equals(InputInterfaceSelector, other.InputInterfaceSelector) && Equals(OutputInterfaceSelector, other.OutputInterfaceSelector) &&
            NegateOutputInterface == other.NegateOutputInterface &&
            NegateSource == other.NegateSource &&
            NegateDestination == other.NegateDestination &&
            Equals(SourceMac, other.SourceMac) &&
            SequenceEqual(SourceMacs, other.SourceMacs) &&
            NegateSourceMac == other.NegateSourceMac &&
            CountPackets == other.CountPackets &&
            Enabled == other.Enabled && Equals(SourceObject, other.SourceObject) && Equals(DestinationObject, other.DestinationObject) && Equals(DestinationPortObject, other.DestinationPortObject);
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Family);
        hash.Add(Protocol);
        hash.Add(Verdict);
        hash.Add(Source);
        hash.Add(Destination);
        hash.Add(DestinationPort);
        hash.Add(Chain);
        hash.Add(RegularChain);
        hash.Add(JumpTarget);
        hash.Add(InputInterface, StringComparer.Ordinal);
        hash.Add(OutputInterface, StringComparer.Ordinal);
        hash.Add(ConnectionStates);
        hash.Add(IcmpType, StringComparer.Ordinal);
        hash.Add(RateLimit);
        hash.Add(MatchOriginalDestinationDnat);
        AddSequenceHash(ref hash, OriginalSourcePrefixes);
        AddSequenceHash(ref hash, OriginalDestinationPrefixes);
        AddSequenceHash(ref hash, SourcePrefixes);
        AddSequenceHash(ref hash, DestinationPrefixes);
        AddSequenceHash(ref hash, DestinationPorts);
        hash.Add(Description, StringComparer.Ordinal);
        hash.Add(NegateInputInterface);
        hash.Add(BindInputInterfaceIndex);
        hash.Add(InputInterfaceSelector);
        hash.Add(OutputInterfaceSelector);
        hash.Add(NegateOutputInterface);
        hash.Add(NegateSource);
        hash.Add(NegateDestination);
        hash.Add(SourceMac);
        AddSequenceHash(ref hash, SourceMacs);
        hash.Add(NegateSourceMac);
        hash.Add(CountPackets);
        hash.Add(Enabled); hash.Add(SourceObject); hash.Add(DestinationObject); hash.Add(DestinationPortObject);
        return hash.ToHashCode();
    }

    private static bool SequenceEqual<T>(IReadOnlyList<T>? a, IReadOnlyList<T>? b)
    {
        if (ReferenceEquals(a, b))
        {
            return true;
        }

        if (a is null || b is null || a.Count != b.Count)
        {
            return false;
        }

        var comparer = EqualityComparer<T>.Default;
        for (var i = 0; i < a.Count; i++)
        {
            if (!comparer.Equals(a[i], b[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static void AddSequenceHash<T>(ref HashCode hash, IReadOnlyList<T>? list)
    {
        if (list is null)
        {
            hash.Add(-1);
            return;
        }

        hash.Add(list.Count);
        for (var i = 0; i < list.Count; i++)
        {
            hash.Add(list[i]);
        }
    }
}

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

    /// <summary>Snapshots rules with explicit per-chain default verdicts for input, forward, and output hooks, plus optional raw rpfilter and forward TCP MSS clamp.</summary>
    /// <param name="schemaVersion">Schema version (1 requires Drop for forward/output and input-only rules; 2 enables all base chains and router constructs).</param>
    /// <param name="inputDefaultVerdict">Decision for unmatched traffic on the input hook.</param>
    /// <param name="forwardDefaultVerdict">Decision for unmatched traffic on the forward hook.</param>
    /// <param name="outputDefaultVerdict">Decision for unmatched traffic on the output hook.</param>
    /// <param name="rules">Ordered rules; null entries are retained for diagnostics.</param>
    /// <param name="rpFilter">Optional raw prerouting reverse-path filter chain (schema 2 only).</param>
    /// <param name="regularChains">Ordered names of local regular chains, including empty chains.</param>
    /// <param name="rawOutput">Optional raw output chain (schema 2 only, accept default).</param>
    /// <param name="forwardTcpMssClampEnabled">Whether the retained MSS clamp contributes to native enforcement.</param>
    /// <param name="forwardTcpMssClamp">Optional forward-chain TCP SYN MSS clamp in bytes (536–1460; schema 2 only).</param>
    /// <exception cref="ArgumentNullException">The collection is null.</exception>
    public FilterPolicy(
        int schemaVersion,
        FilterVerdict inputDefaultVerdict,
        FilterVerdict forwardDefaultVerdict,
        FilterVerdict outputDefaultVerdict,
        IEnumerable<FilterRule?> rules,
        RpFilterPolicy? rpFilter = null,
        int? forwardTcpMssClamp = null,
        bool forwardTcpMssClampEnabled = true,
        RpFilterPolicy? rawOutput = null,
        IEnumerable<string>? regularChains = null)
    {
        ArgumentNullException.ThrowIfNull(rules);
        SchemaVersion = schemaVersion;
        InputDefaultVerdict = inputDefaultVerdict;
        ForwardDefaultVerdict = forwardDefaultVerdict;
        OutputDefaultVerdict = outputDefaultVerdict;
        Rules = Array.AsReadOnly(rules.Select(rule => rule is null ? null : rule with
        {
            SourcePrefixes = rule.SourcePrefixes is null ? null : Array.AsReadOnly(rule.SourcePrefixes.ToArray()),
            DestinationPrefixes = rule.DestinationPrefixes is null ? null : Array.AsReadOnly(rule.DestinationPrefixes.ToArray()),
            DestinationPorts = rule.DestinationPorts is null ? null : Array.AsReadOnly(rule.DestinationPorts.ToArray()),
            SourceMacs = rule.SourceMacs is null ? null : Array.AsReadOnly(rule.SourceMacs.ToArray()),
            OriginalSourcePrefixes = rule.OriginalSourcePrefixes is null ? null : Array.AsReadOnly(rule.OriginalSourcePrefixes.ToArray()),
            OriginalDestinationPrefixes = rule.OriginalDestinationPrefixes is null ? null : Array.AsReadOnly(rule.OriginalDestinationPrefixes.ToArray()),
        }).ToArray());
        RpFilter = rpFilter;
        RawOutput = rawOutput;
        RegularChains = Array.AsReadOnly(regularChains?.ToArray() ?? []);
        ForwardTcpMssClamp = forwardTcpMssClamp;
        ForwardTcpMssClampEnabled = forwardTcpMssClampEnabled;
    }

    /// <summary>Gets the ordered, snapshotted regular-chain declarations.</summary>
    public IReadOnlyList<string> RegularChains { get; }

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

    /// <summary>Gets the optional raw prerouting reverse-path filter chain configuration.</summary>
    public RpFilterPolicy? RpFilter { get; }

    /// <summary>Gets the optional raw-priority output chain configuration.</summary>
    public RpFilterPolicy? RawOutput { get; }

    /// <summary>Gets the optional forward-chain TCP SYN MSS clamp in bytes (536–1460).</summary>
    public int? ForwardTcpMssClamp { get; }

    /// <summary>Gets whether the retained MSS clamp is active in the native projection.</summary>
    public bool ForwardTcpMssClampEnabled { get; }

    /// <summary>Computes the semantic backend features required by this filter policy.</summary>
    public IReadOnlySet<FirewallFeature> GetRequiredFeatures()
    {
        var features = new HashSet<FirewallFeature>
        {
            FirewallFeature.DualStackFiltering,
            FirewallFeature.ForeignTablePreservation,
        };
        if (Rules.Any(rule => rule?.RateLimit?.KeyKind == RateLimitKeyKind.SourceAddress))
        {
            features.Add(FirewallFeature.PerSourceRateLimiting);
        }

        if (Rules.Any(rule => rule?.RateLimit?.KeyKind == RateLimitKeyKind.DestinationAddress)) { features.Add(FirewallFeature.PerDestinationRateLimiting); }
        if (Rules.Any(rule => rule?.RateLimit?.RefreshEntryTimeout == true)) { features.Add(FirewallFeature.MeterEntryTimeoutRefresh); }
        if (RegularChains.Count > 0) { features.Add(FirewallFeature.FilterChainCalls); }
        if (Rules.Any(rule => rule?.CountPackets == true)) { features.Add(FirewallFeature.InlineFilterCounters); }
        if (Rules.Any(rule => rule?.UsesNativeSelectors == true)) { features.Add(FirewallFeature.FilterSelectorSets); }
        if (Rules.Any(rule => rule?.BindInputInterfaceIndex == true)) { features.Add(FirewallFeature.InputInterfaceIndexBinding); }
        if (Rules.Any(rule => rule?.Verdict == FilterVerdict.ClampRouteMss)) { features.Add(FirewallFeature.RouteDerivedMss); }
        if (RpFilter is not null || RawOutput is not null || ForwardTcpMssClamp is not null || Rules.Any(r => r is not null &&
            (r.SourceMac is not null || r.SourceMacs is not null || r.NegateSource || r.NegateDestination || r.NegateInputInterface || r.NegateOutputInterface || r.Verdict is FilterVerdict.Reject or FilterVerdict.RejectPortUnreachable)))
        { features.Add(FirewallFeature.RouterFiltering); }
        if (Rules.Any(rule => rule?.MatchOriginalDestinationDnat == true))
        {
            features.Add(FirewallFeature.OriginalConnectionTuple);
        }

        return features;
    }
}
