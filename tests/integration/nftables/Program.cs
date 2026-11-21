using Nergal.Core.Policy;
using Nergal.Nftables;

// Only synthetic documentation addresses; this program emits text or verifies snapshots without host mutations.
var mode = args.Length > 0 ? args[0] : "schema1";
var routerIdentity = new NftTableIdentity(
    Guid.Parse("00000000-0000-0000-0000-000000000010"),
    Guid.Parse("00000000-0000-0000-0000-000000000020"));

if (mode == "schema1")
{
    var rules = new List<FilterRule?>();
    foreach (var family in Enum.GetValues<IpFamily>())
    {
        var address = family == IpFamily.IPv4 ? "192.0.2.1/32" : "2001:db8::1/128";
        rules.Add(new(family, FilterProtocol.Tcp, FilterVerdict.Drop, DestinationPort: 18082));
        rules.Add(new(family, FilterProtocol.Tcp, FilterVerdict.Accept, new(address), new(address)));
        rules.Add(new(family, FilterProtocol.Udp, FilterVerdict.Accept, new(address), new(address), 18081));
        rules.Add(new(family, family == IpFamily.IPv4 ? FilterProtocol.Icmp : FilterProtocol.IcmpV6, FilterVerdict.Accept));
    }

    var result = NftFilterCompiler.Compile(new(1, FilterVerdict.Drop, rules));
    if (!result.IsSuccess)
    {
        throw new InvalidOperationException("The fixed fixture policy must compile.");
    }

    Console.Write(result.Candidate);
    return 0;
}

if (mode == "router")
{
    var policy = BuildRouterPolicy();
    var result = NftFilterCompiler.Compile(policy, routerIdentity);
    if (!result.IsSuccess)
    {
        throw new InvalidOperationException("Router schema-2 policy failed: " + string.Join(", ", result.Diagnostics));
    }

    Console.Write(result.Candidate);
    return 0;
}

if (mode == "verify-router" && args.Length is 3 or 4)
{
    var expected = NftFilterCompiler.Compile(BuildRouterPolicy(), routerIdentity).Candidate!;
    var echoJson = File.ReadAllText(args[1]);
    var listJson = File.ReadAllText(args[2]);
    var echoed = NftTableObservation.ParseReplacementEcho(echoJson);
    if (!echoed.IsSuccess)
    {
        throw new InvalidOperationException("Router echo failed: " + echoed.ErrorCode);
    }

    var listed = NftTableObservation.Parse(listJson);
    if (!listed.IsSuccess)
    {
        throw new InvalidOperationException("Router listing failed: " + listed.ErrorCode);
    }

    if (echoed.Observation!.StateDigest != listed.Observation!.StateDigest)
    {
        throw new InvalidOperationException("Router echo and listing state digests diverged.");
    }

    if (args.Length == 4)
    {
        var terse = NftTableObservation.Parse(File.ReadAllText(args[3]));
        if (!terse.IsSuccess)
        {
            throw new InvalidOperationException("Router terse listing failed: " + terse.ErrorCode);
        }

        if (terse.Observation!.StateDigest != listed.Observation.StateDigest)
        {
            throw new InvalidOperationException("Router plain and terse state digests diverged.");
        }
    }

    var recompiled = NftFilterCompiler.Compile(listed.Observation.Policy, listed.Observation.Identity).Candidate;
    if (recompiled != expected)
    {
        throw new InvalidOperationException("Router policy did not round-trip deterministically.");
    }

    return 0;
}

if (mode == "nat-filter")
{
    var result = NftFilterCompiler.Compile(BuildNatFilterPolicy(), routerIdentity);
    if (!result.IsSuccess)
    {
        throw new InvalidOperationException("NAT filter policy failed: " + string.Join(", ", result.Diagnostics));
    }

    Console.Write(result.Candidate);
    return 0;
}

if (mode == "nat")
{
    var result = NftNatCompiler.Compile(BuildNatPolicy(), routerIdentity);
    if (!result.IsSuccess)
    {
        throw new InvalidOperationException("NAT policy failed: " + string.Join(", ", result.Diagnostics));
    }

    Console.Write(result.Candidate);
    return 0;
}

if (mode == "verify-nat" && args.Length == 5)
{
    var expectedFilter = NftFilterCompiler.Compile(BuildNatFilterPolicy(), routerIdentity).Candidate!;
    var expectedNat = NftNatCompiler.Compile(BuildNatPolicy(), routerIdentity).Candidate!;

    var filterEcho = NftTableObservation.ParseReplacementEcho(File.ReadAllText(args[1]));
    var filterList = NftTableObservation.Parse(File.ReadAllText(args[2]));
    if (!filterEcho.IsSuccess || !filterList.IsSuccess ||
        filterEcho.Observation!.StateDigest != filterList.Observation!.StateDigest ||
        NftFilterCompiler.Compile(filterList.Observation.Policy, filterList.Observation.Identity).Candidate != expectedFilter)
    {
        throw new InvalidOperationException("NAT filter observation verification failed.");
    }

    var natEcho = NftNatTableObservation.ParseReplacementEcho(File.ReadAllText(args[3]));
    var natList = NftNatTableObservation.Parse(File.ReadAllText(args[4]));
    if (!natEcho.IsSuccess || !natList.IsSuccess ||
        natEcho.Observation!.StateDigest != natList.Observation!.StateDigest ||
        NftNatCompiler.Compile(natList.Observation.Policy, natList.Observation.Identity).Candidate != expectedNat)
    {
        throw new InvalidOperationException("NAT table observation verification failed.");
    }

    return 0;
}

if (mode == "bundle-create")
{
    var result = NftPolicyBundleCompiler.Compile(BuildBundleV1(), routerIdentity);
    if (!result.IsSuccess)
    {
        throw new InvalidOperationException("Bundle v1 compile failed: " + string.Join(", ", result.Diagnostics));
    }

    Console.Write(result.Candidate);
    return 0;
}

if (mode == "bundle-replace")
{
    var result = NftPolicyBundleCompiler.CompileAtomicReplacement(
        BuildBundleV2(), routerIdentity, filterExists: true, natExists: true, bridgeExists: true);
    if (!result.IsSuccess)
    {
        throw new InvalidOperationException("Bundle v2 replace compile failed: " + string.Join(", ", result.Diagnostics));
    }

    Console.Write(result.Candidate);
    return 0;
}

if (mode == "verify-bundle" && args.Length == 3)
{
    var v2 = BuildBundleV2();
    var expectedFilter = NftFilterCompiler.Compile(v2.Filter, routerIdentity).Candidate!;
    var expectedBridge = NftBridgeCompiler.Compile(v2.Bridge!, routerIdentity).Candidate!;

    var filterList = NftTableObservation.Parse(File.ReadAllText(args[1]));
    if (!filterList.IsSuccess ||
        NftFilterCompiler.Compile(filterList.Observation!.Policy, filterList.Observation.Identity).Candidate != expectedFilter)
    {
        throw new InvalidOperationException("Bundle filter listing failed.");
    }

    var bridgeList = NftBridgeTableObservation.Parse(File.ReadAllText(args[2]));
    if (!bridgeList.IsSuccess ||
        NftBridgeCompiler.Compile(bridgeList.Observation!.Policy, bridgeList.Observation.Identity).Candidate != expectedBridge)
    {
        throw new InvalidOperationException("Bundle bridge listing failed.");
    }

    return 0;
}

throw new ArgumentException("Unsupported fixture mode.");

static FirewallPolicyBundle BuildBundleV1() => new(1,
    new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Drop, []),
    new(1, [new(IpFamily.IPv4, FilterProtocol.Tcp, new("192.0.2.99/32"), "192.0.2.20", 80, 8080)], []),
    new(1, FilterVerdict.Drop,
    [
        new(BridgeEtherType.Arp, FilterVerdict.Accept, "veth_br_a", "veth_br_b"),
        new(BridgeEtherType.Arp, FilterVerdict.Accept, "veth_br_b", "veth_br_a"),
        new(BridgeEtherType.IPv4, FilterVerdict.Accept, "veth_br_a", "veth_br_b"),
        new(BridgeEtherType.IPv4, FilterVerdict.Accept, "veth_br_b", "veth_br_a"),
    ]));

static FirewallPolicyBundle BuildBundleV2() => new(1,
    new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Drop, []),
    null,
    new(1, FilterVerdict.Drop,
    [
        new(BridgeEtherType.Arp, FilterVerdict.Accept, "veth_br_a", "veth_br_b"),
        new(BridgeEtherType.Arp, FilterVerdict.Accept, "veth_br_b", "veth_br_a"),
        new(BridgeEtherType.IPv4, FilterVerdict.Accept, "veth_br_a", "veth_br_b"),
        new(BridgeEtherType.IPv4, FilterVerdict.Accept, "veth_br_b", "veth_br_a"),
        new(BridgeEtherType.IPv6, FilterVerdict.Accept, "veth_br_a", "veth_br_b"),
        new(BridgeEtherType.IPv6, FilterVerdict.Accept, "veth_br_b", "veth_br_a"),
    ]));

static FilterPolicy BuildNatFilterPolicy()
{
    var rules = new List<FilterRule?>
    {
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Input, InputInterface: "r_cli", IcmpType: FilterIcmpTypes.NdNeighborSolicit),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Input, InputInterface: "r_cli", IcmpType: FilterIcmpTypes.NdNeighborAdvert),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Input, InputInterface: "r_srv", IcmpType: FilterIcmpTypes.NdNeighborSolicit),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Input, InputInterface: "r_srv", IcmpType: FilterIcmpTypes.NdNeighborAdvert),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Output, OutputInterface: "r_cli", IcmpType: FilterIcmpTypes.NdNeighborSolicit),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Output, OutputInterface: "r_cli", IcmpType: FilterIcmpTypes.NdNeighborAdvert),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Output, OutputInterface: "r_srv", IcmpType: FilterIcmpTypes.NdNeighborSolicit),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Output, OutputInterface: "r_srv", IcmpType: FilterIcmpTypes.NdNeighborAdvert),
        new(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Accept, Chain: FilterChainKind.Forward, InputInterface: "r_srv", OutputInterface: "r_cli", ConnectionStates: ConnectionStateFlags.Established | ConnectionStateFlags.Related),
        new(IpFamily.IPv6, FilterProtocol.Any, FilterVerdict.Accept, Chain: FilterChainKind.Forward, InputInterface: "r_srv", OutputInterface: "r_cli", ConnectionStates: ConnectionStateFlags.Established | ConnectionStateFlags.Related),
        // Permit port 18447 forward ONLY for DNAT-translated connections (`ct status dnat`).
        new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, Destination: new("198.51.100.2/32"), DestinationPort: 18447, Chain: FilterChainKind.Forward, InputInterface: "r_cli", OutputInterface: "r_srv", ConnectionStates: ConnectionStateFlags.New | ConnectionStateFlags.Established, MatchOriginalDestinationDnat: true),
        new(IpFamily.IPv6, FilterProtocol.Tcp, FilterVerdict.Accept, Destination: new("2001:db8:2::2/128"), DestinationPort: 18447, Chain: FilterChainKind.Forward, InputInterface: "r_cli", OutputInterface: "r_srv", ConnectionStates: ConnectionStateFlags.New | ConnectionStateFlags.Established, MatchOriginalDestinationDnat: true),
    };

    return new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Drop, rules);
}

static NatPolicy BuildNatPolicy() => new(1,
    [
        new(IpFamily.IPv4, FilterProtocol.Tcp, new("192.0.2.1/32"), "198.51.100.2", 18446, 18447, "r_cli"),
        new(IpFamily.IPv6, FilterProtocol.Tcp, new("2001:db8:1::1/128"), "2001:db8:2::2", 18446, 18447, "r_cli"),
    ],
    [
        new(IpFamily.IPv4, new("192.0.2.0/24"), "198.51.100.1", new("198.51.100.0/24"), "r_srv"),
        new(IpFamily.IPv6, new("2001:db8:1::/64"), "2001:db8:2::1", new("2001:db8:2::/64"), "r_srv"),
    ]);

static FilterPolicy BuildRouterPolicy()
{
    var rules = new List<FilterRule?>
    {
        // Input: allow IPv6 Neighbor Discovery on both router interfaces under drop default.
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Input, InputInterface: "r_cli", IcmpType: FilterIcmpTypes.NdNeighborSolicit),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Input, InputInterface: "r_cli", IcmpType: FilterIcmpTypes.NdNeighborAdvert),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Input, InputInterface: "r_srv", IcmpType: FilterIcmpTypes.NdNeighborSolicit),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Input, InputInterface: "r_srv", IcmpType: FilterIcmpTypes.NdNeighborAdvert),
        // Output: allow kernel-originated IPv6 Neighbor Discovery on both interfaces under drop default.
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Output, OutputInterface: "r_cli", IcmpType: FilterIcmpTypes.NdNeighborSolicit),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Output, OutputInterface: "r_cli", IcmpType: FilterIcmpTypes.NdNeighborAdvert),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Output, OutputInterface: "r_srv", IcmpType: FilterIcmpTypes.NdNeighborSolicit),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Output, OutputInterface: "r_srv", IcmpType: FilterIcmpTypes.NdNeighborAdvert),
        // Forward: permit established/related reply packets from server back to client.
        new(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Accept, Chain: FilterChainKind.Forward, InputInterface: "r_srv", OutputInterface: "r_cli", ConnectionStates: ConnectionStateFlags.Established | ConnectionStateFlags.Related),
        new(IpFamily.IPv6, FilterProtocol.Any, FilterVerdict.Accept, Chain: FilterChainKind.Forward, InputInterface: "r_srv", OutputInterface: "r_cli", ConnectionStates: ConnectionStateFlags.Established | ConnectionStateFlags.Related),
        // Forward: permit client -> server TCP 18443 and ICMP/ICMPv6 echo-request (NEW) plus established packets.
        new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, new("192.0.2.0/24"), new("198.51.100.0/24"), 18443, FilterChainKind.Forward, "r_cli", "r_srv", ConnectionStateFlags.New | ConnectionStateFlags.Established),
        new(IpFamily.IPv6, FilterProtocol.Tcp, FilterVerdict.Accept, new("2001:db8:1::/64"), new("2001:db8:2::/64"), 18443, FilterChainKind.Forward, "r_cli", "r_srv", ConnectionStateFlags.New | ConnectionStateFlags.Established),
        new(IpFamily.IPv4, FilterProtocol.Icmp, FilterVerdict.Accept, Chain: FilterChainKind.Forward, InputInterface: "r_cli", OutputInterface: "r_srv", ConnectionStates: ConnectionStateFlags.New | ConnectionStateFlags.Established, IcmpType: FilterIcmpTypes.EchoRequest),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Forward, InputInterface: "r_cli", OutputInterface: "r_srv", ConnectionStates: ConnectionStateFlags.New | ConnectionStateFlags.Established, IcmpType: FilterIcmpTypes.EchoRequest),
        // Forward: per-source UDP 18445 rate limit (burst 2, 2/minute).
        new(IpFamily.IPv4, FilterProtocol.Udp, FilterVerdict.Accept, new("192.0.2.0/24"), new("198.51.100.0/24"), 18445, FilterChainKind.Forward, "r_cli", "r_srv", RateLimit: new(2, RateLimitTimeUnit.Minute, 2, 60)),
        new(IpFamily.IPv6, FilterProtocol.Udp, FilterVerdict.Accept, new("2001:db8:1::/64"), new("2001:db8:2::/64"), 18445, FilterChainKind.Forward, "r_cli", "r_srv", RateLimit: new(2, RateLimitTimeUnit.Minute, 2, 60)),
    };

    return new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Drop, rules);
}
