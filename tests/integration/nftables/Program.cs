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

throw new ArgumentException("Unsupported fixture mode.");

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
