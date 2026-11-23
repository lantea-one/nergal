using Nergal.Core.Policy;

namespace Nergal.Testing;

/// <summary>Deterministic synthetic router policy shared by unit and real-kernel fixtures.</summary>
internal static class RouterPolicySamples
{
    internal static FilterPolicy Filter() => new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept,
    [
        new(IpFamily.IPv4, FilterProtocol.Udp, FilterVerdict.Reject, DestinationPort: 53,
            InputInterface: "lan0", NegateInputInterface: true, SourceMac: new("02:00:00:00:00:01"), NegateSourceMac: true),
        new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, Source: new("192.0.2.0/24"), DestinationPort: 9001,
            Chain: FilterChainKind.Forward, SourceMac: new("02:00:00:00:00:01")),
        new(IpFamily.IPv6, FilterProtocol.Tcp, FilterVerdict.Drop, Source: new("2001:db8:1::/64"), Chain: FilterChainKind.Forward,
            NegateSource: true, SourceMacs: [new("02:00:00:00:00:01"), new("02:00:00:00:00:03")]),
        new(IpFamily.IPv4, FilterProtocol.Udp, FilterVerdict.Accept, DestinationPort: 19001, Chain: FilterChainKind.Forward,
            RateLimit: new(5, RateLimitTimeUnit.Second, 2, KeyKind: RateLimitKeyKind.DestinationAddress)),
        new(IpFamily.IPv6, FilterProtocol.Udp, FilterVerdict.Accept, DestinationPort: 19001, Chain: FilterChainKind.Forward,
            RateLimit: new(5, RateLimitTimeUnit.Second, 2, KeyKind: RateLimitKeyKind.DestinationAddress)),
        new(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Drop, Destination: new("203.0.113.0/24"),
            Chain: FilterChainKind.Output, OutputInterface: "wan0", NegateDestination: true, NegateOutputInterface: true),
    ], new(FilterVerdict.Accept,
    [
        new(FilterVerdict.Accept, InputInterface: "lo"),
        new(FilterVerdict.Accept, Protocol: FilterProtocol.Udp, SourcePort: 68),
        new(FilterVerdict.Accept, Family: IpFamily.IPv6, Source: new("2001:db8:2::/64"), NegateSource: true),
        new(FilterVerdict.Drop, MatchFibUnreachable: true),
    ]), 1360);

    internal static BridgePolicy Bridge() => new(1, FilterVerdict.Accept,
    [new(BridgeEtherType.Any, FilterVerdict.Drop, BridgeName: "br0", DestinationMac: new("02:00:00:00:00:02"),
        Protocol: FilterProtocol.Tcp, DestinationPorts: [443, 8080, 8443], JumpTarget: "service_http")], -5,
    [new("service_http",
    [new(BridgeEtherType.Any, FilterVerdict.Drop, SourceMac: new("02:00:00:00:00:01"), Family: IpFamily.IPv4,
        Source: new("192.0.2.2/32"), Protocol: FilterProtocol.Tcp, DestinationPort: 8080, Return: true),
     new(BridgeEtherType.Any, FilterVerdict.Drop)])]);

    // Synthetic acceptance topology; the primary table is identical for both early-inet variants.
    internal static FirewallPolicyBundle AuxiliaryAcceptance(bool blocked = true) => new(1,
        new(2, FilterVerdict.Accept, FilterVerdict.Accept, FilterVerdict.Accept,
            [new(IpFamily.IPv4, FilterProtocol.Udp, FilterVerdict.Drop, DestinationPort: 19001),
             new(IpFamily.IPv6, FilterProtocol.Udp, FilterVerdict.Drop, DestinationPort: 19001)]),
        bridge: new(1, FilterVerdict.Accept,
            [new(BridgeEtherType.Any, FilterVerdict.Drop, InputInterface: "lan0", OutputInterface: "lan1", BridgeName: "br0",
                DestinationMac: new("02:00:00:00:00:02"), Protocol: FilterProtocol.Tcp, DestinationPorts: [18080, 18081], JumpTarget: "service"),
             new(BridgeEtherType.Any, FilterVerdict.Drop, BridgeName: "br0", DestinationMac: new("02:00:00:00:00:02"),
                NegateDestinationMac: true, Protocol: FilterProtocol.Tcp, DestinationPorts: [18080, 18081])], -5,
            [new("service",
                [new(BridgeEtherType.Any, FilterVerdict.Drop, SourceMac: new("02:00:00:00:00:01"), NegateSourceMac: true),
                 new(BridgeEtherType.Any, FilterVerdict.Drop, SourceMac: new("02:00:00:00:00:01"), Family: IpFamily.IPv4,
                    Source: new("192.0.2.2/32"), Protocol: FilterProtocol.Tcp, DestinationPort: 18080, Return: true),
                 new(BridgeEtherType.Any, FilterVerdict.Drop, SourceMac: new("02:00:00:00:00:01"), Family: IpFamily.IPv6,
                    Source: new("2001:db8:1::2/128"), Protocol: FilterProtocol.Tcp, DestinationPort: 18080, Return: true),
                 new(BridgeEtherType.Any, FilterVerdict.Drop)])]),
        auxiliaryFilter: new(-5, new(2, FilterVerdict.Accept, FilterVerdict.Accept, FilterVerdict.Accept,
            [new(IpFamily.IPv4, FilterProtocol.Udp, blocked ? FilterVerdict.Drop : FilterVerdict.Accept, DestinationPort: 19000),
             new(IpFamily.IPv6, FilterProtocol.Udp, blocked ? FilterVerdict.Drop : FilterVerdict.Accept, DestinationPort: 19000)])));

    internal static FilterPolicy PacketFilter() => new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept,
    [
        new(IpFamily.IPv4, FilterProtocol.Udp, FilterVerdict.Accept, DestinationPort: 19000),
        new(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Accept, Chain: FilterChainKind.Forward, ConnectionStates: ConnectionStateFlags.Established | ConnectionStateFlags.Related),
        new(IpFamily.IPv6, FilterProtocol.Any, FilterVerdict.Accept, Chain: FilterChainKind.Forward, ConnectionStates: ConnectionStateFlags.Established | ConnectionStateFlags.Related),
        new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, Source: new("192.0.2.2/32"), DestinationPort: 9001, Chain: FilterChainKind.Forward, SourceMac: new("02:00:00:00:00:01")),
        new(IpFamily.IPv6, FilterProtocol.Tcp, FilterVerdict.Accept, Source: new("2001:db8:1::2/128"), DestinationPort: 9001, Chain: FilterChainKind.Forward, SourceMac: new("02:00:00:00:00:01")),
        new(IpFamily.IPv4, FilterProtocol.Udp, FilterVerdict.Accept, DestinationPort: 19001, Chain: FilterChainKind.Forward, RateLimit: new(1, RateLimitTimeUnit.Minute, 1, KeyKind: RateLimitKeyKind.DestinationAddress)),
        new(IpFamily.IPv6, FilterProtocol.Udp, FilterVerdict.Accept, DestinationPort: 19001, Chain: FilterChainKind.Forward, RateLimit: new(1, RateLimitTimeUnit.Minute, 1, KeyKind: RateLimitKeyKind.DestinationAddress)),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept),
    ], new(FilterVerdict.Accept,
        [new(FilterVerdict.Accept, Family: IpFamily.IPv6, Source: new("fe80::/10")),
         new(FilterVerdict.Accept, Protocol: FilterProtocol.Udp, SourcePort: 68), new(FilterVerdict.Drop, MatchFibUnreachable: true)]), 1360);

    internal static NatPolicy PacketNat() => new(1, [],
    [
        new(IpFamily.IPv4, null, null, Destination: new("198.51.100.3/32"), Action: NatPostroutingAction.Return),
        new(IpFamily.IPv6, null, null, Destination: new("2001:db8:2::3/128"), Action: NatPostroutingAction.Return),
        new(IpFamily.IPv4, null, null, OutputInterface: "wan0", InputInterface: "lan0", Action: NatPostroutingAction.Masquerade, Protocol: FilterProtocol.Tcp, DestinationPort: 9001),
        new(IpFamily.IPv6, null, null, OutputInterface: "wan0", InputInterface: "lan0", Action: NatPostroutingAction.Masquerade, Protocol: FilterProtocol.Tcp, DestinationPort: 9001),
    ]);

    internal static NatPolicy Nat() => new(1,
    [new(IpFamily.IPv4, FilterProtocol.Udp, new("198.51.100.10/32"), "192.0.2.20", 53, 53, "wan0", new("192.0.2.0/24"), NegateSource: true)],
    [
        new(IpFamily.IPv4, new("192.0.2.0/24"), null, Destination: new("198.51.100.0/24"), Action: NatPostroutingAction.Return, NegateDestination: true),
        new(IpFamily.IPv4, null, null, OutputInterface: "wan0", Action: NatPostroutingAction.Masquerade,
            InputInterface: "lan0", Protocol: FilterProtocol.Tcp, DestinationPorts: [443, 9001]),
        new(IpFamily.IPv6, new("2001:db8:1::/64"), null, OutputInterface: "wan0", Action: NatPostroutingAction.Masquerade),
    ]);
    // Agent fixtures carry self-contained snapshots, never a controller database lookup.
    internal static FirewallPolicyBundle WithTransportReferences(FirewallPolicyBundle bundle)
    {
        PolicyObjectReference Reference(int? port, IReadOnlyList<int>? ports)
        {
            var entries = (ports ?? [port!.Value]).Order().Select(p => p.ToString(System.Globalization.CultureInfo.InvariantCulture)).ToArray();
            var content = new Nergal.Core.Controller.ReusableObjectContent("ports_" + string.Join("_", entries), Nergal.Core.Controller.ReusableObjectKind.Port, "Synthetic immutable port list", entries);
            return new(Guid.ParseExact(content.Digest[..32], "N"), 1, content);
        }
        IEnumerable<BridgeFilterRule?> BridgeRules(IReadOnlyList<BridgeFilterRule?> rules) => rules.Select(r =>
            r is null || (r.DestinationPort is null && r.DestinationPorts is null) ? r : r with
            { DestinationPortObject = Reference(r.DestinationPort, r.DestinationPorts), DestinationPort = null, DestinationPorts = null });
        var nat = bundle.Nat is not { } n ? null : new NatPolicy(n.SchemaVersion, n.DnatRules, n.SnatRules.Select(r =>
            r is null || (r.DestinationPort is null && r.DestinationPorts is null) ? r : r with
            { DestinationPortObject = Reference(r.DestinationPort, r.DestinationPorts), DestinationPort = null, DestinationPorts = null }));
        var bridge = bundle.Bridge is not { } b ? null : new BridgePolicy(b.SchemaVersion, b.DefaultVerdict, BridgeRules(b.Rules), b.Priority,
            b.SubChains.Select(c => new BridgeSubChain(c.Name, BridgeRules(c.Rules))));
        return new(bundle.SchemaVersion, bundle.Filter, nat, bridge, bundle.AuxiliaryFilter);
    }
}
