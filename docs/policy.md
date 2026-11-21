# Filter policy contract (schema 1 and schema 2)

The implemented slice consists of immutable POCOs in `Nergal.Core.Policy` and
`NftFilterCompiler.Compile` in the separate `Nergal.Nftables` library. Neither
performs host operations. The web host does not reference the compiler.

- **Schema version 1**: single `input` chain, stateless matching (`Family`, `Protocol`,
  `Source`, `Destination`, `DestinationPort`) and `Accept`/`Drop` verdicts.
- **Schema version 2** ([ADR 0024](decisions/0024-stateful-forwarding-and-icmpv6-policy.md),
  [ADR 0025](decisions/0025-native-per-source-rate-limiting.md)):
  three base chains (`input`, `forward`, `output`) with explicit per-chain defaults
  (`InputDefaultVerdict`, `ForwardDefaultVerdict`, `OutputDefaultVerdict`), optional
  validated interface names (`InputInterface`, `OutputInterface`), conntrack state masks
  (`ConnectionStateFlags`: `New`, `Established`, `Related`, `Invalid`), canonical
  ICMP/ICMPv6 type matchers (`FilterIcmpTypes`, including IPv6 Neighbor Discovery), and
  optional per-source dynamic token-bucket meters (`PerSourceRateLimit` backed by named
  `nergal_rl_<idx>` dynamic timeout sets), and `ct status dnat` original-tuple
  matching (`MatchOriginalDestinationDnat`).
- **Dual-stack NAT (`NatPolicy` / `NftNatCompiler`, [ADR 0026](decisions/0026-dual-stack-nat-and-original-tuple-matching.md))**:
  prerouting destination NAT (`DnatRule`) and explicit postrouting source NAT
  (`SnatRule`, without implicit masquerade) targeting `inet nergal_nat`.
- **Bridge filtering & multi-table bundles (`BridgePolicy` / `FirewallPolicyBundle`, [ADR 0027](decisions/0027-bridge-filtering-and-atomic-multitable-transactions.md))**:
  L2 forward filtering in `bridge nergal_bridge` (`hook forward priority -200`) across
  `arp`, `ip`, and `ip6` Ethernet types, coordinated atomically with `inet nergal_filter`
  and `inet nergal_nat` via `NftPolicyBundleCompiler` without ever flushing foreign tables.
  Schema-2 rules emit grouped by `(input, forward, output)` chain while preserving relative rule order within each chain.
  Schema 1 policies reject schema-2 fields.
All unmatched packets receive the chain's explicit default. There are no implicit permits.

```csharp
var policy = new FilterPolicy(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Drop,
[
    new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept,
        Chain: FilterChainKind.Input, InputInterface: "eth0",
        IcmpType: FilterIcmpTypes.NdNeighborSolicit),
    new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept,
        Source: new NetworkPrefix("192.0.2.0/24"), DestinationPort: 443,
        Chain: FilterChainKind.Forward, InputInterface: "eth0", OutputInterface: "eth1",
        ConnectionStates: ConnectionStateFlags.New | ConnectionStateFlags.Established),
]);
var result = NftFilterCompiler.Compile(policy);
// Inspect result.Diagnostics. Candidate is null on any validation error.
// Candidate text is not permission to execute it on a host.
```

Supported protocols are any, TCP, UDP, ICMP (IPv4 only) and ICMPv6 (IPv6 only).
Ports are 1–65535 and require TCP or UDP. Networks use numeric CIDR syntax,
zero host bits and the rule's family. Scoped and IPv4-mapped IPv6 are rejected.
Interface names allow 1–15 ASCII characters (`[A-Za-z0-9._-]`, leading alphanumeric)
and must match chain direction (`InputInterface` on `Input`/`Forward`,
`OutputInterface` on `Forward`/`Output`). `NetworkPrefix` throws `ArgumentException`
for invalid text; policy collection and compiler null arguments throw
`ArgumentNullException`. Valid values become canonical strings; no caller-provided
native fragments enter output.

Policy construction snapshots the rules, including invalid/null entries. Compiler
validation returns all applicable diagnostics in schema/default/rule/field order.
Paths use zero-based indexes, such as `rules[0].destinationPort`; diagnostics
contain stable identifiers rather than caller-supplied policy data.

| Code | Meaning |
| --- | --- |
| `schema.unsupported` | Schema version is not 1 or 2. |
| `verdict.unknown` | Default or rule verdict is undefined. |
| `rule.required` | A rule entry is null. |
| `family.unknown` | Rule IP family is undefined. |
| `protocol.unknown` | Rule protocol is undefined. |
| `network.familyMismatch` | Source or destination network belongs to another family. |
| `protocol.familyMismatch` | ICMP protocol belongs to another IP family. |
| `port.outOfRange` | Destination port is outside 1–65535. |
| `port.requiresTransport` | A destination port was supplied without TCP or UDP. |
| `chain.requiresSchema2` | Schema 1 policy specified a non-input chain or non-drop forward/output default. |
| `chain.unknown` | Rule chain kind is undefined. |
| `interface.requiresSchema2` | Schema 1 rule specified an ingress or egress interface name. |
| `interface.invalid` | Interface name failed `IFNAMSIZ - 1` / ASCII character safety checks. |
| `interface.chainMismatch` | `InputInterface` used on `Output` or `OutputInterface` used on `Input`. |
| `connectionState.requiresSchema2` | Schema 1 rule specified connection-tracking state flags. |
| `connectionState.unknown` | Connection state mask contains undefined bits. |
| `icmpType.requiresSchema2` | Schema 1 rule specified an ICMP/ICMPv6 type matcher. |
| `icmpType.requiresIcmp` | ICMP type specified without ICMP or ICMPv6 protocol. |
| `icmpType.unsupported` | ICMP type is not in the family's canonical allowlist. |
| `rateLimit.requiresSchema2` | Schema 1 rule specified a per-source rate limit. |
| `rateLimit.unitUnknown` | Rate-limit time unit is undefined. |
| `rateLimit.rateOutOfRange` | Packets per window is outside `1..1000000`. |
| `rateLimit.burstOutOfRange` | Rate-limit burst is outside `1..10000`. |
| `rateLimit.timeoutOutOfRange` | Idle per-source timeout is outside `1..86400` seconds. |
| `ctStatus.requiresSchema2` | Schema 1 rule requested `ct status dnat` matching. |
| `nat.ruleRequired` | DNAT or SNAT rule entry is null. |
| `nat.protocolUnsupported` | DNAT rule protocol is not `Any`, `Tcp`, or `Udp`. |
| `nat.originalDestinationRequired` | DNAT rule missing original destination prefix. |
| `nat.sourceRequired` | SNAT rule missing source prefix. |
| `nat.translatedAddressInvalid` | NAT translated address is not a single un-scoped, non-CIDR IP address. |
| `nat.translatedFamilyMismatch` | NAT translated address belongs to another IP family. |
| `bridge.ruleRequired` | Bridge rule entry is null. |
| `etherType.unknown` | Bridge rule Ethernet type is undefined. |

Successful results contain a complete deterministic native batch, its SHA-256
`Digest` over exact UTF-8 bytes, and no diagnostics. Failed results contain no digest.
See the [confirmed-apply contract](confirmed-apply.md) for artifact binding.
The batch begins with `create table inet nergal_filter`, then adds a single input
base chain at priority 0 and its ordered rules. It uses invariant numeric formatting
and LF newlines. The compiler never returns partial output on validation failure.

A separate typed identity overload adds a canonical owner/resource-birth marker;
see [native resource receipts](native-resource-receipts.md) for its limited observation
contract and why the marker alone is not ownership proof.

The table name is reserved; it is not proof of existing-table ownership. An existing
table with that name causes the native batch to fail atomically, regardless of its
contents. No adoption, replacement, deletion or ruleset flush is emitted. Other
owners' base chains can still deny traffic accepted by this table.

This is an in-process API, not a JSON import schema. It has no raw-text extension
point. Unsupported features (NAT, output/forward filtering, connection tracking,
rate limits, interfaces, logging, sets and bridge rules) cannot be requested through
this contract. Future importers must reject unknown fields. Capability declarations
elsewhere in Core do not imply these features exist in this compiler.

The [decision record](decisions/0002-filter-compiler.md) explains why create-only
provisioning is the current boundary. Native validation, authorized execution,
independent rollback, confirmed apply and recovery remain future agent work.
