# Input-filter policy contract (schema 1)

The implemented slice consists of immutable POCOs in `Nergal.Core.Policy` and
`NftFilterCompiler.Compile` in the separate `Nergal.Nftables` library. Neither
performs host operations. The web host does not reference the compiler.

A policy specifies schema version 1, an explicit accept/drop input default and
ordered rules. Each rule chooses one IP family, a protocol, a terminal accept/drop
verdict, optional source/destination networks and an optional destination port.
Rules are evaluated in supplied order; they are never sorted or deduplicated.
All unmatched packets receive the explicit default. There are no implicit permits.

```csharp
var policy = new FilterPolicy(1, FilterVerdict.Drop,
[
    new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept,
        Source: new NetworkPrefix("192.0.2.0/24"), DestinationPort: 443),
    new(IpFamily.IPv6, FilterProtocol.Tcp, FilterVerdict.Accept,
        Source: new NetworkPrefix("2001:db8::/32"), DestinationPort: 443),
]);
var result = NftFilterCompiler.Compile(policy);
// Inspect result.Diagnostics. Candidate is null on any validation error.
// Candidate text is not permission to execute it on a host.
```

This example is synthetic and incomplete for a real host, especially IPv6 control
traffic. Supported protocols are any, TCP, UDP, ICMP (IPv4 only) and ICMPv6 (IPv6
only). Ports are 1–65535 and require TCP or UDP. Networks use numeric CIDR syntax,
zero host bits and the rule's family. Scoped and IPv4-mapped IPv6 are rejected.
`NetworkPrefix` throws `ArgumentException` for invalid text; policy collection and
compiler null arguments throw `ArgumentNullException`. Valid networks become
canonical strings; no caller-provided native fragments enter output.

Policy construction snapshots the rules, including invalid/null entries. Compiler
validation returns all applicable diagnostics in schema/default/rule/field order.
Paths use zero-based indexes, such as `rules[0].destinationPort`; diagnostics
contain stable identifiers rather than caller-supplied policy data.

| Code | Meaning |
| --- | --- |
| `schema.unsupported` | Schema version is not 1. |
| `verdict.unknown` | Default or rule verdict is undefined. |
| `rule.required` | A rule entry is null. |
| `family.unknown` | Rule IP family is undefined. |
| `protocol.unknown` | Rule protocol is undefined. |
| `network.familyMismatch` | Source or destination network belongs to another family. |
| `protocol.familyMismatch` | ICMP protocol belongs to another IP family. |
| `port.outOfRange` | Destination port is outside 1–65535. |
| `port.requiresTransport` | A destination port was supplied without TCP or UDP. |

Successful results contain a complete deterministic native batch and no diagnostics.
The batch begins with `create table inet nergal_filter`, then adds a single input
base chain at priority 0 and its ordered rules. It uses invariant numeric formatting
and LF newlines. The compiler never returns partial output on validation failure.

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
