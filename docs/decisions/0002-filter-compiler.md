# ADR 0002: create-only native input-filter compiler

- Status: accepted
- Date: November 18, 2026

## Boundary and schema

Core schema version 1 describes an ordered, stateless host input filter with an
explicit accept/drop default. Each rule selects IPv4 or IPv6, an optional source
and destination CIDR, a protocol (any, TCP, UDP, ICMP or ICMPv6), an optional TCP/UDP
destination port (1–65535), and an accept/drop verdict. Networks must have zero
host bits; scoped and IPv4-mapped IPv6 addresses are rejected. Collections are
snapshotted. Unknown versions/enums, null rules, mismatched address/protocol
families and invalid ports produce stable code/path diagnostics and no candidate.
This is a typed in-process contract, not a wire format or a permissive JSON loader.
A future wire schema must reject unknown properties as well as unknown values.

No implicit permits are inserted, including loopback, established connections or
IPv6 control traffic. Rule order is significant. This intentionally small slice
cannot express forwarding/output, NAT, connection state, rate limits, interfaces,
sets, logging, reject, bridge rules or raw nft fragments. Such features require
new typed contracts, validation and conformance tests; they must never be ignored
or approximated. This slice is not a usable production baseline policy.

## Compilation and ownership

A separate unprivileged Nergal.Nftables library emits deterministic UTF-8-compatible
nft text with invariant numeric formatting and LF newlines. Only validated enums,
numbers and canonical numeric CIDRs enter the grammar. It performs no process,
network, filesystem or kernel operations and is not connected to the web host.

The sole target is `inet nergal_filter`, containing one input base chain at priority
0. A candidate starts with `create table`, never add/flush/delete. An existing
same-named table causes the entire transaction to fail, preserving both that table
and all foreign tables. The fixed name is a reservation, not proof of ownership.
Create-only provisioning is intentional: replacement/reconciliation requires a
future agent with durable ownership evidence and an independently timed local
rollback/confirmation design. No privileged apply API is added here.

A future agent must validate the complete candidate with native nftables, authorize
its scope, and apply one atomic batch. Successful compilation is not kernel
validation; a successful check is not proof of packet behavior. Accept verdicts
also remain subject to other base chains owned by other components.

## Verification

Unit tests exercise diagnostics, mutation boundaries, ordering and deterministic
output. The opt-in fixture generates a real candidate and uses disposable user
and network namespaces for nft check/apply and IPv4/IPv6 packet tests. It verifies
foreign-table preservation, collision rejection and all-or-nothing invalid-batch
failure. It never falls back to the host namespace. NAT and rollback are unimplemented
and untested; this fixture does not establish their correctness.

## Sources

Native grammar, create-vs-add semantics, inet family and check mode follow the
[upstream nft manual](https://netfilter.org/projects/nftables/manpage.html).
