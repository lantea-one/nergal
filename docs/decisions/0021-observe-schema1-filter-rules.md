# ADR 0021 — Observe and reconstruct full schema-1 input-filter policies

- Status: accepted
- Date: November 21, 2026

## Decision

Extend `NftTableObservation.Parse` in `Nergal.Nftables` to recognize, fingerprint,
and reconstruct every rule expressible by schema 1 of `FilterPolicy` and
`NftFilterCompiler` (`IpFamily`, optional canonical `Source`/`Destination` CIDR
prefixes, `Protocol` `Any`/`Tcp`/`Udp`/`Icmp`/`IcmpV6`, optional `DestinationPort`
`1..65535`, and terminal `Accept`/`Drop` verdicts) in the `inet nergal_filter` `input`
chain.

Enforce exact canonical `nft` JSON expression order and implicit-dependency elision
rules: `meta nfproto` is required only when neither payload IP addresses (`ip`/`ip6`
`saddr`/`daddr`) nor family-specific layer-4 protocols (`icmp`/`ipv6-icmp`) are
present, and `meta l4proto` is required for `Tcp`/`Udp`/`Icmp`/`IcmpV6` except when
`tcp dport` or `udp dport` is present. Host `/32` and `/128` addresses must match as
canonical strings without `/`, while shorter prefixes must match canonical `prefix`
objects validated through `NetworkPrefix`. Any unmodeled expression, counter, flag,
comment, duplicate handle, non-canonical prefix, or out-of-order match fails closed.

Preserve empty-chain (`nergal-observation-v1`) and family-only (`nergal-observation-v2`)
`StateDigest` projections byte-for-byte so existing schema-2 receipts remain valid. For
rules carrying addresses, protocols, or ports, compute `nergal-observation-v3`
covering the marker, table/chain handles, chain semantics, and every rule's handle,
family, source/destination CIDR, protocol, destination port, and verdict in order.

## Remaining boundary

`NftTableObservation.ParseEnrollmentEcho` remains scoped to initial empty `accept`
baseline enrollment. Forward/output chains, stateful connection tracking, NAT, rate
limits, interfaces, and bridge tables remain outside schema 1.
