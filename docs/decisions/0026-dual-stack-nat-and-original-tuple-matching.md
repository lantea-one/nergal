# ADR 0026 — Dual-stack DNAT, explicit SNAT, and original connection tuple matching

- Status: accepted
- Date: November 21, 2026

## Decision

1. **Dual-stack NAT POCOs (`Nergal.Core.Policy`)**:
   Introduce `DnatRule`, `SnatRule`, and `NatPolicy` (`SchemaVersion = 1`) in
   `Nergal.Core.Policy`, alongside `FilterRule.MatchOriginalDestinationDnat` (`ct status dnat`
   in filter schema version 2). `NatPolicy.GetRequiredFeatures()` declares
   `FirewallFeature.ForeignTablePreservation`, `FirewallFeature.DestinationNat` when
   DNAT rules exist, and `FirewallFeature.ExplicitSourceNat` when SNAT rules exist.
   `FilterPolicy.GetRequiredFeatures()` declares `FirewallFeature.OriginalConnectionTuple`
   when `MatchOriginalDestinationDnat` is used.

2. **Explicit IPv4/IPv6 translation without implicit masquerade (`NftNatCompiler`)**:
   - `NftNatCompiler` targets the separate reserved table `inet nergal_nat` with explicit
     `prerouting` (`hook prerouting priority dstnat; policy accept;`) and `postrouting`
     (`hook postrouting priority srcnat; policy accept;`) chains.
   - `DnatRule` validates protocol (`Any`, `Tcp`, `Udp`), source/original-destination family
     consistency, optional ingress interface, optional TCP/UDP original and translated ports,
     and single-IP canonical `TranslatedAddress` matching the rule family (emitting
     `[ipv6]:port` when translated port is present on IPv6).
   - `SnatRule` validates source/destination family consistency, optional egress interface,
     and single-IP canonical `TranslatedAddress` without implicit masquerade.
   - `NftFilterCompiler` rejects `MatchOriginalDestinationDnat` in Schema 1 and emits
     `ct status dnat` in Schema 2 prior to `ct state`.

3. **Dedicated NAT observation (`NftNatTableObservation`) and filter observation extension**:
   - `NftTableObservation` parses `ct status dnat` in Schema 2 (`nergal-observation-v6`
     when present) and rejects invalid/out-of-order expressions.
   - `NftNatTableObservation` provides symmetric `Parse` and `ParseReplacementEcho` for
     `inet nergal_nat` (`nergal-nat-observation-v1` digest), reconstructing `NatPolicy`
     without tolerating unknown objects or fields.

## Remaining boundary

Bridge filtering (`bridge nergal_bridge`), coordinated multi-table atomic transactions
(`FirewallPolicyBundle`), authenticated remote/local control protocol, controller
persistence, and web console workflows remain for Phases 9–13.
