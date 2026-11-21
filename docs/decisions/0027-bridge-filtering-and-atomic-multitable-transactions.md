# ADR 0027 — Bridge filtering and atomic multi-table transactions

- Status: accepted
- Date: November 21, 2026

## Decision

1. **Typed bridge filtering and multi-table bundles (`Nergal.Core.Policy`)**:
   Introduce `BridgeEtherType` (`Any`, `IPv4`, `IPv6`, `Arp`), `BridgeFilterRule`,
   and `BridgePolicy` (`SchemaVersion = 1`) for L2 bridge forwarding rules, plus
   `FirewallPolicyBundle` (`Filter`, optional `Nat`, optional `Bridge`).
   `FirewallPolicyBundle.GetRequiredFeatures()` aggregates component requirements
   and adds `FirewallFeature.AtomicMultiTableCommit` whenever two or more tables are
   configured.

2. **Bridge compilation and observation (`NftBridgeCompiler`, `NftBridgeTableObservation`)**:
   - `NftBridgeCompiler` compiles `BridgePolicy` into create-only `bridge nergal_bridge`
     with base chain `forward { type filter hook forward priority -200; policy <accept|drop>; }`,
     emitting validated `iifname`/`oifname` matchers and `ether type <ip|ip6|arp>` matches.
   - `NftBridgeTableObservation` strictly parses `bridge nergal_bridge` JSON listings
     and replacement echoes (`nergal-bridge-observation-v1` digest) without tolerating
     unknown objects or expressions.

3. **Coordinated atomic multi-table compiler (`NftPolicyBundleCompiler`)**:
   - `NftPolicyBundleCompiler.Compile` validates all tables in `FirewallPolicyBundle`
     before emitting any native output, prefixing component diagnostics with `filter`,
     `nat`, or `bridge`. If any table fails validation, zero output is produced.
   - `NftPolicyBundleCompiler.CompileAtomicReplacement` emits targeted `delete table`
     statements strictly for previously owned reserved Nergal tables followed by
     complete create+chain+rule definitions for the replacement bundle in one atomic
     `nft` batch, leaving all foreign tables untouched and never issuing `flush ruleset`.

## Remaining boundary

Authenticated local/remote agent control protocol (`Nergal.RemoteTransport`), controller
persistence (`Nergal.ControllerState`), RBAC, and web management workflows belong to
Milestones C and D (Phases 10–14).
