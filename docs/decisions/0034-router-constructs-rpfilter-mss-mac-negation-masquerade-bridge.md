# 0034. Typed router constructs and explicit preview-only auxiliary scope

- Status: accepted contract; implementation and verification are staged
- Date: 2026-11-22

## Context

Gateway policy needs raw reverse-path filtering, source ports, MSS modification,
MAC+IP pinning, rejection, destination-keyed meters, negation, postrouting
masquerade/return, and independent early inet/bridge chains. Dropping any matcher
or flattening jump/return control flow can weaken access control. Native imports
also contain private topology and cannot be used as public test fixtures.

## Decision

Extend small typed POCOs and the strict canonical bundle codec. Native generation
uses validated interfaces, canonical prefixes/MACs, bounded ports/rates/MSS, and
allowlisted verdict/action tokens; native source text is never an execution API.
Snapshot nested caller collections. Retain old compiled output and old observation
fingerprints when new fields are absent. Extended filter observation uses v7 and
extended NAT observation v2, including every new matcher/action and object handle.

The primary inet filter supports ordered `rpFilter` raw prerouting rules and a
forward SYN MSS clamp. Source MAC restrictions remain conjunctive with IP matches.
`reject` emits only ICMPx admin-prohibited. Negation requires its matcher. Meters
explicitly select source or destination keys; source remains the default.
Postrouting preserves ordered explicit SNAT, masquerade, and return exemptions.

Independent early inet policy targets reserved `nergal_aux`, never an imported
foreign table. Bridge extensions support priority, bridge master, L2/L3/L4 matches,
and bounded acyclic local jump/return chains in `nergal_bridge`. These two extensions
are **compiler preview only**. Controller dispatch, agent prepare, and the atomic
replacement compiler reject them as `policy.previewOnlyScope`. Do not enable apply
until their complete ownership receipts, observation, independent timed rollback,
and packet conformance are implemented.

## Evidence and limits

The new disposable three-namespace fixture verifies dual-stack masquerade/return,
MAC+IP denial, captured MSS 1360, destination-meter isolation across sources and
destinations, IPv4 reverse-path denial, and UDP source-port bypass. Native filter/NAT
echo/list snapshots reconstruct the same candidates and state fingerprints.
Extended bridge/auxiliary syntax passes native check-only validation. Those checks
are not evidence of bridge jump/return packet behavior or auxiliary rollback.
The existing integration suite continues to cover its prior semantics separately.

All native recordings and packet fixtures use synthetic addresses and MACs.
Private source inspection retains exact exports without claiming automatic import
or full policy parity. See [the contract and status](../router-constructs.md).
