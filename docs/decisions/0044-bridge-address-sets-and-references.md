# ADR 0044: Complete bridge address sets and pinned lists

## Decision

Extend bridge forwarding and regular-chain rules with bounded source/destination
prefix sets and embedded immutable controller address-list versions. An address
matcher requires an explicit IP family and exactly one scalar, literal set or
same-family reference. Apply the existing 2–64 distinct, disjoint/non-adjacent
prefix contract; project singleton references to scalars. Reject unknown input,
conflicts, missing/mismatched families and invalid dormant rules before emitting
any candidate. Preserve MAC restrictions, EtherType compatibility, bridge master,
ports, priority, jump/return graph, rule order and enabled state.

Native observation must retain every address-set element and recompile the complete
bridge graph. Address-set policies use a v3 fingerprint binding handles and complete
canonical semantics; old scalar/port-only fingerprints remain unchanged. Unknown
objects, malformed sets and unsupported expressions remain denied. Complete owned
bundle receipts, checked atomic replacement and independent local timed rollback
continue to authorize privileged operations; no new host command is exposed.

Strict JSON retains both literal sets and immutable reference identity/version/content.
Database validation/usage covers forwarding and every regular chain. Guided forms
show pinned contents read-only and preserve them through ordinary edits. Explicit
reference removal clears only the selected address restriction. History selection,
draft review, immutable revision save and confirmed apply remain separate. No SQL
schema migration or compile/apply-time lookup of the latest library is introduced.

Acceptance requires defensive/strict domain tests, native complete observations,
forged-history and role/CSRF denial, actual dual-stack MAC-plus-IP/set packet checks,
and receipt-bound confirmation, restart, rollback and native set-drift preservation.
All fixtures are disposable namespaces with synthetic addresses.

This does not add address negation to bridge IP matchers, native named sets/maps,
dynamic objects or DNAT list references. Unsupported import semantics stay explicit;
original-source ingestion is not semantic native conversion.

Native nft may reorder adjacent Ethernet source/destination comparisons by their
wire offsets. Observation accepts either order within the MAC stage, each field
exactly once, before EtherType/IP/transport matching. Duplicate MAC predicates and
other unsupported orderings remain denied; canonical compilation retains both
constraints. This is exercised in the distinct-UID container's actual native echo
and listing, as well as deterministic native-shape regression checks.
