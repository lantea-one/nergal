# ADR 0046: Complete DNAT address sets and pinned lists

## Decision

Extend DNAT source and original-destination matching with bounded literal prefix
sets and embedded immutable IPv4/IPv6 controller-list versions. Use the shared
`sourcePrefixes`/`destinationPrefixes` and `sourceObject`/`destinationObject` fields;
DNAT destination fields always describe matching before translation. They never
replace the single explicit translated address or port. Each matcher has exactly
one scalar, set or reference, with singleton references projected to scalars.
Multiple prefixes use the existing 2–64 distinct, same-family, disjoint/non-adjacent
contract. Reject conflicts and invalid dormant rules before emitting a candidate.

Original-destination matching remains required. Removing its sole reference is
denied; replace it explicitly or remove the rule. Removing a source reference clears
that matcher and its negation. Retain every other matcher, original-port snapshot,
translation, rule order and enabled state. Negation applies to the complete address
matcher, without expanding it into several rules.

Strict JSON, defensive snapshots, SQL history/usage and guided forms preserve exact
immutable versions. Compilation and apply never fetch the latest library version.
Native observation retains every prefix in echo/list reconstruction and binds
DNAT address sets through complete v3 NAT fingerprints; older scalar/port-only
fingerprints stay unchanged. Unknown native expressions remain denied. Checked
atomic replacement, complete ownership and independent protected watchdog receipts
continue to gate privileged actions. No new agent command or SQL migration is added.

Acceptance requires domain/codec denial, caller-mutation protection, forged SQL
history rejection, guided edit retention, actual dual-stack set membership/misses
and negation, complete native fingerprints and receipt-bound apply/confirm/rollback
including same-handle DNAT address drift. All fixtures use synthetic addresses in
disposable namespaces. Native named objects and semantic import remain separate.
