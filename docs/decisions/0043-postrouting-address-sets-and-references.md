# ADR 0043: Complete postrouting address sets and pinned lists

## Decision

Support bounded source/destination address sets in ordered postrouting SNAT,
masquerade and return rules. Each matcher accepts exactly one scalar prefix,
anonymous prefix set or embedded immutable controller-list version. Sets use the
existing 2–64 distinct, same-family, disjoint/non-adjacent prefix contract; a
singleton controller list projects to a scalar. Reject conflicts, invalid families,
unknown input and invalid dormant rules before emitting any candidate. Never expand
one rule into multiple NAT rules or fetch the latest list at compile/apply time.

Retain complete source/destination sets through native echo/list reconstruction.
The reused filter parser must not accept address predicates and then discard them
from the NAT projection. Address-set observations use an explicit v3 fingerprint
binding all handles and canonical semantics. Existing scalar/port-only fingerprints
remain unchanged. Unknown native expressions and unsupported shapes remain denied.
Complete table ownership, checked atomic replacement and independently protected
receipts/watchdog rollback continue to gate privileged actions.

Extend strict JSON, defensive snapshots, saved reference usage and database
verification. Guided postrouting forms author literal CIDR lists, display pinned
contents read-only, and preserve pins through ordinary and legacy edits. Explicit
reference selection/removal changes only the selected matcher in a draft. Removing
a negated address reference clears its negation too; removing an explicit SNAT
source is denied because SNAT requires a source restriction. Review, immutable
revision save and confirmed apply remain separate. No SQL schema change is needed.

Acceptance requires invalid/unknown/conflicting input and forged-history denial,
immutable versions, native set round-trips and fingerprints, real dual-stack NAT
packet outcomes and complete receipt-bound apply/confirm/rollback/drift checks.
All fixtures use disposable namespaces and synthetic addresses.

This does not add native named sets/maps/dynamic objects, DNAT address/port lists,
or bridge address lists. Those remain separate M3 capabilities; source ingestion
is not semantic native import.

The existing bounded native observation size remains unchanged. This does not
claim arbitrary large-policy support; complete observation must succeed before
a new receipt can authorize confirmation or recovery.
