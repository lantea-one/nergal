# ADR 0045: DNAT original-port sets and pinned lists

## Decision

Extend DNAT's original destination-port matcher with bounded literal port sets and
embedded immutable controller Port-list versions. Each rule has exactly one scalar,
set or reference; singleton references project to scalars. Multiple ports are
2–64 distinct integers in 1–65535 and require TCP or UDP. Preserve address/family,
negation, ingress, translation, rule order and disabled state. Every original port
maps to the same explicit target address and optional translated port; no implicit
range mapping, rule expansion or translation-port list is introduced.

Strict JSON, defensive policy snapshots, saved usage and SQL history verification
cover the new fields. Compilation never fetches the latest library. Guided forms
show pins read-only, ordinary edits retain them, and explicit removal clears only
the original-port restriction. Draft review, immutable save and confirmed apply
remain separate; removing a port restriction can broaden traffic.

Native echo/list observation must retain all original-port elements. New DNAT port
sets use the complete v3 NAT fingerprint, binding canonical semantics and handles;
existing scalar/port-only fingerprints stay unchanged. Unknown/malformed native
shapes remain denied. Complete ownership, atomic checked candidates and independent
local timed rollback still gate every privileged action. No new agent command or
SQL schema migration is needed.

Acceptance includes type/protocol/conflict and dormant-rule denial, defensive
snapshots, forged versions, strict JSON, native complete round-trips/set drift,
real dual-stack DNAT packets and receipt-bound apply/confirm/watchdog/rollback.
Fixtures use synthetic addresses and disposable namespaces only. DNAT address
lists, native named objects and semantic source import remain separate work.
