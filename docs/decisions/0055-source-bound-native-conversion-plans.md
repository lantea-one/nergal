# ADR 0055: Source-bound native conversion plans

Status: Accepted design; completion requires the implementation and acceptance below.

## Decision

Extend the existing viewer/import workflow with an exhaustive conversion planner.
Use the same lossless document, delimiter tree and contextual statement partition;
never execute imported commands or resolve a server filesystem/name/service. Every
source statement receives a source-bound mapping disposition or a blocking gap.
A supported prefix, balanced document or successful rule count is insufficient.
A plan with any gap contains no policy candidate. Unknown statements, flags,
options, expressions and repeated matchers that cannot be represented are denied.

Require explicit unique table-to-role mappings: primary inet filtering, inet NAT,
independent auxiliary inet filtering, and bridge filtering. Do not infer ownership
from source names/comments. Only selected new managed resources are candidates;
existing foreign tables are never adopted. A source-wide flush requires an explicit
recorded scope-restriction decision and is never executed. Other deletion/insertion
or live-state commands are blocking gaps. Imported identities remain metadata only.

Support the declared v1 compiler contract, not arbitrary nft language: filter/raw
prerouting/MSS, dual-stack address/MAC/interface/transport/conntrack/ICMP matching,
static named address/port sets, bounded explicit meters, NAT translation/exemptions,
auxiliary priorities and bridge subchain jump/return. Validate hooks, priorities,
defaults, rule order, family/protocol compatibility and complete consumption before
lowering. Unrepresentable counters, logging, maps, dynamic objects or arbitrary
control flow remain explicit blocking gaps; operators cannot approve dropping them.
No claim is made that every private acceptance file is convertible by this slice.
Private complete conversion is also an M8 acceptance target.

Resolve symbolic definitions in lexical scope/order, capturing values at definition
time. Includes require exact literal-path bindings to ordered immutable uploaded
source IDs (and digests), bounded expansion and cycle detection. No glob search,
ambient directory lookup or implicit missing-file skip is permitted. Explicit empty
bindings are allowed only for wildcard include patterns. Preserve all originals.

Persist immutable plans, input source/digest bindings, mappings/gaps, decisions,
canonical intent and candidate digest in the controller database with transactional
attributed audit. Review does not create a policy or reusable object. A separate
CSRF-protected Administrator action creates one linked immutable revision and any
new pinned reusable objects atomically, after recomputing/verifying the plan. Reject
replayed, changed or stale plans. Existing revision review and confirmed apply are
required after conversion; no import action talks to an agent.

Add an explicit offline SQLite schema upgrade preserving prior state/protections;
web startup must not silently migrate. Other SQL backends remain deferred to M6.
Store UTC, display browser-local times. Editable request data uses guided controls;
no new required raw JSON/code fields are introduced. The source viewer and planner
share diagnostics/provenance and keep advanced detail in disclosures.

## Completion and acceptance

M4 is complete only after the supported grammar is implemented, every declaration
and statement is accounted for, unsupported fixtures produce no candidate/revision,
include/definition handling is verified, immutable plan/audit/object/revision writes
are transactional and restart-safe, original and generated exports work through UI,
and independent round-trip and real dual-stack/NAT/bridge/raw/MSS/meter/rollback
packet checks pass in disposable namespaces. Existing compiler/application tests
remain required. Update docs/Pages with authentic synthetic light/dark/mobile
screenshots. Do not mark M4 complete from this design record alone.
