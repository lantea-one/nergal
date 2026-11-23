# Product code-complete milestones

This is the remaining path to a general-purpose FOSS product, not a claim that
all nftables language features will be supported. The historical A–E/code-complete
release descriptions covered a narrower foundation. Product code-complete means
all declared v1 workflows are implemented, integrated, documented and verified,
with unsupported semantics rejected explicitly and release-blocking gaps closed.
No percentage or completion date is asserted without a measured estimate.

## Verified foundation

Native typed filter/NAT/bridge/early-inet compilation; complete native ownership
receipts; atomic confirmed apply and independent local timed rollback; Unix peer
identity and pinned mTLS; local sessions/optional OIDC/RBAC; immutable native source
ingestion/original downloads; versioned typed lists with pinned primary inet filter
references; UTC storage/browser-local times; local code editors; isolated packet
and mapped-identity verification are implemented in their documented slices.
The initial private deployment is an acceptance environment, not the product scope.

## Remaining milestones, in working order

| ID | Milestone | Status | Completion gate |
| --- | --- | --- | --- |
| M1 | Rule lifecycle | Complete | Inline enable/disable for every supported rule, retained contents/order/references, intent review and confirmed apply, packet/rollback acceptance. |
| M2 | Complete structured authoring | In progress | Guided forms for every supported filter/raw/MSS/MAC/meter/negation/NAT/auxiliary/bridge construct, accessible hints/errors, complete review, no required JSON editing. |
| M3 | Reusable-object coverage | Open | Finish declared reference scopes and native object semantics, explicit scope/type validation, immutable versions and impact visibility; no claims of unsupported dynamic sets/maps. |
| M4 | Semantic native import/export | Open | Account for every declaration/rule in the supported grammar, retain exact originals separately, persist mapping/gaps, handle includes explicitly, deterministic scoped revision export, independent round-trip/packet acceptance. |
| M5 | Everyday administration UX | Open | Navigation/setup workflows, accessible light/dark/mobile UI, local Administrator/Auditor user management and profiles with last-administrator protection, audit and revocation, meaningful charts with observation provenance and missing-data states. |
| M6 | Database completion | Open; SQL migrations deferred | Stabilize logical schema, persist remaining managed settings/profiles/observations/mappings/history, distinguish desired/applied/observed state, then verify versioned migrations and backup/restore on SQLite, PostgreSQL and MariaDB. |
| M7 | Installation and operations | Open | Clean single/multi-host installation, guided enrollment around local trust bootstrap, optional OIDC, upgrades, key/certificate rotation, backup/restore, drift and interrupted-operation recovery. |
| M8 | Product acceptance and release | Open | Independent host/router/bridge/dual-stack acceptance plus initial private conversion targets, authorization/security/recovery regressions, dependency/license review, accurate docs/Pages/screenshots, reproducible packages and release-blocker closure. |

## Dependencies and support decisions

M1 is merged into main (PR #81) after local and CI verification. M2 is in
progress. M2–M4 share policy/reference contracts; neither
forms nor lexical inspection establish semantic import equivalence. Native named
sets/maps, dynamic flags/timeouts and NAT/bridge object references remain separate
from the existing static controller-reference projection. Declare the supported v1
grammar and reject everything outside it, rather than silently approximating rules.

M5 charts depend on measured observations and their provenance, not configuration
counts masquerading as traffic. Profiles require audit, role separation, revocation
and last-administrator protection for account-management operations. Basic operation
must not require any particular identity provider or network layout.

M6 follows logical schema stabilization. SQLite is implemented; PostgreSQL and
MariaDB are settings intent, not existing adapters. All three are v1 code-complete targets. Additional SQL engines become
supported only after actual engine migrations, constraints, transactional audit,
upgrade failures, backups and recovery are verified. Generated files remain derived
artifacts. Independently protected agent receipts and rollback decisions retain
their trust boundary.

M7/M8 are product-wide integration gates, not a rewrite of already verified slices.
No production apply, deployment or account change follows from passing tests.
Update this table when a completion gate is actually satisfied, with evidence in
[testing](testing-and-conformance.md), the implementation guides and [migration/authoring status](router-migration-and-sandbox.md).

M2 progress: primary filter MAC matching/negation, source/destination meter keys,
explicit reject, and complete postrouting SNAT/masquerade/return forms are
implemented. Raw/MSS, DNAT negation, auxiliary and extended bridge/sub-chain forms
remain before M2 can close. See [guided router forms](guided-router-forms.md).
