# Product code-complete milestones

This is the remaining path to a general-purpose FOSS product, not a claim that
all nftables language features will be supported. The historical A–E/code-complete
release descriptions covered a narrower foundation. Product code-complete means
all declared v1 workflows are implemented, integrated, documented and verified,
with unsupported semantics rejected explicitly and release-blocking gaps closed.
No percentage or completion date is asserted without a measured estimate.

These milestones target native nftables on Linux exclusively. Other firewall
engines and Windows-native service deployments are outside scope; no adapter work
is required for code-complete. Independent topologies and all three agreed SQL
engines remain targets. See
[ADR 0051](https://git.lantea.one/lantea-one/nergal/src/branch/main/docs/decisions/0051-nftables-only-linux-product.md).

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
| M2 | Complete structured authoring | Complete | Guided forms for every supported filter/raw/MSS/MAC/meter/negation/NAT/auxiliary/bridge construct, accessible hints/errors, complete review, no required JSON editing. |
| M3 | Reusable-object coverage | Complete | Declared reference scopes, immutable history/impact visibility and native static IPv4/IPv6/port sets with complete receipts, packet and apply/rollback acceptance. Dynamic objects/maps remain outside this declared slice. |
| M4 | Semantic native import/export | Open | Account for every declaration/rule in the supported grammar, retain exact originals separately, persist mapping/gaps, handle includes explicitly, deterministic scoped revision export, independent round-trip/packet acceptance. |
| M5 | Everyday administration UX | Open | Clear first-use starting path and next action, task-based navigation and progressive disclosure, accessible light/dark/mobile UI, local Administrator/Auditor user management and profiles with last-administrator protection, audit and revocation, meaningful charts with observation provenance and missing-data states. |
| M6 | Database completion | Open; SQL migrations deferred | Stabilize logical schema, persist remaining managed settings/profiles/observations/mappings/history, distinguish desired/applied/observed state, then verify versioned migrations and backup/restore on SQLite, PostgreSQL and MariaDB. |
| M7 | Installation and operations | Open | Clean single/multi-host installation, guided enrollment around local trust bootstrap, optional OIDC, upgrades, key/certificate rotation, backup/restore, drift and interrupted-operation recovery. |
| M8 | Product acceptance and release | Open | Independent host/router/bridge/dual-stack acceptance plus initial private conversion targets, authorization/security/recovery regressions, dependency/license review, accurate docs/Pages/screenshots, reproducible packages and release-blocker closure. |

## Dependencies and support decisions

M1 is merged into main (PR #81). M2 now has guided forms for the supported
policy constructs, verified by unit/HTTPS/native packet checks and browser QA.
M2–M4 share policy/reference contracts; neither
forms nor lexical inspection establish semantic import equivalence. Native static
list references are implemented; maps, dynamic flags/timeouts and arbitrary source
object conversion remain outside that projection. Declare the supported v1
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
[testing](testing-and-conformance.md), relevant ADRs and the [product workflow](https://git.lantea.one/lantea-one/nergal/src/branch/main/docs/product-workflow.md).

M2 progress: primary filter MAC matching/negation, source/destination meter keys,
explicit reject, and complete postrouting SNAT/masquerade/return forms are
implemented. Raw/FIB/UDP source-port rules, MSS configuration, DNAT negation and
NAT reordering are also implemented. Auxiliary inet table priority/defaults and
complete ordered rule forms are implemented. Extended bridge matching, priority,
regular-chain creation, jump/return and ordering are also implemented.
Broader UX refinement, scaling and product-wide accessibility checks remain M5. See [guided router forms](guided-router-forms.md).

M3 is complete for the declared static IPv4/IPv6/port library and reference scopes.
New UI attachments share native definitions per table; existing revisions retain
literal projection. Complete generation-bound element collection, creation-handle
provenance, exact protected-artifact verification and full lookup/content receipts
cover primary/auxiliary inet, DNAT, postrouting and both bridge scopes. Checks include
low IPv6 echo omissions, real dual-stack/routed/bridge packets, dynamic-meter
coexistence, lookup/content/handle drift denial and Unix/mTLS/web confirmation and
independent rollback. See [native static lists](native-static-lists.md).

M4 remains open for semantic source conversion. Deterministic native and complete
intent exports from explicitly selected saved revisions are implemented, with
saved artifact verification and Administrator-only downloads. See [policy exports](policy-exports.md).
The source viewer/import workflow shares one lossless bounded tokenization and
review pipeline. Semantic parsing, explicit include mappings and persisted gap
plans remain open; lexical success grants no conversion authority.
Maps, concatenations, arbitrary native object types, standalone unused declarations
and native dynamic-list options are not claimed by M3. Their treatment must be
explicit in the supported import grammar and gap reports.

### M5 usability acceptance

The current UI overwhelms a first-time operator and does not explain where to
start. M5 must provide one clear starting path, an obvious next action and
plain-language setup/empty states. Use task-based navigation and reveal advanced
settings, native table/schema details and JSON only when requested. Routine
create/import/review/apply tasks must work without raw policy code; source viewing
and import must share one workflow and analysis/mapping logic. There is no
firewall-engine choice.

Verify first-use and everyday tasks with synthetic installations in light, dark,
keyboard and mobile workflows. Retain clear draft/saved/pending/applied/observed/
recovery states and expert detail without weakening authorization, change review
or confirmed apply. Charts need measured data or explicit missing-data states.
M7 retains installation/trust-bootstrap integration; the UI must guide that boundary
without exposing host privileges to the browser. These are planned acceptance
requirements, not a claim that the current screens are already simplified.
