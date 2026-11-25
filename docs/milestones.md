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
engines remain targets. See [ADR 0051](decisions/0051-nftables-only-linux-product.md).

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
| M4 | Semantic native import/export | Complete for the declared v1 grammar | Account for every declaration/rule in the supported grammar, retain exact originals separately, persist mapping/gaps, handle includes explicitly, deterministic scoped revision export, independent round-trip/packet acceptance. |
| M5 | Everyday administration UX | In progress | Clear first-use starting path and next action, task-based navigation and progressive disclosure, accessible light/dark/mobile UI, local Administrator/Auditor user management and profiles with last-administrator protection, audit and revocation; configurable OIDC/OAuth/LDAP profile defaults and local overrides, LDAP sign-in, email/TOTP MFA and per-provider bypass/assurance policy; meaningful charts with observation provenance and missing-data states. |
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
[testing](testing.md), relevant ADRs and the [product workflow](product-workflow.md).

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

M4 is complete for the [declared native conversion grammar](native-source-library.md).
The viewer/planner share the original lossless tree and contextual partition;
explicit table roles, captured lexical definitions and ordered uploaded includes
produce immutable source-bound mapping/gap plans. Any unsupported statement removes
the complete candidate. Separate reviewed commit atomically creates one revision
and pinned list history, with replay/change denial and transactional audit. Native
and complete intent exports retain their explicit saved scope; originals stay exact.

Acceptance includes independent native/imported dual-stack raw/FIB/DHCP, MAC+IP,
SYN MSS, destination meters, NAT exemption/negation packets; creation/update expiry
under continued traffic; imported auxiliary/bridge complete receipts, confirmation
and independent rollback, including named sets. Unit/real-SQLite/HTTPS tests cover
source positions, includes/cycles, denied input/roles, restart, concurrent replay and
failed-commit rollback. Browser checks cover ordered includes, separate review/commit,
exports, blocked gaps and light/dark/mobile screenshots. Controller schema 4 requires
an explicit offline upgrade. See the source guide and testing evidence.

Counters/logging/maps, arbitrary dynamic objects/control flow, unsupported table
families and unused static declarations remain explicit blocking gaps; M4 does not
claim arbitrary nft language support. Complete private-server migration acceptance
remains M8. M5 is next: simplify first use and everyday tasks, then local users/
profiles and observation-backed charts.

### M5 usability acceptance

The first [appliance console](appliance-console.md) slice adds persistent section
navigation, focused host management, a compact state-based overview, draft-preserving
firewall sections and keyboard/mobile controls. The wider first-use and everyday
workflow acceptance below remains required; this slice does not complete M5.

- Give a new installation one clear starting path and an obvious next action based
  on actual setup state. Explain missing prerequisites and empty states plainly.
- Organize navigation around tasks: connect a host, create or import a policy,
  review changes, apply/confirm, inspect health, manage people and settings.
- Keep source viewing and import in one workflow with shared diagnostics and
  mapping logic. Preserve exact originals and show actionable unsupported-content
  gaps where they occur.
- Reveal advanced settings, native tables, schema details, JSON and complete
  native diffs when requested. Routine work must be possible through guided forms
  and plain-language summaries. Do not present firewall-engine choices.
- Show draft, saved, pending confirmation, applied, observed and recovery states
  clearly. Use charts after there is meaningful observed data; explain missing data.
- Verify the first-use and everyday tasks with synthetic installations in light,
  dark, keyboard and mobile workflows. The operator must be able to identify where
  to start and the next step without reading raw policy code.

Retain the complete native detail for expert review. Simplifying the default view
must preserve explicit change review, authorization, ownership and confirmed-apply
safety. M7 still owns installation/trust-bootstrap integration; M5 must guide the
operator through that boundary without exposing host privileges to the browser.

M5 identity scope now also includes direct LDAP sign-in and profile mapping,
configurable OIDC/OAuth profile defaults with local overrides, local email and
TOTP/authenticator MFA, administrator email-delivery screens, optional enrollment
and a requirement policy for Administrators/all/neither. Federated bypass must be
explicit per provider, optionally requiring a configured MFA assurance claim.
LDAP sign-in follows local MFA requirements. Signed OIDC profile mapping and
per-field local overrides are implemented and verified; runtime provider setup,
generic OAuth/LDAP mapping and local MFA remain open.

This project has not been released publicly. New schema work targets fresh
installations; do not add legacy account upgrade paths or compatibility shims.
Preserve disposable development data separately. M6 still requires fresh-schema,
transactional constraints and backup/restore verification on all three engines.
