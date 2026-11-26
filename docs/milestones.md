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
| M5 | Everyday administration UX | Complete for M5 acceptance | Clear first-use starting path and next action, task-based navigation and progressive disclosure, accessible light/dark/mobile UI, local Administrator/Auditor user management and profiles with last-administrator protection, audit and revocation; configurable OIDC/OAuth/LDAP profile defaults and local overrides, LDAP sign-in, email/TOTP MFA and per-provider bypass/assurance policy; meaningful charts with observation provenance and missing-data states, plus UI internationalization (i18n). |
| M6 | Database completion | Complete for the fresh-schema baseline | Fresh controller schema 6, durable settings and latest authenticated host observations, distinct desired/observed/applied state, and verified constraints and backup/restore on SQLite, PostgreSQL, MariaDB, MySQL and SQL Server. |
| M7 | Installation and operations | Complete for the current schemas | Native Linux packages and hardened controller container, independent QEMU controller and agent installs, optional OIDC, same-schema package upgrades, wrapping and mTLS certificate rotation, full installation restore, drift and interrupted-operation recovery. |
| M8 | Product acceptance and release | In progress | Independent host/router/bridge/dual-stack packet checks have passed. The five private snapshots have complete conversion plans and their candidates pass isolated kernel dry runs. Private packet equivalence and final release acceptance remain open. |

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

M6 inventory: the controller store already owns managed hosts, immutable desired
policy revisions, System settings, reusable objects, native source snapshots and
conversion plans, and attributed audit. Local accounts and personal/provider
profile mappings live in the separately owned identity store; federated provider
defaults/connections and their protected secrets follow that account-store trust
scope. The agent's protected receipts and pending rollback decisions remain in
its independent local journal. These stores have distinct owners and restore
procedures; a controller observation cannot substitute for agent receipt state.

Controller schema 6 is the M6 prerelease baseline. Native backup and restore
preserve versioned settings, audit and authenticated host observations on all
five engines. The restore fixture checks stale writes and verifies independent
writes after recovery. The pinned mutual TLS fixture verifies that an unavailable
host still displays its previous observation after a controller restart.
Release-forward migration verification begins with the first released schema.

M7 acceptance combines the native packages and controller container with a
[multi-host QEMU fixture](../tests/integration/installed-system/README.md).
Separate Debian guests verify the installed controller and agent, managed OIDC
and local fallback, package upgrades within the current schemas, server and
client certificate rotation, and restore to independent guest boots. The
controller retains its verified settings, reviewed policy and audit. The
restored agent reconciles its last confirmed policy and supplies real packet and
drift evidence. The [deployment guide](deployment.md) records the operator
procedures and the individual backup boundaries.

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
exports, blocked gaps and light/dark/mobile screenshots. Current controller stores
initialize offline at the current fresh schema. See the source guide and testing
evidence; this source/conversion persistence is part of the controller store.

Counters/logging/maps, arbitrary dynamic objects/control flow, unsupported table
families and unused static declarations remain explicit blocking gaps; M4 does not
claim arbitrary nft language support. Complete private-server migration acceptance
remains M8. M6 follows the M5 console and identity acceptance.

### M5 usability acceptance

The first [appliance console](appliance-console.md) slice adds persistent section
navigation, focused host management, a compact state-based overview, draft-preserving
firewall sections and keyboard/mobile controls. The Chromium checkpoint suite
exercises the first-use and everyday workflow gates below.

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
- Internationalize the UI using translatable resources for navigation, forms,
  validation and status messages. Define locale selection and fallback, verify
  locale-aware formatting while preserving UTC storage and browser-local time,
  and check representative workflows for text expansion and missing translations.
- Verify the first-use and everyday tasks with synthetic installations in light,
  dark, keyboard and mobile workflows. The operator must be able to identify where
  to start and the next step without reading raw policy code.

Retain the complete native detail for expert review. Simplifying the default view
must preserve explicit change review, authorization, ownership and confirmed-apply
safety. The installation acceptance exercises the operator's explicit trust
bootstrap and the controller's authenticated host registration across that boundary.

M5 identity scope now also includes direct LDAP sign-in and profile mapping,
configurable OIDC/OAuth profile defaults with local overrides, local email and
TOTP/authenticator MFA, administrator email-delivery screens, optional enrollment
and a requirement policy for Administrators/all/neither. Federated bypass must be
explicit per provider, optionally requiring a configured MFA assurance claim.
LDAP sign-in follows local MFA requirements. Signed OIDC profile mapping and
per-field local overrides and UI-managed live OIDC connection settings are
implemented and verified. The [LDAP verifier and protected connection store](decisions/0061-direct-ldap-trust-boundary.md)
establish the directory proof and trust boundaries. The
[shared local MFA flow](decisions/0062-local-mfa-completion.md) covers TOTP
enrollment and LDAP browser sign-in. LDAP defaults and personal overrides
persist independently. Email MFA with verified delivery addresses, enrollment
recovery under enforcement, and per-connection signed OIDC assurance complete
the shared MFA scope. [Generic OAuth](oauth-connection.md) supports a confidential
authorization-code provider with authenticated current-user JSON, independent
profile overrides and explicit MFA trust. [Overview](overview-host-observations.md)
charts current authenticated host status and distinguishes coverage gaps.
[Display languages](ui-localization.md) uses English source fallback and provisional
Spanish coverage for representative console workflows. The launch language set
and expansion to other views remain release work. Synthetic Chromium acceptance
covers first use, guided changes, import, apply review, restricted operations,
keyboard use, both themes and narrow mobile layout.

This project has not been released publicly. New schema work targets fresh
installations; do not add legacy account upgrade paths or compatibility shims.
SQLite controller schema 6 retains versioned System settings with stale-write
protection and transactional audit, and adds the durable latest host observation
contract described above. The controller [backup and restore
procedure](controller-sqlite-backup.md) is verified against committed WAL
data and a separate writable restore. PostgreSQL, MariaDB, MySQL, and SQL Server
have passed fresh controller initialization and independent, writable native
restores. See [controller server databases](controller-server-databases.md)
for engine versions and operator procedures.
