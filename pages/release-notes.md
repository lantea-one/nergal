# Release Notes

nergal uses Calendar Versioning (`YYYY.MM.DD` and `YYYY.MM.DD.N` for same-day releases) and targets `.NET 10` LTS.

## Unreleased native source structure

The combined source viewer/import analysis now builds a bounded delimiter tree
over the exact token document. Missing/mismatched delimiters and nesting beyond
64 groups produce value-free source positions without partial trees/inventories.
Schema-2 reports and viewer diagnostics share the same summary. Unknown input and
exact originals remain intact; semantic conversion is still blocked. See
[the source workflow](native-source-library.md).

## Unreleased native-only product scope

Native nftables on Linux is now the sole firewall target. Other firewall adapters
and Windows-native service deployments are outside scope. Existing pure contracts,
native capability validation, owned-table safety and rollback remain required.
This narrows firewall/platform scope; independent deployments and the three SQL
engine targets remain. See [architecture](architecture.md).

## Unreleased shared source analysis

Native source viewing/review and import now share one bounded, lossless analysis
pipeline with exact token spans and physical positions. It retains unknown input
and opaque values, handles continuations/CRLF/CR/LF, and rejects controls or capacity
exhaustion without a partial document. Conversion remains blocked until semantic
mapping is complete. See [the source workflow](native-source-library.md).

## Unreleased saved revision exports

Administrators can download deterministic native and complete intent files from a
selected saved database revision. Both downloads recompile and verify the saved
artifact digest; dormant rules and pinned reference metadata remain in intent.
Exports carry no host ownership or apply authority. See [policy exports](policy-exports.md).

## Unreleased native static list references

New UI attachments now share constant native IPv4/IPv6/port sets in each owned
table across all declared matcher scopes. Saved earlier references retain literal
projection. Complete generation-bound element collection, creation handles, exact
protected-artifact checks and definition/lookup receipts gate apply and rollback.
Low IPv6 echo omissions are verified through complete listings; missing provenance
or conflicting data is denied. A conservative echo budget rejects oversized new
projections before mutation. No SQL migration is added. Upgrade controller and
agent together. See [native static lists](native-static-lists.md).

M3 is complete for the declared static-list slice. Semantic source conversion and
persisted mappings/gaps and semantic round-trip acceptance remain M4; charts/profiles/local account UI remain M5.

## `2026.11.21.1` (Milestone E)

- **Multi-table agent confirmed apply & rollback**: `nergal-agent` and `Nergal.Web` now dispatch, verify, confirm, and roll back full `FirewallPolicyBundle` policies spanning `inet nergal_filter`, `inet nergal_nat`, and `bridge nergal_bridge` with auxiliary ownership checks and coordinated `--echo --handle --json` validation.
- **Inline address/port sets & IPv4 ICMPv4**: Added schema-2 `sourcePrefixes`, `destinationPrefixes`, and `destinationPorts` (with disjoint/non-adjacent `UInt128` interval validation) plus IPv4 ICMP `parameter-problem`.
- **Visual rule builder & Blazor summary**: Added `PolicyBundleSummary.razor` and CSRF-protected Administrator MVC rule-builder actions (`/manage/policies/rules/{add,move,remove}`).
- **Forgejo Pages portal**: Added this static Docsify + Mermaid documentation site deployed automatically from `pages/` on `main`.
- **Linux release packaging**: Added `nergal.sysusers`, `nergal.tmpfiles`, and `scripts/package-release.sh` producing verified `.deb`, `.tar.gz`, and `SHA256SUMS` artifacts.

## `2026.11.21` (Foundation release; historical A–D milestone)

- Completed Milestones A–D (Phases 1–14): native `nftables` dual-stack filter/NAT/bridge compilers, exclusive ownership & boot/namespace receipts, autonomous timed watchdog rollback, `SO_PEERCRED` Unix and pinned TLS 1.3 mTLS control protocols, local sessions + optional OIDC + RBAC, MVC/Blazor management UI, and end-to-end confirmed apply over HTTPS.

## Unreleased postrouting address lists

Guided postrouting forms now author source/destination CIDR sets and pin immutable
IPv4/IPv6 list versions. Ordinary/legacy edits retain pins; explicit removal cannot
erase the required source of explicit SNAT. Complete native address sets are retained
in v3 receipt fingerprints, with old scalar/port-only fingerprints unchanged. Native
packet and recovery checks cover set misses, negation and NAT-set drift denial.
See [postrouting lists](reusable-object-library.md#attach-an-immutable-version).

## Unreleased historical reference selection

Supported policy reference forms now **Browse selected list history** without
altering the draft. Select and explicitly attach a displayed immutable old version;
the table/chain, rule, matcher and previous selection remain visible after browsing.
Only one list history is loaded at a time. See [historical version selection](reusable-object-library.md#attach-an-immutable-version).

## Unreleased theme accessibility

The application now initializes the theme button to **Light mode** or **Dark mode**
with an explicit accessible action name, including after navigation. System-theme
changes update the label while following the system preference. This matches the
Pages control behavior and still works with browser storage disabled. Local
application script/style URLs now include content versions, including the policy
editor bundle, so updated assets receive new cache keys after an upgrade.

## Unreleased list comparison

The list library now compares any two stored versions, with added/removed entries,
description changes, local save times and saved-reference counts. Policy reference
summaries link to comparison with the current library version in a separate tab.
Administrators and Auditors can review changes without altering pins, revisions or
firewalls. See [list comparison](reusable-object-library.md#create-and-maintain-a-list).

## Unreleased router and settings work

See [Router Migration & Local Sandbox](router-migration-and-sandbox.md) for the
current support matrix, supported apply scope and recovery limits, saved-settings/runtime distinction,
private source inspection, container isolation, verification limits, and screenshots.
This local development work is not a published release.

## Source-bound migration review

Native source inspection includes a bounded lexical inventory, line references
and a private administrator-only report download. Conversion remains blocked:
review signals do not establish syntax validity, exhaustive coverage or semantic
equivalence. Named maps, tracking bypass and counters need explicit preservation
work. No private sources or topology are published in these notes.

## Database-backed native source library (unreleased)

Administrators can upload bounded UTF-8 native sources into immutable controller
schema-2 records, review one source, download its exact original bytes and obtain a
source-bound lexical report. Optional file-directory snapshots are staging only.
Imports and their audit records are atomic; no configuration is executed or
converted. Existing controllers require an explicit offline `controller upgrade`.
Additional SQL providers and semantic native conversion remain future work.
Saved revision exports are now available as described above. See [the source library guide](native-source-library.md).

## Local timestamp display (unreleased)

Dashboard/apply audit rows, audit/revision history and native source imports now
render stored UTC instants in the viewer's browser timezone and locale. The page
names that timezone and each timestamp retains its original UTC instant. DST uses
the offset applicable to the event. Explicit UTC remains the fallback without
JavaScript/Intl. Database and API timestamps remain UTC.

## Unreleased typed object library

[Sets & IP lists](reusable-object-library.md) now supports typed IPv4/IPv6/port
lists with accessible forms, search, immutable version history, UTC storage/local
display, transactional audit and stale-edit protection. Controller schema 3 has an
explicit offline upgrade preserving schema-1/2 state. Policy references, native
named sets and impact review remain a separate milestone; library saves do not
change policies or firewalls.

## Unreleased pinned policy references

Primary inet filter source/destination/port matchers can pin immutable library
versions through the UI. Canonical policy JSON preserves identity, contents and
digest; database saves reject forged/missing references. Library detail exposes
saved revision references without claiming active host use. Edits/reordering retain
references and library updates cannot change saved policy bytes. Static references
compile to existing matchers; native projection is now covered by [the static-set contract](native-static-lists.md). Disposable
IPv4/IPv6 packet and separate-UID HTTPS/Unix/mTLS watchdog conformance covers the
resolved reference path. See [Sets & IP lists](reusable-object-library.md).

Product-wide code-complete is tracked separately in [the milestone overview](milestones.md).

## Unreleased rule lifecycle

[Inline enabled-state controls](rule-enabled-state.md) cover primary/raw/auxiliary
filter, DNAT/postrouting, bridge/sub-chain rules and the configured MSS clamp.
Disabled intent retains settings/order/references and remains fully validated.
Native compilation omits disabled enforcement/meters; an intent diff preserves
review of dormant changes. Rule state follows revision save and confirmed apply,
with dual-stack packet/NAT exemption and mapped-identity watchdog acceptance.

## Guided router forms (M2 in progress)

Primary filter forms now expose explicit ICMP reject, MAC restrictions/negation,
IP/interface negation and source/destination meter keys. Complete postrouting
forms support SNAT, masquerade and return, optional ingress/egress, protocol/ports
and negation. Edits preserve dormant state and pinned references; full-width
panels keep hints reachable outside scrollable tables. All edits remain unsaved
until revision review/save, then confirmed apply. See [guided forms](guided-router-forms.md)
for remaining scope and synthetic light/dark/mobile screenshots.

Guided raw-chain forms now cover FIB reverse-path matching, UDP source ports,
source/interface negation, defaults and ordered exceptions. MSS configuration
preserves disabled state on resize and has explicit removal. DNAT negation and
whole-rule NAT reordering are available without editing JSON. Auxiliary and
extended bridge/sub-chain forms are also implemented; broader UX remains M5.

Auxiliary inet table priority/defaults and complete ordered filter-rule forms are
now available. They preserve dormant state and other policy sections and require
explicit empty-table removal. Extended bridge/sub-chain forms are now implemented.

Complete bridge forms expose priority, bridge-master/MAC/IP/transport matching,
local regular chains, explicit jump/return, ordering and per-rule enabled state.
Auditors can inspect read-only matching fields. Missing/cyclic targets and
referenced-chain removal remain denied. Structured authoring covers the current
supported policy constructs; reusable-object expansion, semantic native import/export
and broader UX/operations/database work remain separate product milestones.

M3 now exposes immutable list selectors for auxiliary inet rules alongside primary
filtering. Table scope is explicit, existing API submissions remain primary-only,
and saved usage paths include auxiliary references. Native static support now follows [the current contract](native-static-lists.md); semantic import remains open.

Postrouting NAT and bridge destination-port rules, including regular chains, can
now pin immutable Port-list versions through contextual UI selectors. Ordinary
edits retain pinned versions and all unrelated intent. JSON/database usage covers
all new scopes; type conflicts, invalid protocols and forged versions remain denied.
Native packet and agent receipt/rollback fixtures use referenced snapshots.
Native static support now follows [the current contract](native-static-lists.md).

Bridge source/destination CIDR sets and immutable address-list versions now work
in forwarding and regular chains. Guided forms preserve MAC restrictions, family,
jump/return behavior, enabled state and pinned history. Complete native address-set
receipts use v3 fingerprints; scalar/port-only receipts remain unchanged. Upgrade
controller and agent together. Native static support now follows [the current contract](native-static-lists.md).

DNAT original destination ports now support literal sets and immutable Port-list
versions. Every matched original port uses one explicit translated target. Guided
edits retain pinned history, negation and disabled state; native observation keeps
all ports in complete v3 fingerprints. Older scalar fingerprints stay unchanged.
Native static support now follows [the current contract](native-static-lists.md).

DNAT source/original-destination sets and immutable address-list versions now work
alongside original-port pins. Guided edits retain all restrictions, translation and
dormant state. Source removal clears its negation; sole-destination removal is
denied. Native observations retain complete sets in v3 fingerprints; older scalar/
port-only fingerprints remain unchanged. Native static support now follows [the current contract](native-static-lists.md).

Agent observations now require a stable kernel transaction generation across the
complete filter/NAT/bridge/auxiliary collection. Denied, malformed or changing
generation queries make collection unavailable. Isolated tests cover same-handle
set-element drift, actual dynamic-meter packets and capability denial. This guards
collection consistency; competing privileged writers remain unsupported and native
static references are now implemented; semantic import remains M4. No UI or screenshot changes accompany
this internal observation boundary.
