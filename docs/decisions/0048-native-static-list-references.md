# ADR 0048: Native static list references

- Status: accepted; static-list, packet, receipt, UI and mapped-identity acceptance implemented
- Date: 2026-11-24

## Decision

Add an explicit native-set projection flag to immutable policy object references.
Existing references default to the previous literal projection, preserving saved
revision artifacts. Native projection emits one constant named set per object
identity/version/type within each owned table. Names are generated from validated
identity, version and type, never caller-supplied native syntax. New UI attachments
will use native projection only after complete acceptance. Ordinary edits retain
that choice; immutable database versions remain authoritative.

Support the existing static IPv4/IPv6 prefix and transport-port list contracts,
including singleton lists, every existing reference scope, complete-set negation,
dormant validation and shared references. Detect conflicting snapshots for the
same generated name. Keep translated NAT targets explicit. Dynamic meters remain
separate objects; arbitrary native types, maps, timeouts, concatenations, unused
standalone declarations and semantic import are outside this slice.

Complete observation expands recognized static lookups only for validation by the
existing strict rule parsers, then restores typed native references. Fingerprints
add every static set's handle, type, flags, complete canonical contents and each
rule-handle/matcher/name binding. Never authorize from expanded literals alone.
Native observation reconstructs enforcement references, not controller descriptions
or database authority; protected revision intent remains independent.

Terse table listing omits static elements. Collect bounded individual set listings
only for recognized generated names in fixed owned tables. Verify definition/handle
agreement before combining contents. Bind the complete collection to one kernel
transaction generation under ADR 0047. No arbitrary native command or write API is
added; atomic ownership checks and independently protected timed rollback remain.
Unknown or partial objects, missing elements, malformed names, conflicting types,
unused sets and unknown lookups fail closed. Preserve fingerprints for tables
without native static references. No SQL schema migration is required. New native projections use a conservative
creation-echo budget inside the existing 64 KiB observation limit, including the
combined bundle; reject oversized candidates before mutation. Keep legacy literal
artifacts unchanged. Complete collection has a ten-second overall deadline.
Upgrade controller and agent together; older codecs reject the new reference flag.

Acceptance requires strict domain/codec/compiler denial, shared-definition and
reference retention, complete native echo/list reconstruction, same-value lookup
rebinding and content/handle drift detection, real dual-stack/bridge/NAT packets,
and receipt-bound apply/confirm/independent rollback. All native fixtures use
synthetic data and disposable namespaces. Documentation must not claim support
before those checks pass.

## Creation echo omissions

The tested nft userspace omits some IPv6 interval elements (including `::1` and
`::/64`) from creation echo while complete listings contain them. To verify those
sets, retain every original creation definition/handle and lookup. Collect complete
owned listings under one kernel generation, reconstruct their canonical artifact,
and require exact equality with the independently protected expected artifact.
Require every echoed static definition to match the listing's definition and handle;
all elements actually emitted in echo must be distinct members of the complete set.
Complete only the element records from those verified listings, then run the strict
creation parser and the existing full echo/list receipt comparison. Missing creation
handles or definitions, mismatching values, lookups or artifacts remain denied.

Apply, rollback and new-boot recreation all use this evidence path. The protected
journal independently repeats exact candidate/baseline artifact verification before
binding receipts. Creation handles establish provenance; the generation-bound full
listing and exact protected artifact establish contents. No element is inferred
from policy intent, and unverified listings cannot authorize receipt adoption.

## Acceptance results

Core and real-SQLite checks cover legacy/native projections, shared definitions,
strict malformed/unknown/partial denial, lookup and handle fingerprints, creation
provenance and exact protected-artifact verification, oversized candidates, retained
history and new-boot intent. Native fixtures round-trip all four tables and verify
actual dual-stack membership/misses/negation, bridge control flow, populated dynamic
meters and low IPv6 singleton/prefix packets. Five named agent scenarios and the
mapped-UID HTTPS/Unix/mTLS workflow pass confirmation, explicit/independent watchdog
rollback and drift preservation. Browser QA saves synthetic native pins, retains
read-only guided fields and ordinary edits, and verifies dark/light/mobile output.
The mobile digest badge now wraps within the viewport; Pages shares that stylesheet.
These results cover the declared static slice, not semantic source conversion or
arbitrary native object types. No production kernel state was modified.
