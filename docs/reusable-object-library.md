# Typed sets and IP lists library

Open **Sets & IP lists** (`/manage/objects`) to create and maintain typed lists.
Library management and pinned primary filter-rule references are implemented;
native named-set compilation is not implemented. Saving a list changes database history only.
It does not create a policy revision, apply a firewall or change saved policies.

## Everyday workflow

1. Choose **New list**. Enter a unique lowercase name such as `trusted_clients`
   and select IPv4, IPv6 or transport ports. Names/types remain fixed after creation.
2. Add an optional description and 1–64 entries, one per line. Forms include
   accessible contextual hints; JSON or native syntax is not required.
3. Save the list. Numeric addresses become canonical `/32` or `/128` prefixes;
   CIDRs must have zero host bits. IPv6 spelling and port numbers are normalized.
   Entries are sorted, with overlapping prefixes retained without merging.
4. Search by name/description and select a list to view or edit. Every save appends
   an immutable version and attributed audit event in the same transaction.
5. Expand **Version history** to inspect an older snapshot. Historical views are
   read-only. They do not restore contents or change the latest version.

IPv4/IPv6 lists cannot mix address families. Hostnames, scoped/mapped addresses,
address/port ranges, duplicate canonical entries, dynamic flags and timeouts are
rejected. Transport ports are individual integers from 1 to 65535; TCP versus UDP
belongs to the referencing policy rule, not the list. Descriptions are plain text
up to 500 characters. Blank lines and surrounding entry whitespace in forms are
ignored; unsupported tokens are never passed through to nftables.

Administrators can create/edit; Auditors can inspect/search/history only. Anonymous
requests are denied. All writes require CSRF protection. Invalid values are retained
with actionable guidance. A stale edit returns HTTP 409 with the user's input,
without overwriting the newer version. Compare with the current version before
editing again. There is no force-save action. Names/types are immutable and no
object deletion/rename workflow is provided in this first slice.

## Persistence and support boundary

The controller database is canonical. Object identity, type, contents, digest,
version, actor and UTC time persist across restarts. Browser times are local with
an explicit timezone indication. Immutable SQL protections cover identities and
history, and selected contents are verified against canonical serialization and
SHA-256. Lists are limited to 128 objects and 64 immutable versions per object.
Capacity failures leave no partial object or audit event.

New stores use controller schema 3. Existing schema-1/2 controllers must stop their
writer, take a verified SQLite backup, then run the explicit offline
`nergal-admin controller upgrade ABSOLUTE_CONTROLLER_DIRECTORY` before restarting.
The upgrade preserves source snapshots, policy revisions, hosts, settings and audit;
unknown versions, colliding tables and forged protections are rejected. The web
process does not migrate. See [source-library upgrade procedure](native-source-library.md#existing-controller-databases).
Additional SQL backends and their migrations remain deferred.

Pinned references retain identity/version and resolved contents in saved policy
JSON. Library detail shows saved revision references without inferring live host
usage. A list edit never silently changes a saved policy. Native named-set
observation and packet/rollback conformance remain a separate capability.
See [ADR 0039](decisions/0039-versioned-typed-object-library.md).

## Pinned filter-rule references

Policies can now attach the current displayed list version to a primary inet
filter rule's source address, destination address or destination ports. Open
**Policies → Reusable list references**, select a rule, matcher and version, then
choose **Attach selected version to draft**. This explicitly replaces that
matcher's literals or previous reference. Check the rule summary and native diff,
save a policy revision, then use the existing confirmed-apply workflow.

Canonical policy JSON retains the object's identity, version, name, type, contents
and content digest. Preview/save verifies the snapshot against immutable database
history. Compiling or applying a saved revision never looks up "latest". An older
pinned version remains valid after a library edit; reselect the newer version
explicitly in a draft to change policy. Normal rule editing and reordering retain
references. Literal fields for pinned matchers are read-only in the rule form.
**Remove reference from draft** clears that matcher and its negation, which may
broaden the rule; inspect the change before saving/applying. It does not retain a
hidden copy of the old values.

The library detail page shows every matching saved valid policy revision and
matcher path, including older list versions. This is reference/impact visibility,
not an assertion of active use on a host. A list edit does not update those
revisions automatically. Reference-only metadata changes are visible in the
reference summary even when native text is unchanged.

This is controller reuse, not native named nftables sets. Compilation projects the
embedded snapshot onto the existing scalar/anonymous-set matcher contract. No
identity/version is discarded from saved intent. Singletons become scalar matches;
multiple addresses must satisfy the existing disjoint/non-adjacent prefix bounds.
Overlapping or adjacent entries may be stored in the library but are rejected when
attached to a rule if native observation cannot round-trip them. Family/protocol
mismatches, conflicting literals, unknown flags and missing/forged references fail
explicitly. NAT and bridge references, native named sets/maps, dynamic lists and
semantic native import remain unsupported. Auxiliary inet references are represented
by the shared codec, but the structured selector currently edits primary filter
rules only. Use updated controller and agent builds; older codecs reject the new
fields rather than silently accepting weaker policy.

No database schema change is needed beyond schema 3. See
[ADR 0040](decisions/0040-pinned-controller-policy-references.md).
