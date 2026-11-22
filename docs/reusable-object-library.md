# Typed sets and IP lists library

Open **Sets & IP lists** (`/manage/objects`) to create and maintain typed lists.
Library management is implemented; policy rule references and native named-set
compilation are not yet implemented. Saving a list changes database history only.
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
belongs to a future policy rule reference, not the list. Descriptions are plain text
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

Library objects currently have no policy references; the UI does not claim usage
counts or native set support. Future integration must pin object identity/version
and resolved content into immutable policy revisions, show affected references,
reject incompatible/dangling references and require review/confirmed apply. A list
edit must never silently change a saved policy. Native named-set observation and
packet/rollback conformance are required before that capability is announced.
See [ADR 0039](decisions/0039-versioned-typed-object-library.md).
