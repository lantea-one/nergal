# ADR 0038: Database-backed native source snapshots

Status: Accepted for source ingestion and original-source download only.

## Decision

Persist exact bounded UTF-8 native source snapshots in the controller database as
immutable, content-bound records with a canonical identifier, display name,
importing actor and UTC timestamp. Insert the source and its audit event in one
transaction. Download original bytes from that record; never reload a file or
reconstruct an original from generated policy. Repeated imports are independent
history records, including identical bytes under different names.

Administrator-only, CSRF-protected UI actions accept bounded file uploads or copy
an explicitly selected operator-directory staging snapshot. File names never select
server paths. Directory snapshots are optional staging inputs, not the canonical
source store; a changed staging file cannot update an existing database record.
Only selected source detail loads its contents. Listing returns metadata.
Reports are recomputed deterministically from immutable stored bytes and retain
source SHA-256 binding; no semantic conversion or execution authority is granted.
Unknown native content remains visible and conversion remains blocked.

Keep schema evolution explicit: initialize new stores at controller schema 2 and
provide an offline SQLite-only `controller upgrade` from validated schema 1. The
web host never silently upgrades an existing database. The transaction preserves
existing hosts, policy revisions, settings and audit history; immutable-source
triggers, audit protection definitions and schema shape are checked when opening schema 2. No additional SQL
adapter or cross-engine migration is introduced.

Sources are limited to 512 KiB each, 128 records and 32 MiB total retained source
bytes per controller in this first implementation. Reject invalid UTF-8, unsafe
names, unknown schema versions, missing immutability protections, corrupt digest
bindings and over-capacity imports explicitly. No delete or overwrite workflow is
added. A future retention policy requires explicit audited design.

## Verification

Use synthetic sources and real SQLite to verify immutable snapshots, exact byte
round trips, independent identities for duplicate content, actor authorization,
transactional audit, capacity rejection, corruption denial and offline upgrades.
Exercise the real HTTPS upload/staging/download routes, CSRF and anonymous/auditor
boundaries. Browser screenshots use synthetic data only. This adds no firewall
operation and establishes no source-to-policy equivalence.

Controller schema 3 under [ADR 0039](0039-versioned-typed-object-library.md) now
retains these source protections and extends the explicit offline upgrade from
schemas 1 and 2. New stores initialize at schema 3.

Controller schema 4 now retains these protections and adds immutable conversion
plans under [ADR 0055](0055-source-bound-native-conversion-plans.md). New stores
initialize at 4; schemas 1/2/3 require the same explicit offline upgrade boundary.
