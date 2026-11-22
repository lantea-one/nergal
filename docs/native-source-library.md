# Native source library

Administrators can open **Native sources** on an authenticated controller to import
an `nftables.conf` or other UTF-8 native configuration snapshot into controller
SQLite history. Supply a display name and select a file. Contextual hints explain
encoding, size, storage and conversion limits. Importing stores an immutable source
and an attributed audit entry atomically; it never executes nft, resolves includes,
creates a managed policy or changes a firewall.

Each import has an independent identity, even when names or contents repeat. The
metadata list shows import time in the viewer's local timezone and size. Timestamps
remain stored in UTC, with the original instant available in the tooltip. Select **Review** for one source's exact
content, digest and non-exhaustive lexical migration review. **Download original**
returns its exact UTF-8 bytes, including BOM and line endings, as an attachment
named `nftables.conf`. Reports select a stored source by identity, not a server path
or ambiguous digest. This replaces the previous unreleased staging-digest selector.
Generated policy export and semantic conversion remain separate future work.

## Storage and authorization

Source bytes, SHA-256, importing actor and UTC time live in `controller.db`. Only
metadata is loaded for the list; selected content is verified against its persisted
byte length and digest before inspection or download. Database triggers reject source updates/deletes. Their definitions and append-only
audit protections are checked on each store operation.
No source deletion/retention UI is implemented in this slice.

Anonymous and Auditor requests cannot inspect, import or download private sources.
Import actions require Administrator role and CSRF protection. Display names never
select filesystem paths; uploaded client filenames are ignored. Bounds are 512 KiB
per UTF-8 source, 128 records and 32 MiB retained content. The upload request bound
is 600,000 bytes including multipart overhead, with bounded multipart buffering in
memory. Invalid encoding, names, duplicate/unknown form fields, extra files and
capacity exhaustion fail without a partial source/audit transaction.

`NativeSources:Directory` is now optional operator staging. Existing bounded file
snapshots can be explicitly copied through **Import staged …**. The database copy
is canonical after import; a later file change cannot alter it. Staging is never
automatically reapplied or used to overwrite history. A basic installation needs
no staging directory or particular deployment topology.

## Existing controller databases

New controller stores use schema 3, including the typed object library. Existing schema-1/2 stores require an explicit
offline upgrade; the web process never upgrades them automatically:

1. Stop the controller and take a verified backup of its SQLite store using an
   appropriate SQLite backup procedure, including any uncheckpointed WAL state.
2. Run `nergal-admin controller upgrade ABSOLUTE_CONTROLLER_DIRECTORY` under the
   controller store's owner identity. The directory and database protection rules
   are unchanged. No agent journal or account database is migrated by this command.
3. Restart the controller and verify retained hosts, revisions, settings and audit
   history. The upgrade is atomic and idempotent; unknown versions, source-table
   collisions and invalid protection definitions are rejected without repair.

The isolated development stack stops its own web writer and runs this command via
its disposable provisioning container. This is not a production upgrade operation.
Migrations for additional SQL backends remain deferred until the logical schema
stabilizes. See [ADR 0038](decisions/0038-database-native-source-snapshots.md).
