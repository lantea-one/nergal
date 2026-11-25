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
[Generated policy exports](policy-exports.md) are separate downloads from saved
database revisions. Semantic native source conversion remains future work.

## One viewer and import workflow

Source viewing, review and later semantic import use the same analysis pipeline,
not separate parsers. Upload or select one immutable source here, inspect its exact
contents and diagnostics, and retain that identity for mapping/conversion review.
The frontend tokenizes once and retains exact UTF-16 offsets, physical line/column
positions, comments, BOM, CRLF/CR/LF, quoted values, references and continuations.
The displayed inventory and downloadable report derive from those same tokens.
Unknown tokens remain present for explicit semantic accounting; values inside
quotes and references cannot masquerade as review keywords.

Tokenization is bounded to 512 KiB of strict UTF-8, 65,536 non-trivia/non-newline
tokens and 131,072 total tokens including trivia. Invalid encoding, unsupported
control characters, unterminated quoted chunks or exhausted bounds return stable
diagnostics without partial tokens or copied source values. Only ASCII space/tab
are horizontal trivia; unfamiliar Unicode whitespace is retained as unknown input.
Success is lexical accounting, not native syntax validation or semantic conversion.
The original remains downloadable even when analysis fails. Include paths are
retained as source text and never opened by the viewer/import frontend.

The existing review always reports conversion blocked. Semantic parsing, persisted
mapping/gap plans and reviewed revision creation will extend this same workflow;
there is no separate converter with different validation. See
[ADR 0050](decisions/0050-lossless-native-source-tokenization.md).

## Shared source structure and diagnostics

The same analysis now groups braces, brackets and parentheses over the original
token document, including all trivia and unknown input. **Source structure and
diagnostic details** shows optional group/depth metadata. An incomplete source
shows the failure code and physical line/column alongside the original. Quoted
values and comments cannot introduce delimiters. Nothing is executed or resolved.

Nesting is limited to 64 groups. Missing/unexpected braces retain
`source.unbalancedBraces`; other missing/unexpected delimiters report
`source.unbalancedDelimiter`, wrong closing kinds report
`source.mismatchedDelimiter`, and excessive nesting reports `source.nestingTooDeep`.
Positions identify the offending closer or unmatched opener. Columns and offsets
count UTF-16 code units, with tabs counting as one; they are not UTF-8 byte offsets.
Failure returns no partial tree or topic inventory. The exact original can still
be inspected and downloaded. The viewer hides partial counts and explains that
review topics are unavailable until the source error is resolved.

Current migration-review downloads use **schema 2**: the original name/digest and
masked `review` remain, with a value-free `structure` summary containing completion,
token/group counts, maximum depth and an optional code/span diagnostic. Counts are
zero on failure. The report does not serialize source values, tokens or the tree.
Clients must check the report version. Structural completion does not establish
native syntax validity, semantic compatibility or conversion readiness. Semantic
parsing, explicit include mappings and persisted gap plans remain M4 work. See
[ADR 0052](decisions/0052-bounded-native-source-structure.md).

These captures use staged synthetic sources in a separate disposable controller.
The complete structure still reports semantic work; the failed structure shows
the exact mismatch position and omits partial counts. The mobile light view fits
a 375-pixel viewport without page overflow.

![Shared source structure in dark mode](../pages/assets/screenshots/source-structure-dark.jpg)

![Source mismatch position in light mode on mobile](../pages/assets/screenshots/source-structure-mobile-light.jpg)

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
