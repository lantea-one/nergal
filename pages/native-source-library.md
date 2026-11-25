# Native source library

The administrator-only **Native sources** screen accepts UTF-8 `nftables.conf`
uploads into immutable controller database history. Supply a display name and a
file; field hints explain the limits. Uploads do not execute nft, resolve includes,
create managed policies or change firewall rules.

Each import receives an independent identity, attributed audit event, UTC time,
exact byte length and SHA-256. Times are stored in UTC and displayed in the
viewer's browser timezone, named in the page footer; the tooltip retains UTC. Repeated names or identical contents remain separate
snapshots. Select **Review** for one source's exact text and non-exhaustive migration
review. **Download original** returns its exact bytes, including BOM and line endings,
as `nftables.conf`. The JSON review download uses the stored source identity.
Semantic conversion remains unfinished. [Saved revision exports](policy-exports.md)
provide separate native and complete intent files from selected database revisions.

## Shared viewer and import analysis

Viewing and import use one workflow and the same source-analysis entry point.
Exact token spans retain physical positions, comments, BOM, CRLF/CR/LF, opaque
quoted values, variable/set references and continuations. The displayed inventory
and downloaded report derive from those same tokens. Unknown input remains present
for semantic accounting, and values cannot masquerade as review keywords.

The lexical frontend does not execute source, open include paths, validate native
syntax or produce policy. It has independent 512-KiB UTF-8, 65,536 significant-token
and 131,072 total-token bounds; comments, whitespace and line endings count toward
the total. Controls, invalid encoding, unterminated chunks and capacity exhaustion
yield stable diagnostics with no partial document or private values. The exact
original remains available even when analysis fails. Future semantic mapping and
revision creation will extend this same workflow; conversion remains blocked.
See [ADR 0050](https://git.lantea.one/lantea-one/nergal/src/branch/main/docs/decisions/0050-lossless-native-source-tokenization.md).

## Shared source structure

The shared analysis groups braces, brackets and parentheses over the original
tokens, retaining unknown input, comments and line endings. Optional **Source
structure and diagnostic details** shows group/depth metadata; failures show a
code and physical line/column beside the original. Quoted values/comments cannot
introduce delimiters. Nesting is limited to 64 groups. No partial tree or topic
inventory is used when grouping fails, and the exact original remains downloadable.

Current review downloads use **schema 2**, retaining the name/digest and masked
review plus a value-free `structure` summary: completion, token/group counts,
maximum depth and an optional code/span diagnostic. Counts are zero on failure;
source values, tokens and the tree are excluded. Positions use UTF-16 units and
physical source lines; tabs count as one column. Structural completion is not
native syntax validation or semantic conversion. See
[ADR 0052](https://git.lantea.one/lantea-one/nergal/src/branch/main/docs/decisions/0052-bounded-native-source-structure.md).

The shared analysis also partitions original nodes into ordered contextual
statements, retaining all trivia and raw expressions. It recognizes root table
headers and table-local chain/object headers; table/chain counts come from those
scopes rather than keyword sequences inside definitions or rules. Definitions,
includes and native commands remain source data. Unclassified heads appear as
`source.unclassifiedStatements` review topics with value-free line positions.
Object bodies and rule expressions still need semantic parsing. No statement is
discarded, include opened or command executed; conversion remains blocked.
See [ADR 0053](https://git.lantea.one/lantea-one/nergal/src/branch/main/docs/decisions/0053-native-source-declaration-partition.md).

The following captures use staged synthetic sources in a separate controller.
Complete grouping retains semantic gaps; failed grouping identifies the exact
position without partial counts. The mobile light view has no page overflow.

![Shared source structure in dark mode](assets/screenshots/source-structure-dark.jpg)

![Source mismatch position in light mode on mobile](assets/screenshots/source-structure-mobile-light.jpg)

## Persistence and limits

Source bytes and metadata live in `controller.db`; listing loads metadata only.
Selected content is checked against its stored length and digest before use.
Immutability triggers block updates/deletes and their definitions are verified.
The initial retention limits are 128 records and 32 MiB, with 512 KiB per source.
No deletion or retention-policy interface is implemented in this slice.

Anonymous users and Auditors are denied. Imports require Administrator role and
CSRF. Invalid UTF-8, unsafe display names, extra/ambiguous fields, multiple files,
file/request limits and capacity exhaustion are rejected without partial imports.
Uploaded filenames never select paths. Raw source views are read-only.

An optional operator directory provides staging snapshots. **Import staged …**
copies a selected snapshot into database history; later file changes cannot update
that record. A basic installation requires no staging directory or site integration.

## Existing databases

New controller stores use schema 3, including the typed list library. Stop the controller and make a verified SQLite
backup, including any uncheckpointed WAL data, before upgrading an existing schema-1/2
store under its owner identity:

```sh
nergal-admin controller upgrade ABSOLUTE_CONTROLLER_DIRECTORY
```

The web host does not silently upgrade. The explicit operation is atomic and
idempotent, retains hosts/settings/policy revisions/audit, and rejects unknown
versions, source-table collisions and invalid protection definitions without repair.
Agent journals and account stores are not changed. The isolated local sandbox stops
its own writer and performs this offline step through disposable provisioning.
Migrations for additional SQL engines remain deferred until schema stabilization.

## Verification

Real SQLite tests cover exact bytes, independent identities, atomic audit failure,
role/capacity denial, immutable protections, corruption and upgrades. HTTPS checks
exercise upload/staging/download, persisted data after restart, source escaping,
CSRF, encoding/size limits and anonymous/Auditor denial. Existing packet and rollback
checks remain separate evidence; source ingestion is not conversion equivalence.

## Appearance

These captures use a separate synthetic-only controller database and staging source.
They contain no private server exports or topology.

![Database source library in dark mode](assets/screenshots/source-library-dark.jpg)

![Database source library in light mode](assets/screenshots/source-library-light.jpg)

![Database source library on mobile](assets/screenshots/source-library-mobile.jpg)
