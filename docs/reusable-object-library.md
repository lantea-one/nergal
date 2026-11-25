# Typed sets and IP lists library

Open **Sets & IP lists** (`/manage/objects`) to maintain reusable IPv4, IPv6 and
transport-port lists. The database stores stable identities and immutable versions.
New policy attachments use [shared native static sets](native-static-lists.md).
Earlier saved references retain their original literal projection. Saving a list
changes library history only; it does not update policies or apply a firewall.

## Create and maintain a list

1. Choose **New list**, enter a unique lowercase name such as `trusted_clients`,
   and select IPv4, IPv6 or transport ports. Names and types stay fixed.
2. Add an optional plain-text description and 1–64 entries, one per line. Numeric
   addresses become canonical `/32` or `/128` prefixes. CIDRs require zero host
   bits. Ports are individual integers from 1 to 65535; TCP/UDP belongs to the rule.
3. Save. The controller appends an immutable version and attributed audit event in
   one transaction. Entries are copied, normalized and sorted without merging.
4. Search by name/description. **Version history** shows read-only old contents;
   **Compare versions** reports added, removed and unchanged entries plus metadata
   changes. Entry differences do not infer network coverage or packet outcomes.
5. To use a changed version, explicitly select it in a policy draft, review the
   candidate/diff, save a revision and use confirmed apply.

Forms provide contextual hints and retain invalid input. IPv4 and IPv6 cannot mix.
Hostnames, scopes, mapped addresses, host bits, duplicate canonical entries,
address/port ranges, arbitrary native syntax and dynamic options are rejected.
Descriptions allow up to 500 characters. Lists may store overlapping prefixes,
but a multi-prefix rule reference must satisfy the compiler's disjoint/non-adjacent
contract. Compilation rejects incompatible lists without merging or dropping entries.

Administrators can create/edit; Auditors can inspect/search/history. Writes require
CSRF protection and the exact expected version. A stale edit returns HTTP 409 with
retained input and leaves the newer contents untouched. Compare with the current
version before editing again. There is no force-save, rename or deletion workflow.

## Attach an immutable version

Open **Policies → Reusable list references**, choose the table/chain and rule,
select the matcher and a displayed list version, then choose **Attach selected
version to draft**. This replaces only that matcher's literals or previous pin.
The selector can browse one list's bounded history while preserving the draft;
it never selects a newer version implicitly.

| Scope | Supported matchers |
| --- | --- |
| Primary and auxiliary inet rules | Source addresses, destination addresses, destination ports |
| DNAT | Source addresses, original destination addresses, original destination ports |
| Postrouting NAT | Source addresses, destination addresses, destination ports |
| Bridge forwarding and regular chains | Source addresses, destination addresses, destination ports |

Snapshots retain identity, version, name, type, description, canonical entries,
content digest and projection choice in policy JSON. Preview/save verifies each
against immutable database history. Agent compilation uses those embedded snapshots
without fetching "latest" or consulting the controller database. Editing a library
object cannot change a saved policy's bytes, digest or enforcement.

Ordinary editing, ordering and inline enable/disable retain every pin. Pinned
literal fields are read-only and are not submitted as conflicting values. Disabled
rules retain contents/order but emit no runtime rule or unused static definition;
invalid dormant references still fail validation. **Remove reference from draft**
clears that matcher and its negation, which may broaden access. Required DNAT
destinations and explicit-SNAT sources cannot be removed without replacement.
All changes remain drafts until revision save and confirmed apply.

The detail page lists every saved revision reference, including older object
versions and all supported matcher paths. This shows saved usage, not proof of
active deployment. Reference-only metadata changes remain visible even where
legacy native text is identical. For native projection, a different version has a
different generated set identity even if its entries did not change.

## Persistence and runtime boundaries

The controller database is canonical. Object identity, type, contents, digest,
version, actor and UTC time survive restart. Browser times show the viewer's local
timezone explicitly. Immutable SQL protections cover identities/history and exact
canonical contents are checked with SHA-256. Limits are 128 objects, 64 versions
per object and 64 entries per version; capacity errors leave no partial audit/state.
Native projection also has the stricter complete-observation budget documented in
[the native static-set guide](native-static-lists.md#bounds-and-support-limits).

Current stores use controller schema 4. Initialize a new store with the offline
controller initializer. The application rejects retired controller schemas and
preserves existing files. Additional SQL engines remain M6 work.

Native named objects now have complete definition/content/handle/lookup receipts,
generation-consistent collection and confirmed apply/rollback. Dynamic meters remain
separate; maps, concatenations, named MAC sets, standalone unused declarations and
native dynamic-list options are unsupported. The [native conversion workflow](native-source-library.md) preserves supported static sets and rejects unsupported semantics. [Saved revision exports](policy-exports.md)
and exact original-source downloads are available as distinct workflows.

## Screenshots

The existing guided-reference screenshots show the retained UI for earlier saved
revisions. Current native candidate screenshots are in the native static-set guide.

See [ADR 0039](decisions/0039-versioned-typed-object-library.md), [ADR 0040](decisions/0040-pinned-controller-policy-references.md) and [ADR 0048](decisions/0048-native-static-list-references.md) for the original library, legacy projection and native evidence contracts.
