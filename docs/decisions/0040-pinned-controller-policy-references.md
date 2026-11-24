# ADR 0040: Pinned controller list references in filter rules

Status: Accepted for static controller references resolved to existing matchers.

Each schema-2 inet filter source, destination or destination-port matcher may select
one immutable controller object version. Retain identity, version, name, type,
contents and content digest in canonical policy JSON. Never resolve "latest" at
compile/apply time. Controller saves verify references against database history;
agent compilation uses the embedded snapshot and needs no controller database.

References are mutually exclusive with the corresponding literal matcher. Validate
family, transport, cardinality, overlap and every existing native matcher constraint
before emitting a candidate. Resolve a singleton to a scalar, multiple entries to
the existing anonymous set contract. Preserve all other rule restrictions, negation,
order and verdict. This implements controller reuse, not native named nft sets,
dynamic lists, maps, intervals, timeouts or imported native named-object conversion.
Those require separate complete observation and packet/rollback conformance.

UI selection explicitly pins a displayed version. Rebinding is a draft change;
review, revision save and confirmed apply remain separate. Ordinary rule edits and
reordering retain references. Removing a reference clears its matcher explicitly
and must be reviewed; it never leaves a hidden literal copy. Show saved revision
references before library edits and warn that older revisions retain older versions.
No deletion is introduced. Native diffs show enforcement changes; reference metadata
changes are visible separately even when native text is unchanged.

Retain the existing receipt boundary: native observation describes resolved kernel
matchers, not controller metadata. Exact compiled artifacts and complete ownership
receipts still gate apply/confirm/rollback. Verify reference compilation against
literal equivalents and real packets in disposable namespaces; unit tests alone
cannot establish packet semantics or rollback correctness. No production firewall
or SQL schema change is required for self-contained immutable revision snapshots.

## Selector scope extension

The same immutable-reference contract now has explicit primary and auxiliary inet
selectors. Database verification, usage enumeration and native projection already
cover both scopes. A missing scope retains the original primary-only API behavior;
unknown/empty/duplicate form scopes are denied. Scope selection changes no native
semantics, SQL schema, receipt boundary or implicit host-application behavior.

[ADR 0048](0048-native-static-list-references.md) adds complete native static-set
projection while retaining the legacy projection specified here for old revisions.
See [the current library guide](../reusable-object-library.md) for all supported slots.
