# Native resource identity and receipt comparison

The native library can emit a typed table marker and parse/compare a limited native
observation. All these operations are unprivileged and deterministic; none reads a
host, executes nft, enrolls a resource, persists a receipt or authorizes an apply.
The separate [protected journal](protected-resource-receipts.md) can now persist
explicit trusted expected receipts and perform read-only reconciliation.
See [ADR 0007](decisions/0007-native-resource-receipts.md).

## Compiler identity

`NftFilterCompiler.Compile(policy, identity)` accepts `NftTableIdentity`, containing
nonempty owner and resource-birth UUIDs. It emits a fixed canonical table comment:
`nergal:v1:<owner UUID in lowercase N format>:<resource UUID in lowercase N format>`.
No raw comment input is accepted. The candidate digest includes these bytes. The
original one-argument compiler retains its output unchanged. Both overloads remain
create-only and fail on an existing table when submitted as a native batch.

Identities must come from trusted enrollment and be unique for a resource birth.
A name or comment alone is not ownership evidence; other privileged actors can copy
those bytes. This marker is not the nft process-owner flag or an authorization token.

## Observation slice

`NftTableObservation.Parse(json)` accepts at most 64 KiB of valid UTF-8 text and JSON
depth 16. It requires native schema version 1 with metadata, the tagged
`inet nergal_filter` table and one `input` base chain of type filter, hook input,
priority 0, with an explicit accept/drop policy. Table and chain handles must be
positive integers. Marker text must be canonical and have nonempty UUIDs.

Duplicate/unknown properties, flags, extra objects, unsupported rules, different hooks/families,
missing fields, malformed identities and unknown schema versions are rejected. A
failed result has no partial observation and a stable `ErrorCode`. Null input throws
`ArgumentNullException`. Invalid input is never echoed in diagnostics.

After the chain, the observer accepts ordered schema-1 rules matching canonical
`NftFilterCompiler` output: IPv4/IPv6 family (`meta nfproto` or implied by address/ICMP),
optional source/destination canonical CIDR prefixes (`ip`/`ip6` `saddr`/`daddr`),
protocol (`meta l4proto` for `tcp`, `udp`, `icmp`, `ipv6-icmp` or implied by `dport`),
optional TCP/UDP destination port (`1`–`65535`), and a terminal `accept`/`drop`.
Each rule must have a distinct positive handle and belong to that input chain.
Redundant elidable matches, out-of-order match stages, non-canonical prefixes, counters,
comments, interfaces, or extra expressions cause the entire snapshot to be refused.
The immutable `Policy` reconstructs every accepted rule in order. See
[ADR 0018](decisions/0018-family-rule-observations.md) and
[ADR 0021](decisions/0021-observe-schema1-filter-rules.md).

`StateDigest` retains `nergal-observation-v1` for empty chains and `nergal-observation-v2`
for family-only rules byte-for-byte. Rules carrying addresses, protocols, or ports use
`nergal-observation-v3` binding the marker, table and chain handles, chain semantics,
and each rule's handle, family, source/destination CIDR, protocol, destination port,
and verdict in order. JSON property order and validated tool version/release text do
not alter enforcement identity. No accepted enforcement field is dropped. The parser
cannot prove collection completeness: a trusted future agent must obtain a full table
snapshot locally under its resource lock, not accept filtered or browser-supplied JSON
as host evidence. Observations and their digests are immutable snapshots.

Observation errors are `observation.tooLarge`, `observation.invalidJson`,
`observation.duplicateProperty`, `observation.shape`, `observation.unsupportedObjects`,
`observation.schema`, `observation.fields`, `observation.scope`, `observation.handle`,
`observation.identity`, `observation.policy`, `observation.rule` and `observation.createEcho`.

`NftTableObservation.ParseEnrollmentEcho(json)` parses the handle-bearing JSON echo
from a successful local exclusive creation of the tagged `inet nergal_filter` empty
`accept` input chain (`create` table followed by `add` chain, both with positive
handles). `NftTableObservation.ParseReplacementEcho(json)` similarly parses the
echo of an atomic delete-and-recreate replacement or rule-bearing baseline creation
(`create` table, `add` chain with `accept` or `drop`, and zero or more schema-1
`add` rules). Unsupported replacement echo shapes fail with `observation.replacementEcho`.
The caller must establish successful native transaction exit and independently compare
a complete listing before binding or recording receipts.

## Expected receipt

`NftTableReceipt` binds the expected boot UUID, positive Linux network namespace inode,
typed owner/resource-birth identity, positive table handle and complete observation
digest. `NftReceiptVerifier.Verify` compares it with an observation and separately
supplied trusted current context. It returns all mismatches in stable order:

| Code | Meaning |
| --- | --- |
| `context.invalid` | Current boot identity is empty or namespace identity is zero. |
| `context.bootChanged` | Current boot differs from expected enrollment. |
| `context.namespaceChanged` | Current network namespace differs. |
| `identity.mismatch` | The typed owner/resource-birth marker differs. |
| `handle.mismatch` | Table was replaced or another native table is being observed. |
| `state.drift` | The complete recognized observed state differs. |

Constructors reject missing identities/digests and zero handles/context. Comparison
results expose a defensive read-only list. A match establishes only equality of the
supplied assertions. Receipt and current context must not be accepted from browser
request claims as authority. A caller must not turn a rejected current observation
into a new expected receipt to make the mismatch disappear.

Protected receipt persistence, explicit enrollment/reconciliation, authenticated
agent transport and receipt-aware confirmed apply are implemented. Kernel replacement
and journal acknowledgement are separate transactions; ambiguous crash windows fail
closed rather than claiming a cross-system atomic commit. Legacy unbound apply is
not an alternative to receipt verification.

## Complete multi-table observations and rollback

The development implementation reconstructs all present owned NAT, bridge and
early inet tables. Its composite fingerprint binds each table's native object
handles and complete supported semantics, in addition to the primary filter.
Single-table fingerprints are unchanged. Journal binding, candidate evidence,
confirmation and reconciliation compare the entire compiled bundle with protected
intent. A copied ownership comment is not an authorization to adopt a table.

Existing primary-only receipts for multi-table deployments cannot match these
complete fingerprints. They fail closed; no observation silently upgrades them.
Do not mix old and new binaries or deploy this change over an active operation.
A trusted maintenance procedure must recreate and verify protected intent before
using the new receipt format. See [ADR 0036](decisions/0036-complete-bundle-observation-and-rollback.md).
Extended bridge and early inet dispatch use the same receipt-bound transaction.
Explicit and watchdog rollback require either the protected baseline or the
durably recorded candidate fingerprint. A semantic lookalike with different
native handles cannot authorize replacement. Unacknowledged replacements and
restore-before-acknowledgement crash windows require manual recovery.
