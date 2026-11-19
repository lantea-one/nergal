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
depth 16. It requires native schema version 1 and exactly metadata, the tagged
`inet nergal_filter` table and one empty `input` base chain of type filter, hook input,
priority 0, with an explicit accept/drop policy. Table and chain handles must be
positive integers. Marker text must be canonical and have nonempty UUIDs.

Duplicate/unknown properties, flags, extra objects, rules, different hooks/families,
missing fields, malformed identities and unknown schema versions are rejected. A
failed result has no partial observation and a stable `ErrorCode`. Null input throws
`ArgumentNullException`. Invalid input is never echoed in diagnostics.

**This observer does not yet support the rule-bearing policies the compiler can
emit.** It explicitly rejects them. It is an identity/reconciliation slice for the
empty-chain watchdog resource, not a general import, decompiler or full backend driver.

`StateDigest` fingerprints a typed projection of the marker, both native handles,
family/name, chain type/hook/priority and default verdict. JSON property order and
validated tool version/release text do not alter enforcement identity. No accepted
enforcement field is dropped. The parser cannot prove collection completeness: a
trusted future agent must obtain a full table snapshot locally under its resource
lock, not accept filtered or browser-supplied JSON as host evidence. Observations and their digests are immutable snapshots.

Observation errors are `observation.tooLarge`, `observation.invalidJson`,
`observation.duplicateProperty`, `observation.shape`, `observation.unsupportedObjects`,
`observation.schema`, `observation.fields`, `observation.scope`, `observation.handle`,
`observation.identity` and `observation.policy`.

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

Protected receipt persistence and read-only reconciliation now exist in LocalState.
Production resource enrollment, receipt-aware apply/recovery, reboot reconciliation,
kernel/journal compare-and-swap and authenticated agent transport remain unimplemented.
Bound-resource legacy apply is disabled until those mutation boundaries are designed
and tested.
