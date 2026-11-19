# ADR 0007: unprivileged native resource observations and expected receipts

- Status: accepted
- Date: November 18, 2026

## Decision and slice

Add a typed optional table identity to the native compiler, expressed as a fixed
canonical comment containing nonempty owner and resource-birth UUIDs. The caller
must obtain those identities from trusted enrollment, never a browser claim. The
existing compile overload keeps its exact create-only output; tagged candidates
remain create-only and their digests include the identity. There is no raw comment
or native-text extension point.

Add a strict bounded parser for native JSON observations of the fixed inet table
with one empty input base chain at priority zero and an explicit accept/drop policy.
This identity slice deliberately rejects rule-bearing/extra-object tables, flags,
unknown/duplicate properties, unknown schema versions, mismatched family/name/hook,
invalid handles and absent/noncanonical identities. It is not a general nft import,
a policy decompiler or proof of the compiler's entire supported rule slice.

Observation fingerprints cover both kernel handles, identity, chain semantics and
default policy in a deterministic typed projection. JSON property order and nft tool
version/release text do not affect the fingerprint; metadata is validated separately.
No recognized enforcement field is ignored. Numeric handles must be positive integers.
The parser cannot detect omitted kernel objects: a trusted collector must supply a
full table snapshot under its resource lock, not filtered or browser-supplied JSON.

An expected receipt binds boot UUID, network namespace inode, table identity, kernel
table handle and the complete observation fingerprint. Verification compares all
bindings and reports stable denials. The expected receipt must come from protected
local enrollment/reconciliation evidence. A new observation must never be promoted
to a new expected receipt simply because its name/comment looks familiar. These
POCOs and comparisons are not authorization tokens and perform no host operations.

## Proof boundaries and future work

A receipt value alone is not proof of ownership. This milestone does not persist
receipts in the journal, enroll a real table, perform compare-and-swap replacement,
or close races with another privileged ruleset writer. Protected enrollment and
crash-safe receipt persistence/reconciliation remain the next boundary. The watchdog
fixture still owns only a freshly created namespace resource. Web remains disconnected.

A future executor must bind its trusted current context, serialized resource lock,
protected expected receipt, complete native validation and rollback evidence before
any owned mutation. It must fail on drift or a missing/recreated resource, not adopt
it. Independent rollback and kernel/journal recovery ordering remain mandatory.
Do not generalize an observation comparator into a production privileged apply API.

## Verification

Unit tests cover malformed/ambiguous JSON, unsupported semantics, identity and
context mismatch, deterministic projections, mutation protection and receipt validation.
An isolated native fixture verifies tagged candidates, observations, policy drift,
recreated same-name/same-comment tables with different handles, and a different real
network namespace. It performs all kernel work in disposable user/network namespaces
and preserves foreign tables. No production observation or private topology is input.

## Sources

- [Upstream nft manual](https://netfilter.org/projects/nftables/manpage.html)
- Installed upstream libnftables-json(5) schema for native observation objects.
