# ADR 0003: model confirmed apply before implementing an executor

- Status: accepted
- Date: November 18, 2026

## Decision and implemented boundary

Implement an immutable, deterministic confirmed-apply state model in Core. Bind an
operation to the enrolled agent, ownership identity, expected confirmed revision,
exact candidate digest and exact rollback-artifact digest. Add a SHA-256 digest to
successful compiler results so approval can identify exact UTF-8 candidate bytes.
A digest identifies content; it is not authorization, a signature or kernel validation.

This milestone implements contracts and transitions only. It adds no timer, journal,
watchdog, processes, privileges, web endpoints or kernel execution. Evidence supplied
to the model is a trusted coordinator's assertion, not independently verified proof.
No production or development-host apply API is enabled by this decision.

## Contract and transitions

Ownership identifies the sole managed resource on an enrolled agent by agent UUID,
owner UUID and nonzero revision. A future agent must establish these from its own
protected durable enrollment/journal and live owned-state reconciliation, never from
request data or a table name/comment alone. The plan binds a unique operation UUID,
expected ownership, candidate digest and rollback digest, with a positive timeout
of at most one hour to keep the unconfirmed interval bounded. Revision exhaustion
and identical candidate/rollback digests are rejected. The next confirmed revision
is exactly expected revision plus one. Initial enrollment and first installation
without a prior confirmed revision are outside this plan model.

Every event must carry the same plan binding. Rollback arming requires a nonempty
watchdog UUID, which subsequent events must match. Prepared -> rollback armed ->
awaiting confirmation -> confirmed is the only success path. Apply failure, post-apply
verification failure or timeout requires rollback; successful rollback ends rolled back, failed rollback requires
recovery. An interruption in a nonterminal phase requires recovery, since this
in-memory model cannot establish what reached disk or kernel. Terminal states cannot
be reopened or overwritten. Rejected events return stable error codes and an immutable
session; expiration may advance that returned session to rollback required even when
the requested operation is denied. Callers must retain the returned session.

Time is caller-supplied monotonic elapsed time from operation creation, never wall
clock time. It cannot decrease. The deadline starts when rollback is armed, before
apply can be acknowledged. Confirmation at the exact deadline is too late. Late
apply success cannot revive an expired lease. Checks and rollback results remain
possible after expiration. This model does not schedule its own deadline checks.

## Requirements for the future executor (not implemented)

Before any apply, a restricted local agent must serialize operations per resource,
authorize the enrolled owner and expected revision, reconcile observed state, validate
the entire candidate natively, and capture a complete restorable owned-state artifact.
It must durably record the bound operation and arm an independent local watchdog with
that exact rollback artifact before changing the kernel. Acknowledgments must describe
completed durable side effects, not intentions. The watchdog must survive controller,
web and apply-worker loss. Confirmation and timeout require one serialized durable
decision: the watchdog cannot race a successful confirmation and restore old state.

Recovery must compare protected journal state and actual owned kernel state after
restart; missing, corrupt or conflicting evidence blocks new applies. In-flight or
uncertain operations cannot be silently confirmed. Failed rollback must remain visible
and block new work. Ownership changes, revisions and watchdog cancellation require
explicit crash-safe ordering and compare-and-swap persistence. The pure model does
not supply concurrency control or replay protection across discarded sessions.

The reserved table remains create-only under ADR 0002. A future replacement compiler
must preserve foreign tables and match ownership/revision evidence; this model does
not grant permission to adopt or delete an existing table. Restoration, interrupted
apply, watchdog independence, confirmation races and packet recovery all need real
isolated integration tests before privileged apply is enabled.

## Verification and limits

Deterministic unit tests cover stale/cross-operation evidence, unknown events,
monotonic and exact-deadline behavior, failed apply/rollback, interruption, terminal
states, and immutable transitions. Existing isolated compiler and packet fixtures
remain regression checks; they do not exercise a watchdog or establish rollback
correctness. The next milestone is a protected durable journal and independently
running watchdog prototype, initially against disposable namespace resources only.
