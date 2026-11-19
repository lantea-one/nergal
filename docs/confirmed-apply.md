# Confirmed-apply model

`Nergal.Core.Deployment` implements immutable plan bindings and deterministic
transitions. The separate [local journal](local-journal.md) can persist and replay
these transitions. Core itself does not execute an apply, arm a timer, persist state,
authorize requests or restore packets. The web app does not expose this model as an endpoint.
The [decision record](decisions/0003-confirmed-apply-contract.md) specifies the
future agent/watchdog obligations that remain unimplemented.

## Artifact and ownership binding

`CandidateDigest.FromText` hashes exact UTF-8 bytes with SHA-256. It preserves line
endings, whitespace and Unicode representation and rejects malformed UTF-16. The
constructor accepts exactly 64 lowercase hexadecimal characters. Successful native
compiler results expose `Digest`; failed results expose neither candidate nor digest.
Digests identify content and do not prove authorization, ownership or native validity.

`ResourceOwnership` identifies the enrolled agent, its sole managed resource's owner
and a nonzero last-confirmed revision. `ApplyPlan` binds that claim to an operation
UUID, candidate digest, rollback-artifact digest and timeout. IDs cannot be empty;
artifacts must differ; timeout must be positive and at most one hour. Exhausted
revisions cannot start new plans. `ConfirmedRevision` is the proposed next revision,
not a claim that it has been committed. Initial enrollment and first installation,
which have no prior confirmed revision, are outside this plan model.

Ownership must eventually come from protected local enrollment/journal records and
kernel reconciliation, not from request claims, table names or comments. This model
compares asserted bindings only. It cannot enroll an agent or establish real ownership.

## Lifecycle

`ApplySession.Prepare(plan)` starts at elapsed time zero, with no watchdog or deadline.
`Advance(kind, evidence, watchdogId, elapsed)` evaluates an acknowledgment from a
trusted coordinator. The evidence must equal every field of the plan. Arming must
supply a nonempty watchdog UUID; all later acknowledgments must match it. Before
arming, non-arming events use an empty watchdog UUID.

| Phase | Acknowledgment | Result |
| --- | --- | --- |
| Prepared | RollbackArmed | RollbackArmed; exclusive deadline = elapsed + timeout |
| RollbackArmed | CandidateApplied before deadline | AwaitingConfirmation |
| RollbackArmed | ApplyFailed | RollbackRequired |
| AwaitingConfirmation | Confirm before deadline | Confirmed |
| AwaitingConfirmation | VerificationFailed | RollbackRequired |
| RollbackArmed / AwaitingConfirmation | CheckDeadline at/after deadline | RollbackRequired |
| RollbackRequired | RollbackSucceeded | RolledBack |
| RollbackRequired | RollbackFailed | RecoveryRequired |
| Any nonterminal phase | Interrupted | RecoveryRequired |

`CheckDeadline` otherwise preserves the phase and incorporates the elapsed time.
Confirmed, RolledBack and RecoveryRequired are terminal. Other out-of-order events
are denied. Repeated arming cannot renew the deadline. A late apply/confirmation
acknowledgment is denied and returns RollbackRequired. A rollback outcome can also
be acknowledged directly at/after expiration; interruption still requires recovery.

Elapsed values are monotonic durations since operation creation, not wall timestamps.
They cannot be negative or decrease. Confirmation one tick before expiry can succeed;
at the exact deadline it is too late. The model never polls time itself. Restart
cannot safely reset this clock or reconstruct authority from an in-memory session;
recovery requires protected journal and kernel reconciliation.

Always retain `transition.Session`, even if `Accepted` is false: expiration can advance
the returned phase to RollbackRequired while rejecting a late acknowledgment. Other
denials return the unchanged original session. Old session instances remain immutable;
callers must serialize transitions and must not replay from an old instance. There is
no concurrency control, durability or cross-restart replay prevention in this library.

## Stable denial codes

| Code | Meaning |
| --- | --- |
| `event.unknown` | Undefined event enum value. |
| `time.invalid` | Negative elapsed duration. |
| `time.regressed` | Elapsed time precedes the session's incorporated time. |
| `binding.mismatch` | Operation, ownership, revision, artifact or timeout differs. |
| `watchdog.required` | Arming omitted the watchdog identity. |
| `watchdog.mismatch` | An event substituted a different watchdog identity. |
| `phase.terminal` | A terminal operation cannot be changed. |
| `deadline.expired` | Apply/confirmation or another non-recovery acknowledgment arrived too late. |
| `time.overflow` | Arming would overflow the elapsed-time deadline. |
| `phase.invalid` | The acknowledgment is not allowed in the current phase. |

Validation follows this table's order except `time.overflow`, which applies only to
an otherwise valid arming transition. Null plans/evidence/digests throw
`ArgumentNullException`; malformed constructor input throws `ArgumentException` or
`ArgumentOutOfRangeException` as documented in the public XML contracts.

These are in-process contracts, not a wire protocol. A future transport must reject
unknown fields and must authenticate/authorize callers before accepting acknowledgments.
Unit tests establish transition behavior only. The independent watchdog, durable
confirmation/timeout decision, owned-state replacement and real packet recovery need
separate implementation and isolated conformance testing before host apply is enabled.
