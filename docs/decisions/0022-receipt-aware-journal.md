# ADR 0022 — Receipt-aware journal operations for bound resources

- Status: accepted
- Date: November 21, 2026

## Decision

Advance `Nergal.LocalState.ApplyJournal` to SQLite schema 3 to support
receipt-aware confirmed-apply lifecycles on bound resources while keeping legacy
unbound `Start` disabled. Add explicit offline `UpgradeFromVersion2(directory, clock)`
alongside `UpgradeFromVersion1`, preserving the existing requirement that callers stop
all older writers and never migrate active, recovery-blocked, or corrupt journals.

Add `bound_operations` to track per-operation baseline receipts, candidate creation-echo
receipt bindings, and an immediate-transaction `allow_insert` guard so the
`bound_resource_no_legacy_start` and `enrollment_no_legacy_start` triggers continue
blocking legacy `Start` and raw `INSERT INTO operations` attempts on bound or
intent-enrolled journals.

Add four serialized journal transitions for bound operations:
- `StartBound`: verifies `resource_bound == 1`, active boot, ownership, live
  `VerifyExpectedResource`, and exact schema-1 compiler reconstruction of the live
  observation against the enrolled rollback artifact before reserving the operation.
- `RecordCandidateAppliedBound`: verifies the candidate creation-echo receipt matches
  the complete candidate listing in the enrolled namespace and compiles back to the
  operation's exact candidate artifact before recording `AwaitingConfirmation` and
  persisting candidate handle/digest bindings.
- `ConfirmBound`: verifies a live full listing matches the recorded candidate receipt
  and artifact before deadline, then atomically commits `Confirmed`, advances
  `enrollment.revision`/`artifact`/`digest`, and updates `resource_receipt`
  (`revision`, `handle`, `digest`) in one transaction.
- `RecordRollbackSucceededBound`: verifies a restored creation/replacement-echo
  receipt matches the complete restored listing and compiles back to the exact
  rollback artifact, then commits `RolledBack` and updates `resource_receipt`
  (`handle`, `digest`) without advancing `enrollment.revision`.

Legacy `Advance` rejects `CandidateApplied`, `Confirm`, and `RollbackSucceeded` on
bound operations with `resource.boundReceiptRequired` so callers cannot mutate kernel
state without supplying verified native receipts.

## Remaining boundary

`Nergal.LocalState` still executes no `/usr/sbin/nft` commands and supplies no
replacement echo parser or agent apply/watchdog orchestration; those belong to Phase 5
(`ADR 0023`).
