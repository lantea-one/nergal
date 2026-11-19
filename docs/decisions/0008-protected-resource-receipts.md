# ADR 0008: protected receipt persistence and read-only reconciliation

- Status: accepted
- Date: November 18, 2026

## Decision

Extend the Linux local journal to schema 2 with an immutable expected native resource
receipt bound to the enrolled revision, with a separate persistent bound marker.
A missing receipt on a marked resource is corruption, never an unbound fallback. Keep receipt persistence and reconciliation
unprivileged: no kernel operations, resource adoption, authenticated transport or
bound-resource apply is added. The LocalState infrastructure library may reference
the native backend; Core remains free of host/database/framework dependencies.

Binding is an explicit trusted bootstrap assertion after exclusive resource creation,
not an automatic consequence of observing a familiar name/comment. Require exact
enrolled agent/owner/revision, no active operation, matching current/enrolled boot,
matching supplied expected receipt and complete actual observation/context, and a
canonical compiler reconstruction equal to the protected baseline artifact. This
slice supports only the observer's empty-chain resource. Existing identical bindings
may be retried; a different binding is refused rather than overwriting expected state.

Read-only reconciliation loads the expected receipt from private transactional state
and compares a trusted complete observation against its boot/namespace/identity/
handle/fingerprint bindings. Missing receipts, invalid stored fields and drift fail
closed. A failed comparison never promotes actual state to expected state or repairs
the journal. The trusted collector must hold the resource execution lock across local
observation and this decision; these APIs do not close external privileged-writer races.

## Prevent stale authority

Once a receipt is bound, the legacy Start API refuses all applies. A database trigger
also blocks operation insertion, including an older queued writer. Receipt-aware apply,
new expected receipts after replacement/rollback, and their kernel/journal crash
ordering are unimplemented. Keeping the old apply path enabled would permit revision
changes without a matching protected resource receipt. Read-only classification is
the entire implemented bound-resource contract.

## Explicit migration

Initialize creates schema 2; normal Open rejects schema 1 without modifying it. Provide
an explicit schema-1 upgrade whose caller must stop all older writers first. It
requires no active or recovery-blocked operation,
checks legacy application/schema/integrity and every retained terminal history, creates
the receipt table and advances schema version in one immediate transaction. Never
migrate while an old watchdog may need its journal. Active-state checks cannot prove
process quiescence; live mixed-version migration is not supported. Unknown/corrupt state or concurrent
version changes abort; failures leave the old schema/history unchanged. No production
or user journal is automatically upgraded by repository code or tests.

## Verification and remaining boundary

Unit tests use actual private SQLite files for binding/reopen, identical retry, stale
or mismatched assertions, receipt corruption, no-rebind behavior, legacy-path denial,
quiescent migration and failed migration without data loss. A disposable native fixture
records a protected intent before exclusive create, binds/opens/reconciles its receipt,
and rejects policy drift, copied-marker replacement, conflicting foreign resources and
a second actual namespace without kernel writes from the managed probe.

This does not establish production enrollment authority, external-writer atomicity,
bound-resource apply/recovery, cross-reboot reconciliation, arbitrary-rule snapshots,
service installation or authenticated agent transport. Those remain explicit milestones.
