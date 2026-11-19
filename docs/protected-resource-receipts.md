# Protected expected receipt persistence

Schema 2 of `Nergal.LocalState` stores an immutable expected native receipt and a
separate persistent bound marker. This extends [native receipt comparison](native-resource-receipts.md)
and the [private journal](local-journal.md), following [ADR 0008](decisions/0008-protected-resource-receipts.md).
No API here executes kernel operations, proves exclusive creation, adopts a table or
authorizes a request. Web does not reference this infrastructure library.

## Binding and reconciliation

`BindExpectedResource(ownership, expected, actual, currentNamespace)` is an explicit
trusted bootstrap assertion after exclusive resource creation. It requires:

- Exact enrolled agent/owner/revision and no active or recovery-blocked operation.
- Current boot equal to the protected enrolled boot; expected identity belongs to
  the enrolled owner, and expected receipt matches the full actual observation/context.
- A canonical empty-chain candidate reconstructed from the observation/identity
  exactly equal to the protected baseline artifact. Unsupported/rule-bearing
  observations cannot enter this limited binding API.
- No different existing binding. Identical retries return the same receipt; rejected
  state is never promoted into a replacement expected receipt.

Receipt, bound marker and enrolled revision binding commit together. The expected
receipt must originate in trusted exclusive-creation evidence, not browser claims.
The caller must hold the resource execution lock across trusted complete observation
and the storage decision. This library cannot establish snapshot completeness or
close races with another privileged kernel writer.

`ReadExpectedResource()` returns the verified stored receipt or null only when never
bound. A missing receipt on a marked resource, an unexpected receipt on an unmarked
resource, malformed fields or inconsistent owner/boot/revision is corruption.
`VerifyExpectedResource(actual, currentNamespace)` loads that protected receipt and
compares the observation using a locally sampled boot identity. It returns all native
receipt mismatch codes; missing binding throws `resource.unbound`. Drift never repairs,
clears, reenrolls or updates state. The current namespace argument must be trusted local
context, not request data. Matching assertions are still not authorization.

Once bound, `Start` rejects legacy operations with `resource.boundApplyUnavailable`.
A database trigger also blocks operation insertion on a marked resource, including
an older queued writer. Receipt-aware apply, replacement/rollback receipt updates and
their crash ordering are absent. Keeping them disabled prevents revision changes
from leaving stale protected authority behind. There is no unbind/reset/recovery bypass.

Additional binding errors are `ownership.stale`, `resource.busy`, `clock.bootChanged`,
`resource.receiptMismatch`, `resource.baselineMismatch` and `resource.alreadyBound`.
Invalid stored evidence is `journal.corrupt`; standard argument exceptions apply to
missing programming arguments. Native observation/comparison errors retain their
[documented codes](native-resource-receipts.md).

## Schema-1 upgrade

Initialize creates schema 2. Normal Open rejects schema 1 without changing it.
`ApplyJournal.UpgradeFromVersion1(directory, clock)` is an explicit offline upgrade:
stop **all older writers/watchdogs first**. It rejects active/recovery-blocked state
with `migration.activeOperation`, verifies the legacy database and retained terminal
histories, and adds the bound marker, receipt table and legacy-insert guard together
with version 2 in one immediate transaction. Failures preserve schema 1 and history.
Active-state checks cannot prove process quiescence; live mixed-version upgrade is
unsupported. Normal current-version transactions recheck their schema under lock.

The upgrade does not create a resource binding, discard history or reset ownership.
Unknown versions, corrupt histories or unexpected concurrent version changes fail.
Existing event/phase numeric identifiers are now explicitly assigned and documented
as persisted contracts; they must not be renumbered. The migration fixture uses literal
schema-1 identifiers so changes to current enum declarations cannot rewrite history
unnoticed. No repository startup code automatically upgrades an operator's database.

## Evidence and remaining boundary

Unit tests use real private SQLite files for binding, reopen/idempotence, stale/invalid
claims, corruption/missing marked receipts, database-level legacy denial and successful
or failed migration without data loss. The [native binding fixture](../tests/integration/enrollment/README.md)
checks actual namespace resources, copied markers, drift, cross-namespace rejection and
unchanged protected bytes/foreign tables. Existing packet/watchdog/UID fixtures remain
separate evidence for their constrained resources.

Protected intent/receipt persistence is implemented. Production exclusive-creation
authority, arbitrary rule observation, receipt-aware apply/recovery, external-writer
atomicity, reboot reconciliation, authenticated transport and production service
installation remain unimplemented. Same-account/root and hostile-parent limitations
from the local journal still apply.
