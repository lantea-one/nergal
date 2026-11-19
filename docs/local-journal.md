# Private local apply journal

`Nergal.LocalState` schema 2 is a Linux-only persistence library separate from Core, the
compiler and Web. It stores trusted bootstrap enrollment assertions, artifact text,
operation bindings and replayable phase transitions in a private SQLite database.
It neither establishes live kernel ownership nor authorizes or executes firewall
changes. See [ADR 0004](decisions/0004-local-journal.md) for the storage threat boundary.

## API and safety contract

- `Initialize(directory, ownership, artifact, clock)` exclusively creates state in
  an existing absolute, nonsymlink 0700 directory with a trusted service-owned parent.
  The database is created with mode 0600. Existing databases or sidecars are refused.
  This explicit prototype bootstrap assertion does not adopt an existing firewall table.
- `Open` requires the database to exist, validates protection, application/schema
  identity and SQLite integrity, and never repairs, recreates or resets state.
  Schema 1 requires an explicit offline upgrade with all older writers stopped;
  see [protected receipt persistence](protected-resource-receipts.md).
  Directory/database/sidecar owners must equal the effective Linux UID. Symbolic
  links, unsafe modes, non-regular files and file link counts other than one are
  refused using no-follow statx metadata before SQLite opening.
- `ReadEnrollment`, `Read` and `ReadActive` expose consistent verified snapshots.
  Operation reads hash the exact artifacts and replay recorded phase changes through
  the Core model; unknown, inconsistent or out-of-order history is an error.
- `Start` uses an immediate transaction to reserve the sole enrolled resource. It
  requires exact enrolled agent/owner/revision, unused operation UUID, candidate and
  rollback hashes, and rollback bytes equal to the last-confirmed artifact. Artifacts
  are valid UTF-8 text, at most 1 MiB each. No raw SQL or shell extension exists.
- `Advance` samples the clock after taking the write lock. It evaluates the Core
  transition and atomically records phase changes. Confirmation advances the revision,
  replaces the confirmed artifact and releases the resource in one commit. Successful
  rollback releases it without advancing revision. RecoveryRequired keeps it blocked.
  A denied late confirmation still durably records RollbackRequired.

Phase-preserving polls are not appended. Their returned elapsed value is an observation,
not a durable heartbeat; subsequent writes sample the real monotonic clock under lock.
The library rejects clock regression against recorded transitions. Bound-resource
legacy starts are disabled; see the protected receipt contract for binding and
read-only reconciliation. Operation IDs and
history remain retained after completion; there is no pruning, reset, unenrollment or
recovery override API in this slice. Failed writes roll back the whole transaction.

`IJournalClock` enables explicit deterministic test clocks. Normal operation uses
64-bit Linux `CLOCK_BOOTTIME` and `/proc/sys/kernel/random/boot_id`; suspend consumes
the deadline and reboot changes its identity. A changed boot blocks new operations;
a changed boot or regressed clock during an active operation records RecoveryRequired.
Cross-reboot reconciliation is deliberately unimplemented.

## Diagnostics

Core transition denials retain their [existing codes](confirmed-apply.md). A
`JournalUpdate` always exposes the resulting entry, acceptance and denial code;
callers must retain the returned entry even when the requested event was denied.
Clock discontinuity returns `clock.bootChanged` or `clock.regressed` while durably
recording recovery. Invalid clock samples throw `clock.invalid` without changing state.

Routine reservation and storage failures throw `JournalException` with a stable `Code`:

| Codes | Meaning |
| --- | --- |
| `resource.busy`, `ownership.stale` | Resource is reserved/recovery-blocked, or enrollment/revision differs. |
| `operation.reused`, `operation.missing` | Operation UUID was previously used, or is absent. |
| `artifact.mismatch`, `artifact.tooLarge`, `rollback.mismatch` | Hash/size/last-confirmed bytes do not agree. |
| `journal.exists`, `journal.missing` | Explicit initialization conflicts, or existing state disappeared. |
| `journal.corrupt`, `journal.schemaOrIntegrity` | Semantic history/content failure, or schema/application/SQLite integrity failure. |
| `database.error`, `database.durability` | SQLite operation failed, or required durability settings are unavailable. |
| `path.absoluteRequired`, `path.directoryMissing`, `path.directoryMode` | The supplied state directory is not an acceptable private absolute path. |
| `path.owner`, `path.hardLink`, `path.type`, `path.metadataUnavailable` | Foreign UID, shared inode, wrong node type or unavailable required statx metadata. |
| `path.symlink`, `path.databaseMode` | A path redirects through a symbolic link, or database/sidecar permissions are unsafe. |

Missing programming arguments throw standard argument exceptions; malformed UTF-16
throws an encoding exception. Ordinary filesystem access errors remain IO/access
exceptions. Public diagnostics contain no artifact contents. Callers must avoid logging
private artifacts or request data when handling failures.

## Durability and protection limits

The store pins Microsoft.Data.Sqlite and its native dependencies through lockfiles.
Connections disable pooling and shared cache, enable foreign keys, and require DELETE
journal mode with synchronous EXTRA. It relies on SQLite's local filesystem locking
and storage synchronization guarantees. This is not a kernel/journal distributed
transaction, and it does not establish power-loss correctness on a particular device.

The caller must supply a trusted local service-owned parent and protect the service
account. Same-account/root attackers, hostile parent renames or inode swaps, untrusted
network filesystems and broken hardware flush semantics are outside the prototype's
protection boundary. Owner/type/mode/link checks are not a substitute for production
openat/VFS confinement or a trusted service-owned parent. The library is not a
production privileged agent.

The separate [watchdog fixture](../tests/integration/watchdog/README.md) now tests
process death/reopen and real packet recovery for fixed synthetic namespace resources.

Unit tests use synthetic artifacts and actual private temporary databases. They
exercise reopen, real concurrent writers, tampering, permissions, symlinks, stale
bindings, operation replay and exact-deadline races. They do not kill processes,
restore packets or prove hardware durability. Production installation/path confinement
and general owned-resource reconciliation remain separate unimplemented boundaries.
The [UID-isolation fixture](../tests/integration/isolation/README.md) tests actual
filesystem denial between distinct mapped local UIDs without creating host accounts.
