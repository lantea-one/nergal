# ADR 0004: private transactional local journal

- Status: accepted
- Date: November 18, 2026

## Decision

Add Nergal.LocalState, separate from Core and Web, to persist enrollment, exact
UTF-8 artifacts and replayable apply transitions in SQLite. This library performs
filesystem/database operations only. It does not execute nft, establish live kernel
ownership, authorize a request or run a watchdog. Initializing this prototype journal
records an explicit trusted bootstrap assertion, not permission to adopt a table.

Use immediate serializable write transactions, DELETE journal mode, synchronous
EXTRA, foreign keys, strict schema version 1 and parameterized SQL. Disable connection
pooling. Enrollment, operation history, content and transitions share one database;
confirmation updates the revision/artifact and releases the active operation in the
same transaction as the terminal event. Successful rollback releases the operation
without advancing revision. RecoveryRequired keeps the resource blocked. No API
silently deletes history, repairs corrupt state, resets ownership or skips recovery.

Before creating a new operation, require exact enrolled agent/owner/revision,
content digests and rollback bytes, no active operation, and an unused operation ID.
Transition history is replayed through the Core model on reads and verified against
recorded phase/error values. Missing/invalid/unknown data is rejected. Operations
are not hydrated by setting private session properties or by permissive JSON.
Phase-preserving deadline polls are not appended; meaningful transitions are finite.

Use a boot identity and monotonic time source sampled inside each write transaction,
after obtaining the database lock. Deadlines are based on Linux CLOCK_BOOTTIME,
including suspend time. Boot mismatch or clock regression blocks progress; there is
no automatic cross-reboot recovery. A future watchdog must use the same protected
store to serialize timeout and confirmation, and hold a separate execution lock while
performing side effects. Database commit alone cannot make a kernel transaction and
journal update atomic. Crash reconciliation remains mandatory before host execution.

## Protection and durability limits

Require an explicitly created private directory with mode 0700 and database mode
0600. Reject symbolic links in the supplied path, wrong modes and missing databases;
normal open never creates/reinitializes a database. Creation uses exclusive file
creation with 0600 permissions. SQLite sidecars remain in the private directory.
The operator must provide a trusted local parent directory owned by the service
account. Same-account/root attackers, hostile parent renames, hard-link attacks,
network filesystems and broken storage synchronization are outside this prototype's
protection boundary. This is not a production privileged storage implementation.

Reject unsupported platforms and schema versions; do not disable durability pragmas
to make tests pass. Local storage must honor SQLite locking and sync requests. Tests
establish process/reopen/concurrency and failure behavior, not physical power-loss
or hardware durability. No production artifacts may be stored by repository tests.

## Next slice

Add an independent watchdog prototype limited to disposable user/network namespaces.
Use real process termination, serialized confirmation/timeout and real packet recovery
checks. Keep the compiler create-only and the web host disconnected. General owned-table
replacement and production enrollment/recovery remain separate security boundaries.

## Sources

- [Microsoft.Data.Sqlite transactions](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/transactions)
- [SQLite atomic commit and storage assumptions](https://www.sqlite.org/atomiccommit.html)
- [SQLite synchronous modes](https://www.sqlite.org/pragma.html#pragma_synchronous)
