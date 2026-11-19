# ADR 0011: classify local resource status from one protected snapshot

- Status: accepted
- Date: November 19, 2026

The test status provider currently reads enrollment revision, receipt presence and
receipt comparison in separate journal transactions. Each read is valid alone,
but concurrent binding or legacy confirmation can mix generations in one reply.
Add a journal status query that reads enrollment, bound marker and receipt in one
SQLite read transaction and derives the typed reply from that protected snapshot.

Keep authorization and native collection outside LocalState. The caller supplies a
complete immutable observation and trusted current namespace under its resource
lock. Missing/unrecognized observations produce unavailable for bound resources,
never a fabricated match. An idle unbound enrollment can report unbound with its
snapshot revision, but an active/recovery-blocked operation or changed boot on an
unbound enrollment produces unavailable without metadata. Corrupt receipt bindings
remain errors rather than falling back to unbound.

This API makes no writes, repairs or kernel operations and does not enable bound
apply. Its snapshot is advisory read-only status, not a lock/CAS token or authority
to mutate the kernel. Native observation and database state are separate systems;
no claim of atomicity against external privileged kernel writers is introduced.
