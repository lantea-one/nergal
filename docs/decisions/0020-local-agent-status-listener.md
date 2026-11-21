# ADR 0020 — Per-resource execution lock and local agent status listener

- Status: accepted
- Date: November 21, 2026

## Decision

Add `ResourceExecutionLock` to `Nergal.LocalState` to serialize native kernel operations
and protected journal decisions across processes for one private state directory.
Validate the directory with `PrivateJournalPath` and inspect `resource.lock` via
no-follow `LinuxNodeMetadata` (requiring a regular `0600` single-link file owned by
the effective UID) before opening and acquiring a byte-range file lock, paired with an
in-process directory gate so same-process callers serialize cleanly without overlapping
file descriptors.

Extend `nergal-agent` with `status-serve ABSOLUTE_PRIVATE_JOURNAL_DIRECTORY ABSOLUTE_SOCKET_PATH ALLOWED_PEER_UID [SOCKET_GROUP_ID]`
and hold `ResourceExecutionLock` during both `enroll` and read-only status queries.
Before binding `UnixStatusServer`, verify that the private journal opens cleanly and the
current Linux network namespace inode is readable. Configure the listener with one
explicit peer UID and no implicit root exception.

On each authorized status query, acquire `ResourceExecutionLock`, collect a read-only
full snapshot via `/usr/sbin/nft --json list table inet nergal_filter` using fixed
arguments and an empty environment, and classify status in one SQLite read transaction
through `ApplyJournal.ReadResourceStatus`. Map missing/unsupported observations, lock
contention, or storage failures to metadata-free `unavailable`, and remove only the
owned socket inode on `SIGINT` or `SIGTERM`.

## Remaining boundary

`nergal-agent status-serve` exposes only the bounded version-1 read-only `status`
protocol. Confirmed apply, replacement, watchdog execution, remote mTLS transport,
and systemd service installation remain separate milestones.
