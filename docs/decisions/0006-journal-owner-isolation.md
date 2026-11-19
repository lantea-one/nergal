# ADR 0006: journal owner/type checks and disposable service-UID isolation

- Status: accepted
- Date: November 18, 2026

## Decision

Require journal directory, database and known SQLite sidecars to belong to the
process's effective Linux UID. Inspect metadata with statx using no-follow/no-automount
flags and require the requested type/mode/owner/link-count fields to be available.
Reject symbolic links, non-directory state roots, non-regular database/sidecar nodes,
and file link counts other than one. Mode requirements remain 0700/0600. Missing
metadata support fails closed; there is no weaker stat fallback or automatic chmod,
chown, unlink or repair. These checks precede SQLite opening the database.

This strengthens misconfiguration/foreign-inode denial, including when tests run
with namespace-local DAC override privileges. It does not remove the trusted-parent
requirement from ADR 0004, supply openat/VFS confinement, defend against a malicious
same-account/root actor, or establish production enrollment and live kernel ownership.
SQLite and the native compiler remain independent of Web. No service account, group,
production path, firewall or production credential is changed by this milestone.

## Conformance boundary

Add a storage-only fixture using fresh user/network namespaces and the invoking
user's existing subordinate UID/GID allocations. Namespace UID 0 represents the
agent; UID 1 represents an unprivileged browser account. The browser child drops UID,
GID and effective capabilities before access checks. It must be unable to read/write
the database, create state files, rename/unlink the private state directory or replace
the database. Agent-side probes must reject foreign-owned directory/database/sidecars,
hard-linked files and FIFO nodes without modifying their targets. Restoring fixture
metadata must allow the original state to reopen unchanged.

The fixture is opt-in and uses newuidmap/newgidmap; failure to create the mapping is
a failure, never a host-account or privilege fallback. Its small managed probe has no
network/firewall or arbitrary command functionality. The Python harness owns only
synthetic files in its private disposable tree. It does not use Docker or a host bus.

## Remaining boundary

The tested UID separation is an OS filesystem boundary, not browser authorization,
authenticated transport or an installable production service model. General resource
identity/reconciliation, protected enrollment, production daemon privilege distribution,
transport authorization and cross-reboot recovery remain separate milestones.

## Sources

- [Linux statx contract](https://man7.org/linux/man-pages/man2/statx.2.html)
- Linux UAPI struct/field offsets and mask definitions in linux/stat.h.
