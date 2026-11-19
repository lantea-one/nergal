# Journal filesystem account isolation

After the pinned SDK Release build:

```sh
bash tests/integration/isolation/check.sh
```

Requires 64-bit Linux, Python 3, .NET, unprivileged user/network namespaces,
newuidmap/newgidmap and existing subordinate UID/GID allocations for the invoking
user. The fixture fails if unavailable; it does not create host accounts, change
subordinate-ID configuration, use Docker or fall back to host privileges. Some
execution sandboxes prohibit setuid-helper capabilities and require the normal
sandbox approval for this rootless namespace command.

The harness creates fresh user/network namespaces and synthetic temporary state.
Namespace UID 0 acts as the agent and UID 1 as the browser role. A child drops UID/GID,
clears supplementary groups where permitted, then execs a fresh interpreter so it
retains no private parent-process artifact memory. It must have zero effective
capabilities. It can write its own state but cannot read/write/unlink/replace the
agent database, create files in the agent directory or rename that directory.

Agent-side probes then verify explicit owner denial for the directory, database and
all known SQLite sidecars, including with namespace-local DAC override privileges.
Hard-linked database inodes and FIFO nodes are refused before SQLite opening. The
original database bytes remain unchanged and reopen after fixture metadata is restored.
No network traffic or firewall operations occur; the managed probe references only
the local storage library. No credentials, host account data or topology are fixtures.

This establishes a filesystem boundary for distinct local UIDs in the tested setup.
It does not establish browser authentication, transport authorization, hardened
openat/VFS confinement, production service installation, kernel resource ownership,
or protection from a malicious same-account/root actor. Trusted service-owned parent
paths and local storage synchronization remain required. Default CI runs the unit
cases; this subordinate-ID conformance fixture is opt-in.
