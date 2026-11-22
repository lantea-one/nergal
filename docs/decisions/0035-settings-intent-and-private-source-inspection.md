# 0035. Settings intent and private native source inspection

- Status: accepted
- Date: 2026-11-22

## Decision

System settings persist validated operator intent and an atomic append-only audit
entry. Management appearance uses the saved branding. Stored authentication,
database, and firewall preferences do not hot-reconfigure runtime services; the UI
must state this explicitly. LDAP, PostgreSQL, and MariaDB adapters remain absent.
A latest saved policy is not an active policy on every host. Protected deployment
configuration continues to own authentication, session security, and actual stores.

Stored settings reject duplicate/unknown properties, missing/null sections, invalid
bounds, and malformed text. Corrupt persisted settings produce `settings.corrupt`
rather than silently resetting security-related intent to defaults. A login banner
is saved intent until a dedicated login integration is implemented.

An explicitly configured trusted native source directory is snapshotted with strict
file/count/size bounds. Only authenticated Administrators can inspect the escaped
source; Auditors are denied. HTTP input cannot select filesystem paths. Source text
is never dispatched to an agent or shell. The feature is absent from the default
unconfigured host. Private exports and their content bindings stay outside tracked
files and public screenshots. Directory parents must remain operator-controlled.

Local development uses an unprivileged controller container and independent
network-isolated check-only workers. Neither the UI nor the workers can alter a
production firewall. Native validation outcomes are not migration-equivalence or
packet-enforcement claims. See [sandbox operation](../local-sandbox.md).
