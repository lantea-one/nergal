# Architecture

The first milestone is an independently implemented, nftables-first management
application, not a new packet-filtering engine. The kernel continues to enforce
policy when the web console or identity provider is unavailable.

## Boundaries

1. MVC owns HTTP controllers and conventional views. Blazor provides reusable
   interactive components. Neither is a privileged firewall agent.
2. The core contains typed policy concepts, requirements, validation results and
   capability contracts. It has no knowledge of a particular site's addresses,
   authentication directory or deployment system.
3. The unprivileged `Nergal.Nftables` compiler produces deterministic, create-only
   candidates from schema 1 input-filter policies (see [the contract](policy.md)).
   It performs no host operations and the web host does not reference it.
   Kernel JSON is an observation/command interface, not a lossless replacement
   for source metadata, comments and named definitions.
4. A future restricted agent validates owned-table operations and executes
   narrow native nftables transactions. It will not accept arbitrary shell scripts.
5. `Nergal.LocalState` persists explicit enrollment assertions, exact artifacts and
   replayable transitions in a private SQLite journal. Transactions serialize
   confirmation/timeout and commit revisions with confirmation. It has no kernel
   access and is not referenced by Web. See [the journal contract](local-journal.md).
6. Core now models ownership/revision/artifact bindings and confirmed-apply state
   transitions (see [the contract](confirmed-apply.md) and ADR 0003). This is a pure
   model with no timer, watchdog or executor. Future coordination must
   validate a complete candidate, snapshot owned state, arm local rollback, apply
   atomically, verify and confirm. Revisions and runtime state need explicit
   reconciliation even with a durable journal.
7. `Nergal.LocalTransport` serves/queries only bounded versioned read-only status intent.
   Accepted Unix sockets are authorized by kernel peer UID before parsing or
   provider access. Clients verify kernel server UID before sending intent and
   require a complete bounded reply/EOF. `Nergal.Linux` shares no-follow metadata with LocalState.
   The journal derives status revision/binding/classification in one protected read
   snapshot; native collection remains a separate trusted caller obligation.
   Neither infrastructure library is referenced by Web. No production daemon,
   collector or apply API is installed; see [the protocol](local-status-protocol.md).
8. `Nergal.Identity` provides separate private local application-account storage
   and standard Identity password/lockout verification. Explicit bootstrap creates
   at most one administrator; no default account or public registration exists.
   Its framework/database types remain outside Core. Web has no reference yet and
   issues no identity session; see [the contract](local-administrator-accounts.md).
   A separate protected Data Protection provider now persists encrypted session
   keys, rejects partial/ambient key loading and refreshes existing protectors on
   appended revocation; see [the key contract](protected-session-keys.md).

Do not treat a capability declaration as evidence that a driver is implemented,
connected, authorized or healthy. The capability contracts prevent lossy
backend selection; the compiler implements only the subset in ADR 0002, not all
features represented by capability enums. No privileged agent exists. The read-only
web foundation uses an ephemeral, application-scoped Data Protection provider
to avoid creating or sharing machine-wide keys. Durable authenticated releases
will require an explicit persisted and protected key store before session support.

## Optional site integration

OIDC identity providers, group names, agent endpoints and revision storage are
configuration concerns. A deployment can select AD-backed Keycloak roles, but
basic installations must not require that infrastructure. Unsupported or unknown
policy semantics must fail closed. Raw shell execution is not an extension API.

## Future adapters

A backend interface is a boundary, not a commitment to multiple implementations.
Only native nftables is selected. A firewalld adapter would require its own
semantic conformance suite and an accepted decision record before implementation.
Do not edit firewalld-owned tables from a native adapter.

## Next milestone

The [test-only watchdog fixture](../tests/integration/watchdog/README.md) now exercises
independent process deadlines, worker/watchdog death and actual packet restoration
for a fixed synthetic resource. It is not an agent or a production replacement API.

Journal paths now verify effective UID ownership, regular node types, private modes
and single file links. The disposable UID fixture tests filesystem denial for an
unprivileged browser role; trusted parent paths remain required.

Typed identity markers and a strict empty-chain observation/receipt comparator now
bind boot, namespace, marker, handle and complete recognized state. They perform no
host operations. Schema 2 of LocalState persists explicit trusted expected receipts
and provides read-only reconciliation; bound-resource apply remains disabled. See
[the receipt contract](native-resource-receipts.md).

The status-only listener now has real separate-UID socket conformance, bounded
framing/provider deadlines and safe explicit pathname cleanup. The next boundary
is controller status integration with explicit deployment configuration and
application authorization; the peer-authenticated client now has independent
hostile-server conformance. Receipt-aware apply/recovery remains a later milestone.
The user selected local administrator/password authentication with optional OIDC.
The credential and protected session-key foundations are implemented as libraries.
Next add HTTPS-only login/logout, CSRF, rate limiting, per-account revocation and isolated HTTP tests
before protected status routes. The read-only scaffold still uses ephemeral keys.
Protected receipt binding is not production enrollment authority. Keep Web
disconnected from privileged execution. Production enrollment, reboot recovery and arbitrary snapshots
need their own design and conformance evidence. NAT, forwarding, connection state and
IPv6 neighbor discovery remain outside the tested input-filter slice.
