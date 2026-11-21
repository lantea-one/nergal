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
4. `Nergal.Agent` provides offline local operator enrollment
   (`nergal-agent enroll ABSOLUTE_PRIVATE_JOURNAL_DIRECTORY`,
   [ADR 0019](decisions/0019-local-agent-enrollment.md)), the peer-authorized
   read-only status listener (`nergal-agent status-serve`,
   [ADR 0020](decisions/0020-local-agent-status-listener.md)), and local operator
   receipt-aware confirmed-apply, watchdog, and boot-reconciliation commands
   (`prepare`, `watch`, `apply`, `confirm`, `reconcile`,
   [ADR 0023](decisions/0023-explicit-boot-reconciliation.md)). All mutate/observe
   operations serialize with `ResourceExecutionLock`. Enrollment generates fresh
   ownership and table identities locally, commits the empty `accept` baseline
   intent before invoking `/usr/sbin/nft`, parses `ParseEnrollmentEcho`, and verifies
   an independent full listing before binding. Confirmed apply validates complete
   atomic delete+create replacement candidates, arms an independent `watch` process
   before mutating the kernel, binds candidate/rollback handles via `ParseReplacementEcho`,
   and restores packets automatically on timeout. It accepts no arbitrary shell scripts
   or browser-supplied native commands.
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
   Web uses only the status client for its opt-in [controller route](controller-status.md). No production daemon,
   collector or apply API is installed; see [the protocol](local-status-protocol.md).
8. `Nergal.Identity` provides separate private local application-account storage
   and standard Identity password/lockout verification. Explicit bootstrap creates
   at most one administrator; no default account or public registration exists.
   Its framework/database types remain outside Core. Web can enable [local administrator sessions](local-sessions.md) over direct HTTPS.
   A separate protected Data Protection provider now persists encrypted session
   keys, rejects partial/ambient key loading and refreshes existing protectors on
   appended revocation; see [the key contract](protected-session-keys.md).

Do not treat a capability declaration as evidence that a driver is implemented,
connected, authorized or healthy. The capability contracts prevent lossy
backend selection; the compiler implements only the subset in ADR 0002, not all
features represented by capability enums. No privileged agent exists. The default scaffold uses ephemeral Data Protection.
The enabled session host requires explicitly protected, persistent keys.

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

Typed identity markers and a strict observation/receipt comparator for empty chains,
family-wide rules, and complete schema-1 input-filter policies (CIDR addresses, TCP/UDP/ICMP/ICMPv6,
and TCP/UDP destination ports per [ADR 0021](decisions/0021-observe-schema1-filter-rules.md)) now
bind boot, namespace, marker, handle and complete recognized state. They perform no
host operations. Schema 3 of `Nergal.LocalState` persists explicit trusted expected receipts,
provides read-only reconciliation, and adds receipt-aware bound-resource journal operations
(`StartBound`, `RecordCandidateAppliedBound`, `ConfirmBound`, `RecordRollbackSucceededBound`,
[ADR 0022](decisions/0022-receipt-aware-journal.md)) while keeping legacy unbound `Start` blocked. See
[the receipt contract](native-resource-receipts.md).

The status-only listener now has real separate-UID socket conformance, bounded
framing/provider deadlines and safe explicit pathname cleanup. The peer-authenticated client has independent
hostile-server conformance. Receipt-aware apply/recovery remains a later milestone.
The user selected local administrator/password authentication with optional OIDC.
Local HTTPS login/logout, antiforgery, rate limiting and per-account revocation
are implemented with isolated Kestrel conformance. The opt-in controller status
route uses that session boundary and an explicitly configured shared socket. An optional [OIDC login](federated-login.md) grants administrator access from
exact configured groups, with distinct issuer/subject identities and a fifteen-minute maximum.
Protected receipt binding and offline local operator enrollment (`nergal-agent enroll`)
are not production apply authority or automated recovery. Keep Web
disconnected from privileged execution. Production receipt-aware apply/rollback, reboot recovery and arbitrary snapshots
need their own design and conformance evidence. NAT, forwarding, connection state and
IPv6 neighbor discovery remain outside the tested input-filter slice.
