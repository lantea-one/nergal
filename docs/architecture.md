# Architecture

Selected saved revisions support deterministic native and complete intent
[exports](policy-exports.md), verified against the persisted candidate digest.
These read-only derived artifacts carry no ownership/apply authority or runtime
observations. See [ADR 0049](decisions/0049-saved-revision-exports.md).

The first milestone is an independently implemented, nftables-first management
application, not a new packet-filtering engine. The kernel continues to enforce
policy when the web console or identity provider is unavailable.

The product target is a general-purpose FOSS firewall manager for independent
single-host and optional multi-host installations. The initial private deployment
is one acceptance environment. Its topology and integrations must not define core
contracts, defaults, required infrastructure or the limits of public conformance.
See [product scope](product-workflow.md).

## Boundaries

1. MVC owns HTTP controllers and conventional views. Blazor provides reusable
   interactive components. Neither is a privileged firewall agent.
2. The core contains typed policy concepts, requirements, validation results and
   capability contracts. It has no knowledge of a particular site's addresses,
   authentication directory or deployment system.
3. The unprivileged `Nergal.Nftables` compiler produces deterministic, create-only
   candidates from schema 1 input-filter and schema 2 stateful/rate-limited policies
   (see [the contract](policy.md), [ADR 0024](decisions/0024-stateful-forwarding-and-icmpv6-policy.md),
   [ADR 0025](decisions/0025-native-per-source-rate-limiting.md),
   `NftNatCompiler` / [ADR 0026](decisions/0026-dual-stack-nat-and-original-tuple-matching.md),
   and `NftBridgeCompiler` + `NftPolicyBundleCompiler` / [ADR 0027](decisions/0027-bridge-filtering-and-atomic-multitable-transactions.md)).
   It performs no host operations; `Nergal.Web` references it strictly in-memory for
   candidate compilation and diff previewing ([ADR 0030](decisions/0030-web-policy-authoring-and-audit-views.md)).
   Kernel JSON is an observation/command interface, not a lossless replacement
   for source metadata, comments and named definitions.
4. `Nergal.Agent` provides offline local operator enrollment
   (`nergal-agent enroll ABSOLUTE_PRIVATE_JOURNAL_DIRECTORY`,
   [ADR 0019](decisions/0019-local-agent-enrollment.md)), the peer-authorized
   read-only status listener (`nergal-agent status-serve`,
   [ADR 0020](decisions/0020-local-agent-status-listener.md)), authenticated
   local and remote control listeners (`control-serve` and `tls-serve`,
   [ADR 0028](decisions/0028-authenticated-agent-control-protocol.md)), and local operator
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
7. `Nergal.LocalTransport` serves/queries both bounded versioned read-only status intent
   (`UnixStatusServer`/`UnixStatusClient`) and typed control exchanges
   (`UnixControlServer`/`UnixControlClient`). Accepted Unix sockets are authorized by
   kernel peer UID before parsing or handler dispatch. Clients verify kernel server UID
   before sending intent and require a complete bounded reply/EOF. `Nergal.RemoteTransport`
   (`TlsControlServer`/`TlsControlClient`) provides remote agent control strictly over
   TLS 1.3 with required client certificates and constant-time SHA-256 leaf thumbprint
   pinning, EKU validation, and validity-window enforcement without ambient root CA trust.
   `Nergal.Linux` shares no-follow metadata with LocalState.
   The journal derives status revision/binding/classification in one protected read
   snapshot; native collection remains a separate trusted caller obligation.
   Web uses only the status client for its opt-in [controller route](controller-status.md).
   See [the protocol](local-status-protocol.md) and
   [ADR 0028](decisions/0028-authenticated-agent-control-protocol.md).
8. `Nergal.Identity` provides separate private local application-account storage
   and standard Identity password/lockout verification. Explicit bootstrap creates
   at most one local account with an explicit controller role (`nergal:administrator`
   or `nergal:auditor`); no default account or public registration exists.
   Its framework/database types remain outside Core. Web can enable [local administrator sessions](local-sessions.md) over direct HTTPS.
   A separate protected Data Protection provider now persists encrypted session
   keys, rejects partial/ambient key loading and refreshes existing protectors on
   appended revocation; see [the key contract](protected-session-keys.md).
9. `Nergal.ControllerState` persists registered managed agent hosts, monotonic
   policy bundle revisions, and an append-only audit log in a private `0700`/`0600`
   SQLite WAL store (`controller.db`) separated from `accounts.db` and agent
   `journal.db`. SQLite triggers prevent `UPDATE` or `DELETE` on `audit_log`, and
   `Nergal.Web` maps `ControllerAuthorizationPolicies` (`NergalAdministrator` and
   read-only `NergalReader`) across both local and OIDC sessions with explicit
   `local:<uuid>` and `oidc:<issuer>:<subject>` actor attribution
   ([ADR 0029](decisions/0029-controller-persistence-rbac-and-audit.md)).
10. When `ControllerState:Enabled` and `LocalSessions:Enabled` are active, `Nergal.Web`
   provides the RBAC-gated fleet dashboard, typed policy bundle editor with
   `BackendCompatibilityEvaluator` checks, deterministic nftables candidate line diff
   preview, and audit/revision history viewer (`/manage`, `/manage/policies`,
   `/manage/audit`, [ADR 0030](decisions/0030-web-policy-authoring-and-audit-views.md)).

Do not treat a capability declaration as evidence that a driver is implemented,
connected, authorized or healthy. The capability contracts prevent lossy
backend selection; the compiler implements only the subset in ADR 0002, not all
features represented by capability enums. The default scaffold keeps agent integration disabled and uses ephemeral Data Protection.
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
disconnected from privileged execution: [ADR 0031](decisions/0031-two-phase-web-confirmed-apply.md)
routes `/manage/apply*` and `/controller/apply/*` through `ApplyWorkflowService`
and `IAgentControlDispatcher`, sending typed `AgentControlRequest` frames over
`UnixControlClient` (`SO_PEERCRED` peer-UID check) or `TlsControlClient`
(pinned TLS 1.3 mTLS with owner-only `0600` client private keys) to an isolated
`nergal-agent control-serve` or `tls-serve` process. Single-table `FilterPolicy`
and multi-table `FirewallPolicyBundle` (`inet nergal_filter`, `inet nergal_nat`,
and `bridge nergal_bridge`) revisions dispatch via two-phase `prepare-apply` /
`confirm` / `rollback`, synchronizing host revision metadata and recording
`apply.start`, `apply.confirm`, and `apply.rollback` in `audit_log` (see
`docs/decisions/0032-multitable-agent-confirmed-apply.md`). On the agent side,
`ReplaceAndVerifyAsync`, `WatchAsync`, and `AgentControlHandler` inspect auxiliary
table presence and ownership (`nft --terse --json list tables`), fail closed on
unowned table collisions or auxiliary drift, validate coordinated multi-table
`--echo --handle --json` receipts, and remove or restore `inet nergal_nat` and
`bridge nergal_bridge` atomically during rollback while preserving foreign tables.

## Router authoring and private import boundary

[ADR 0034](decisions/0034-router-constructs-rpfilter-mss-mac-negation-masquerade-bridge.md)
extends typed filter/NAT models with raw prerouting, MSS, MAC pinning, destination
meters, negation, and masquerade/return. Extended bridge and independent early inet
tables use complete receipt-bound confirmed apply under ADR 0036.
See [support and verification limits](router-constructs.md). No arbitrary native
source is accepted as an agent execution payload.

[ADR 0035](decisions/0035-settings-intent-and-private-source-inspection.md) separates
persisted settings intent from protected runtime configuration. Management appearance
uses saved branding; stored auth/database/firewall choices do not hot-reconfigure
services. Optional administrator-only operator source staging snapshots private
operator-controlled files and never executes them. The [local sandbox](local-sandbox.md)
uses separate containers for the unprivileged UI and native check-only workers.

Complete multi-table observation and confirmed apply are implemented under
[ADR 0036](decisions/0036-complete-bundle-observation-and-rollback.md). A composite
receipt includes complete owned NAT, bridge and early inet state rather than only
auxiliary ownership comments. Packet and recovery acceptance includes dual-stack
bridge pinning, priority ordering, controller loss, watchdog restart and drift denial. [The product workflow](product-workflow.md) tracks
the ordered UI, migration and profile work without treating saved intent as live
runtime configuration.

Private native migration review is an unprivileged, bounded lexical inventory
([ADR 0037](decisions/0037-private-native-migration-review.md)). It never invokes
nft, resolves external files or returns a partial policy. The administrator-only
report route selects an existing immutable database source by canonical identity,
never a request-supplied path. Directory snapshots are optional staging inputs. A source-bound inventory cannot authorize apply or certify
conversion. Exact sources and exported reports remain private.

Native source ingestion now persists immutable exact UTF-8 snapshots and attributed
audit entries transactionally (introduced in controller schema 2, retained in schema 3). The optional operator file
catalog is staging only. Web uploads never execute source text, and original-file
downloads use the verified database snapshot. Existing controllers require explicit
offline `controller upgrade`; no additional SQL adapter is introduced. See
[source library](native-source-library.md) and [ADR 0038](decisions/0038-database-native-source-snapshots.md).

Timestamp persistence and API contracts use UTC instants. Shared MVC/Blazor time
markup and a local browser formatter display the viewer's timezone without using
the server timezone or mutating stored data; see [time display](time-display.md).

The [typed object library](reusable-object-library.md) stores stable identities and
immutable IPv4/IPv6/port-list versions under controller schema 3 (ADR 0039). Library
edits require Administrator authorization, CSRF and exact expected-version checks,
with transactional audit. Auditors can inspect history. Pinned references under ADR 0040 embed immutable object versions in saved inet
filter rules. Compilation projects those snapshots onto existing matchers; no
latest-version lookup occurs during apply. [Native static references](native-static-lists.md) now add shared definitions under ADR 0048 while older references retain this projection.
Saved policies cannot change as a side effect of editing a library object.

[Rule enabled state](rule-enabled-state.md) remains in canonical revision intent
under ADR 0041. Compilers validate all rules before emitting the active projection,
omitting disabled rules/meters without changing defaults. Native observation never
claims to reconstruct dormant intent. Inline controls alter a draft only; revision
save and confirmed apply preserve the existing privilege boundary.

Pinned port-list snapshots also support postrouting NAT and bridge/regular-chain
destination-port matching. A pure domain projection supplies existing literal
matchers; stored intent and database usage retain identity/version/content. No
compile-time database lookup, new host operation or receipt bypass is introduced.
See [ADR 0042](decisions/0042-transport-port-list-references.md).

Read-only list comparison loads two stored versions of the same identity/type.
It compares canonical entries and descriptions, without network coverage analysis
or live-host inference. Policy pin links open comparison in a separate tab.
Existing database history, desired state, audit and apply receipts are unchanged.

A draft reference form may explicitly load one bounded immutable list history
for selection. Other lists retain their current-version choices. Target/form
selection is presentation state; browsing never changes canonical intent and
compilation/apply still use only the exact embedded, validated version snapshot.

Postrouting address lists project to scalar or bounded anonymous prefix sets,
retaining identity/version/content in immutable intent. Native observations retain
both complete sets; address-set receipts use an explicit v3 fingerprint while old
scalar/port-only fingerprints remain unchanged. Guided/legacy edits preserve pins
and explicit removal cannot erase a required SNAT source. No new host operation
or controller database lookup during apply is introduced. See
[ADR 0043](decisions/0043-postrouting-address-sets-and-references.md) and the reusable library.

Bridge address-list snapshots are embedded in immutable policy intent for both
forwarding and regular chains. Compilation resolves same-family snapshots without
a database lookup and retains every prefix through native reconstruction. Complete
address-set graphs use a v3 fingerprint; preceding scalar/port-only fingerprints
stay unchanged. MAC restrictions, explicit family, bridge master and jump/return
control flow remain conjunctive. Invalid dormant rules are denied too. See
[ADR 0044](decisions/0044-bridge-address-sets-and-references.md).

DNAT original destination-port lists use embedded immutable snapshots, resolved
without database lookup into scalar/set matchers before one explicit translation.
Complete native observations retain every port and bind set policies with v3 NAT
fingerprints. This preserves the existing receipt/watchdog boundary; no new agent
command or SQL schema is introduced. Native projection now follows [the complete static-set contract](native-static-lists.md).

DNAT source/original-destination address snapshots use the same self-contained
reference contract. Compilation projects scalars/sets without database lookups,
retains whole-set negation and one explicit translation, and rejects missing
original-destination restrictions. Complete native v3 observations bind all address
entries; older scalar/port-only fingerprints remain unchanged. No new privileged
command or SQL migration is introduced. Native projection now follows [the complete static-set contract](native-static-lists.md).

Native observations now bracket complete table collection with bounded read-only
kernel transaction-generation queries ([ADR 0047](decisions/0047-generation-consistent-native-observations.md)).
A changed generation, denied query or malformed reply makes the observation
unavailable rather than combining state from different transactions. This covers
outside writers during collection; it does not close the later observation-to-write
race. Transactions in unrelated tables can conservatively invalidate collection.
Static elements now use complete per-set collection, matching creation handles and exact protected-artifact verification under [ADR 0048](native-static-lists.md).

Native static lists preserve enforcement references across every declared scope.
Receipts bind definitions, complete contents and lookup edges. Generation-bound
listings can complete nft creation-echo element omissions only when creation
handles agree and the reconstructed artifact exactly matches protected intent.
Missing provenance or conflicting data remains denied. The journal repeats exact
artifact verification; dynamic meter runtime contents retain their separate boundary.
