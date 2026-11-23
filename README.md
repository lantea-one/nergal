# nergal

Self-hosted Linux firewall management, built with .NET 10, ASP.NET Core MVC,
Blazor, and reusable C# POCOs. Native nftables is the first backend.

Nergal is a general-purpose FOSS firewall manager in development. The initial
private deployment supplies migration and acceptance cases; the product is designed
for independent single-host and multi-host installations with different network
layouts. Site-specific infrastructure is optional configuration, not a core
requirement. See [product scope and workflow](docs/product-workflow.md).

**Release `2026.11.21`** implements the complete single-table controller and host
agent workflow across verified privilege boundaries:

- **Typed policy & native nftables compiler**: schema-1 input filtering and
  schema-2 stateful forwarding, output chains, ingress/egress interface matchers,
  IPv6 Neighbor Discovery ([ADR 0024](docs/decisions/0024-stateful-forwarding-and-icmpv6-policy.md)),
  per-source rate-limiting meters ([ADR 0025](docs/decisions/0025-native-per-source-rate-limiting.md)),
  dual-stack DNAT/SNAT and `ct status dnat` in `inet nergal_nat`
  ([ADR 0026](docs/decisions/0026-dual-stack-nat-and-original-tuple-matching.md)),
  and `bridge nergal_bridge` with atomic multi-table transaction compilation
  ([ADR 0027](docs/decisions/0027-bridge-filtering-and-atomic-multitable-transactions.md)).
- **Isolated host agent (`nergal-agent`)**: offline enrollment (`enroll`), boot
  reconciliation (`reconcile`), authenticated read-only status (`status-serve`),
  two-phase confirmed apply and independent timed watchdog rollback (`control-serve`
  with Linux `SO_PEERCRED` and `tls-serve` with TLS 1.3 pinned mTLS), explicit table
  ownership receipts in SQLite WAL (`Nergal.LocalState`), and preservation of unrelated tables.
- **Unprivileged web controller (`Nergal.Web` & `nergal-admin`)**: isolated local
  HTTPS credentials, persistent Data Protection session keys, optional OIDC with
  disjoint `AdministratorGroups`/`AuditorGroups` RBAC, SQLite WAL host registry,
  monotonic policy revisions, append-only audit log (`Nergal.ControllerState`), MVC/Blazor
  policy bundle authoring with diff previews, and two-phase confirmed apply (`ApplyWorkflowService`).

Two-phase agent dispatch (`prepare-apply`/`confirm`/`rollback`) supports owned
`inet nergal_filter`, `inet nergal_nat`, and extended `bridge nergal_bridge` bundles, plus independent early `inet nergal_aux`
filtering, with complete native receipts, coordinated atomic replacement and rollback
([ADR 0036](docs/decisions/0036-complete-bundle-observation-and-rollback.md)).
`firewalld` is excluded ([ADR 0001](docs/decisions/0001-native-nftables.md)).
See [deployment guide](docs/deployment.md) and [CHANGELOG.md](CHANGELOG.md) for
installation and hardening details before live deployment.

## Current development work

The development version includes [typed router constructs and explicit support limits](docs/router-constructs.md),
a Lantea.One-inspired light/dark management UI, validated audited settings intent,
a [versioned typed list library with pinned filter references](docs/reusable-object-library.md),
and an administrator-only [database-backed native source library](docs/native-source-library.md). Independent early inet tables and
extended bridge jump/return support confirmed apply after complete native verification. New router fields are
currently authored through **Advanced JSON & Revisions** in a locally bundled CodeMirror editor; simple forms retain them.
Rules also have [versioned inline enable/disable controls](docs/rule-enabled-state.md).
See [the ordered product workflow](docs/product-workflow.md) for the remaining work.

For a persistent, isolated local controller and check-only source containers, see
[the local sandbox guide](docs/local-sandbox.md). Private exports and credentials
stay under ignored `artifacts/dev-stack/`; the public tests and screenshots use
synthetic data. This work has not been published as a release.

## Run locally

Install the .NET 10 SDK version pinned in `global.json`, then:

```sh
dotnet restore Nergal.sln
dotnet test Nergal.sln --configuration Release
dotnet run --project src/Nergal.Web --urls http://127.0.0.1:5191
```

Open `http://127.0.0.1:5191/` for the MVC page, `/backend-decision` for the
Blazor page, and `/healthz` for application health. The current health endpoint
only establishes application availability, not firewall or agent health.
Bind this development build to loopback; it is not a secured administration endpoint.

## Design

- `Nergal.Core`: framework-independent, immutable policy/capability POCOs and
  fail-closed backend compatibility checks, artifact/ownership bindings and a pure
  confirmed-apply state model. No timers, persistence, network or host operations.
- `Nergal.Nftables`: schema validation and deterministic create-only input-filter
  candidates for the reserved `inet nergal_filter` table, typed identity markers and
  native observation/receipt comparison across the complete schema-1 input-filter slice. No execution or host access.
- `Nergal.LocalState`: Linux SQLite journal with explicit bootstrap assertions,
  serialized transitions, exact artifact/revision persistence, protected resource
  receipts, explicit offline schema upgrade and effective-UID/type/mode/link checks. No kernel operations.
- `Nergal.Linux`: shared no-follow metadata and local kernel identity inspection.
- `Nergal.LocalTransport`: bounded status-only (`UnixStatusServer`/`UnixStatusClient`) and
  control (`UnixControlServer`/`UnixControlClient`) Unix socket listeners/clients with
  explicit kernel peer-UID checks in both directions. No firewall executor, database or browser access.
- `Nergal.RemoteTransport`: TLS 1.3 pinned mTLS control listener/client (`TlsControlServer`,
  `TlsControlClient`) validating client/server leaf certificates by SHA-256 thumbprint,
  EKU OID (`serverAuth`/`clientAuth`), and validity window without ambient CA trust.
- `Nergal.Admin`: offline initialization and singleton account provisioning (`account init`,
  `account provision [--role administrator|auditor]`, `controller init`)
  for private account and controller stores. See [operator commands](docs/local-administrator-accounts.md).
- `Nergal.ControllerState`: mode-checked `0700`/`0600` SQLite WAL store for registered agent
  hosts, monotonic policy bundle revisions, and trigger-enforced append-only audit logs
  ([ADR 0029](docs/decisions/0029-controller-persistence-rbac-and-audit.md)).
- `Nergal.Agent`: offline local operator enrollment (`enroll`), peer-authorized read-only
  local status listener (`status-serve`), authenticated local/remote control listeners
  (`control-serve`, `tls-serve`), receipt-aware confirmed-apply/watchdog CLI
  (`prepare`, `watch`, `apply`, `confirm`), and explicit new-boot reconciliation (`reconcile`)
  for `inet nergal_filter`, serialized with `ResourceExecutionLock` using native echo
  handles and complete listing reconciliation.
- `Nergal.Identity`: explicitly provisioned private singleton administrator store
  using standard Identity hashing/lockout and serialized SQLite decisions, plus
  certificate-encrypted persistent session keys and revocable local sessions.
- `Nergal.Web`: MVC controllers/views and Blazor components providing fleet dashboards,
  typed policy bundle authoring with `BackendCompatibilityEvaluator` checks, deterministic
  nftables candidate diff previews (`Nergal.Nftables`), audit/revision viewers, and
  two-phase confirmed apply (`ApplyWorkflowService` over `UnixControlClient` and
  `TlsControlClient`) when explicitly enabled on HTTPS. It has no Docker socket, SSH,
  `CAP_NET_ADMIN`, or shell execution.
- `tests/Nergal.Core.Tests`: deterministic unit tests for semantic safety,
  invalid inputs and defensive snapshots.
- `tests/integration/nftables`: opt-in real kernel and dual-stack packet checks
  in disposable user/network namespaces, including collision and foreign-table safety.
- `tests/integration/enrollment`: opt-in protected intent/receipt binding and
  read-only native reconciliation; no production enrollment or bound apply.
- `tests/integration/ownership`: opt-in native identity, drift and cross-namespace
  receipt checks for tagged input chains. The enrollment fixture also checks ordered family rules against packets.
- `tests/integration/isolation`: opt-in filesystem denial between distinct mapped
  local UIDs, without creating host accounts or changing firewalls.
- `tests/integration/local-status`: opt-in real peer-UID, framing, deadline and
  read-only native status conformance with independent mapped client processes.
- `tests/integration/watchdog`: opt-in independent process/kill-point and real
  packet recovery conformance for fixed synthetic accept/drop policies only.
- `tests/integration/firewalld`: reproducible backend research in a disposable
  container network namespace; it never mounts the host firewall or system bus.

Read [the backend decision](docs/decisions/0001-native-nftables.md),
[architecture](docs/architecture.md), [policy contract](docs/policy.md),
[compiler decision](docs/decisions/0002-filter-compiler.md),
[confirmed-apply model](docs/confirmed-apply.md), [local journal](docs/local-journal.md),
[native resource receipts](docs/native-resource-receipts.md),
[protected receipt persistence](docs/protected-resource-receipts.md),
[local status protocol](docs/local-status-protocol.md),
[local administrator credentials](docs/local-administrator-accounts.md),
[protected session keys](docs/protected-session-keys.md), [local sessions](docs/local-sessions.md), [federated login](docs/federated-login.md), [controller status](docs/controller-status.md),
[deployment guide](docs/deployment.md), [changelog](CHANGELOG.md),
and [testing standards](docs/testing.md).

The intended deployment model is a controller and restricted per-host agent.
A simple single-server installation works without Active Directory,
Forgejo, WireGuard or any particular network layout. Site integrations belong
in optional deployment configuration, not in the policy core.

## Security boundaries and remaining scope

Native OIDC, configurable disjoint Administrator/Auditor group RBAC, per-user
append-only audit attribution, protected kernel-resource ownership verification,
native `nft --check` validation, atomic single-table (`inet nergal_filter`)
apply, and independent local timed rollback are implemented and verified in
disposable namespaces for release `2026.11.21`. Complete multi-table agent apply, including extended bridge and early inet filtering,
is verified in disposable namespaces under ADR 0036. Future secondary backends
remain separate work; every backend must reject unsupported semantics explicitly
rather than silently weakening policy (`firewalld` is excluded per ADR 0001).

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md). Original code
is licensed under MIT. No FWCloud implementation or assets are included.

The native source library supports bounded file uploads, immutable database
snapshots, source-bound reviews and exact original-file downloads. These are source
ingestion/review workflows; semantic conversion and generated policy export remain
unfinished. See [source library](docs/native-source-library.md) and [migration status](docs/router-constructs.md).

See the [remaining product code-complete milestones](docs/milestones.md) for completion gates and dependencies.
