# nergal

Self-hosted Linux firewall management, built with .NET 10, ASP.NET Core MVC,
Blazor, and reusable C# POCOs. Native nftables is the first backend.

**Status: early development foundation, not a production firewall manager.**
This revision includes the backend decision, semantic capability assessment,
a typed input-filter policy, an unprivileged deterministic native nftables compiler,
a pure confirmed-apply state model, a private transactional local journal, unit tests,
an authorized read-only local status listener, an MVC landing page and a Blazor decision page. The compiler emits create-only
candidates; it cannot inspect, install or modify host firewall rules.
A test-only independent watchdog exercises synthetic rollback in disposable
namespaces; it is not a host agent. The web app has no compiler/editor endpoint.
Optional OIDC supports administrator group login. `nergal-agent` provides offline local
operator enrollment (`enroll`, [ADR 0019](docs/decisions/0019-local-agent-enrollment.md)),
a peer-authorized read-only status listener (`status-serve`, [ADR 0020](docs/decisions/0020-local-agent-status-listener.md)),
and receipt-aware local confirmed-apply, watchdog rollback, and boot reconciliation commands
(`prepare`, `watch`, `apply`, `confirm`, `reconcile`, [ADR 0023](docs/decisions/0023-explicit-boot-reconciliation.md))
alongside schema-1 input filtering and schema-2 stateful forwarding, output chains,
interface matchers, IPv6 Neighbor Discovery ([ADR 0024](docs/decisions/0024-stateful-forwarding-and-icmpv6-policy.md)),
and native per-source rate limiting ([ADR 0025](docs/decisions/0025-native-per-source-rate-limiting.md))
in `inet nergal_filter`, plus dual-stack DNAT, explicit SNAT, and `ct status dnat`
(`inet nergal_nat`, [ADR 0026](docs/decisions/0026-dual-stack-nat-and-original-tuple-matching.md));
bridge filtering, atomic multi-table transactions, remote agent transport, web policy
authoring, and systemd packaging remain subsequent phases.
Isolated local administrator credentials and protected persistent Data Protection
keys support an opt-in HTTPS administrator login and session page. A separately enabled administrator route reads one configured local agent status snapshot.

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
- `Nergal.LocalTransport`: bounded status-only Unix socket listener/client with
  explicit kernel peer-UID checks in both directions. No firewall executor, database or browser access.
- `Nergal.Admin`: offline initialization and singleton administrator provisioning
  for the private application account store. See [operator commands](docs/local-administrator-accounts.md).
- `Nergal.Agent`: offline local operator enrollment (`enroll`), peer-authorized read-only
  local status listener (`status-serve`), receipt-aware confirmed-apply/watchdog CLI
  (`prepare`, `watch`, `apply`, `confirm`), and explicit new-boot reconciliation (`reconcile`)
  for `inet nergal_filter`, serialized with `ResourceExecutionLock` using native echo
  handles and complete listing reconciliation.
- `Nergal.Identity`: explicitly provisioned private singleton administrator store
  using standard Identity hashing/lockout and serialized SQLite decisions, plus
  certificate-encrypted persistent session keys and revocable local sessions.
- `Nergal.Web`: MVC controllers/views and Blazor components. It must never gain
  the production Docker socket, unrestricted SSH or arbitrary shell execution.
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
[protected session keys](docs/protected-session-keys.md), [local sessions](docs/local-sessions.md), [federated login](docs/federated-login.md), [controller status](docs/controller-status.md)
and [testing standards](docs/testing.md).

The intended deployment model is a controller and restricted per-host agent.
A simple single-server installation must work without Active Directory,
Forgejo, WireGuard or any particular network layout. Site integrations belong
in optional deployment configuration, not in the policy core.

## Planned security boundaries

Native OIDC (including Keycloak), configurable group/role authorization,
per-user audit attribution, protected kernel-resource ownership verification, native
candidate validation by an agent, atomic apply, independent local timed rollback and
production enrollment/recovery are requirements for future releases. They are not
claims about this initial scaffold. A future backend must reject unsupported semantics rather than
silently weakening a policy. The initial implementation will not manage firewalld.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md). Original code
is licensed under MIT. No FWCloud implementation or assets are included.
