# nergal

Self-hosted Linux firewall management, built with .NET 10, ASP.NET Core MVC,
Blazor, and reusable C# POCOs. Native nftables is the first backend.

**Status: early development foundation, not a production firewall manager.**
This revision includes the backend decision, semantic capability assessment,
a typed input-filter policy, an unprivileged deterministic native nftables compiler,
unit tests, an MVC landing page and a Blazor decision page. The compiler emits
create-only candidates; it cannot inspect, install or modify host firewall rules.
The web app has no compiler/editor endpoint. OIDC and the host agent are planned,
not implemented. No production deployments are configured.

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
  fail-closed backend compatibility checks. No network or host operations.
- `Nergal.Nftables`: schema validation and deterministic create-only input-filter
  candidates for the reserved `inet nergal_filter` table. No execution or host access.
- `Nergal.Web`: MVC controllers/views and Blazor components. It must never gain
  the production Docker socket, unrestricted SSH or arbitrary shell execution.
- `tests/Nergal.Core.Tests`: deterministic unit tests for semantic safety,
  invalid inputs and defensive snapshots.
- `tests/integration/nftables`: opt-in real kernel and dual-stack packet checks
  in disposable user/network namespaces, including collision and foreign-table safety.
- `tests/integration/firewalld`: reproducible backend research in a disposable
  container network namespace; it never mounts the host firewall or system bus.

Read [the backend decision](docs/decisions/0001-native-nftables.md),
[architecture](docs/architecture.md), [policy contract](docs/policy.md),
[compiler decision](docs/decisions/0002-filter-compiler.md) and
[testing standards](docs/testing.md).

The intended deployment model is a controller and restricted per-host agent.
A simple single-server installation must work without Active Directory,
Forgejo, WireGuard or any particular network layout. Site integrations belong
in optional deployment configuration, not in the policy core.

## Planned security boundaries

Native OIDC (including Keycloak), configurable group/role authorization,
per-user audit attribution, durable ownership verification, native candidate
validation by an agent, atomic apply, local timed rollback and configuration
persistence are requirements for future releases. They are not claims about this
initial scaffold. A future backend must reject unsupported semantics rather than
silently weakening a policy. The initial implementation will not manage firewalld.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md). Original code
is licensed under MIT. No FWCloud implementation or assets are included.
