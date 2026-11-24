# Changelog

## Unreleased — router authoring and settings review

- Make native nftables on Linux the sole firewall/platform target. Remove the
  future-adapter roadmap, retain explicit native support limits and framework-free
  policy contracts, and align application/Pages guidance and agent rules (ADR 0051).
- Share one source-analysis pipeline across native viewing/review and import.
  Retain exact token spans, physical source positions, quoted/reference values and
  unknown syntax; handle continuations and CRLF/CR/LF without lossy normalization.
  Bound bytes and both significant/total tokens, reject controls without partial
  output, and keep conversion blocked pending semantic mapping (ADR 0050).
- Add Administrator-only exports of selected saved revisions: exact create-only
  native candidates and separate canonical complete intent. Verify every saved
  candidate digest before either download; retain dormant rules and pinned
  snapshots in intent, without exporting host ownership or runtime state (ADR 0049).
- Add typed raw rpfilter/source-port rules, forward MSS clamping, source-MAC
  pinning/negation, ICMPx rejection, destination meters, negated matchers, and
  postrouting masquerade/return with extended matchers.
- Preserve extended semantics through canonical JSON, filter/NAT observation, and
  structured draft edits; test real dual-stack packet outcomes in disposable namespaces.
- Add priority-table and extended bridge jump/return authoring with complete native
  ownership receipts and verified confirmed apply/rollback (ADR 0036).
- Review settings corruption handling and distinguish saved intent from runtime
  services. Refresh management light/dark appearance using Lantea.One's palette.
- Add private administrator-only source inspection and a loopback containerized
  development stack with separate check-only native source workers.
- Refresh documentation and the repository Pages site with local test screenshots.

- Require stable kernel transaction generations across complete agent observations;
  reject mixed snapshots and unavailable/unknown netlink replies (ADR 0047). Verify
  same-handle set-element drift, stable meter traffic and capability denial in
  disposable namespaces. Native static references now follow ADR 0048.
- Add shared constant native IPv4/IPv6/port sets for new UI attachments across all
  declared reference scopes. Preserve legacy artifacts, bind definition handles,
  complete contents and lookup edges, verify omitted IPv6 echo elements through
  generation-bound listings and exact protected artifacts, and reject oversized
  native evidence before mutation (ADR 0048). Semantic import remains M4.


## [2026.11.21.1] - 2026-11-21

### Multi-Table Confirmed Apply & Rollback
- Extended the agent control protocol (`AgentControlRequest.Bundle`, `PolicyBundleJsonCodec`) and `ApplyWorkflowService` to dispatch full `FirewallPolicyBundle` revisions (`inet nergal_filter`, `inet nergal_nat`, `bridge nergal_bridge`) end-to-end (ADR 0032).
- Added auxiliary table inspection (`NftTableObservation.TryInspectAuxiliaryTables`, `ParseBundleReplacementEcho`) and multi-table rollback/status verification in `nergal-agent` and `ApplyJournal.ResourceReceipts`, preserving foreign tables and failing closed on unowned collisions.

### Inline Sets, IPv4 ICMPv4 & Visual Rule Builder
- Added schema-2 inline anonymous sets (`sourcePrefixes`, `destinationPrefixes`, `destinationPorts`) with disjoint/non-adjacent `UInt128` interval validation and deterministic kernel observation round-tripping, plus allowlisted IPv4 ICMP `parameter-problem` (ADR 0033).
- Added `PolicyBundleSummary.razor` Blazor summary component and CSRF-protected Administrator MVC rule-builder actions (`/manage/policies/rules/{add,move,remove}`) with Auditor `403` enforcement.

### Forgejo Pages & Release Packaging
- Added a static Docsify + Mermaid documentation portal under `pages/`, `scripts/verify-pages.py`, and `.forgejo/workflows/pages.yml` publishing `pages/` on `main`.
- Added `deploy/systemd/nergal.sysusers`, `deploy/systemd/nergal.tmpfiles`, and `scripts/package-release.sh` assembling verified `.tar.gz`, `.deb`, and `SHA256SUMS` artifacts in CI.

## [2026.11.21] - 2026-11-21

### Core & Policy Model
- Added framework-independent immutable domain POCOs (`FilterPolicy`, `NatPolicy`, `BridgePolicy`, `FirewallPolicyBundle`, `BackendCapabilities`, `BackendCompatibilityEvaluator`, `ResourceOwnership`, `ApplyPlan`, and `AgentControlProtocol`) in `Nergal.Core` with deterministic bounds checking and structured diagnostics.
- Established [ADR 0001](docs/decisions/0001-native-nftables.md) selecting native `nftables` as the primary backend.

### Native `nftables` Compiler & Agent Execution
- Implemented deterministic `NftFilterCompiler` (Schema 1 & Schema 2 stateful forwarding, output chains, ingress/egress interface matchers, IPv6 Neighbor Discovery, per-source rate-limiting meters, `ct status dnat`), `NftNatCompiler` (`inet nergal_nat` DNAT/SNAT), `NftBridgeCompiler` (`bridge nergal_bridge`), and coordinated atomic `NftPolicyBundleCompiler` transactions.
- Implemented `Nergal.LocalState` (`ApplyJournal`, `ResourceExecutionLock`, monotonic revision and boot-clock persistence in owner-only `0700`/`0600` SQLite WAL storage) and `Nergal.Linux` metadata/namespace guards.
- Built `nergal-agent` (`enroll`, `reconcile`, `status-serve`, `control-serve`, `tls-serve`, `prepare`, `watch`, `apply`, `confirm`) enforcing explicit `inet nergal_filter` table ownership, independent watchdog rollback, and zero mutation of foreign tables.
- Implemented mutual-authentication transports in `Nergal.LocalTransport` (`SO_PEERCRED` peer-UID sockets) and `Nergal.RemoteTransport` (pinned TLS 1.3 mTLS with `AllowTlsResume = false`, leaf EKU, and SHA-256 thumbprint validation).

### Web Controller, RBAC & Operations
- Built `Nergal.ControllerState` (mode-checked `0700`/`0600` SQLite WAL store for registered hosts, monotonic policy revisions, and trigger-protected append-only `audit_log`), `Nergal.Identity` (`LocalAdministratorAccounts`, certificate-protected persistent Data Protection session keys), and `Nergal.Admin` (`account init`, `account provision [--role]`, `controller init`, `--version`).
- Built `Nergal.Web` MVC & Blazor controller UI featuring local HTTPS authentication, optional OIDC with disjoint `AdministratorGroups`/`AuditorGroups` RBAC, `/manage` fleet dashboard, `/manage/policies` bundle editor with capability checks and unified nftables diff preview, `/manage/apply` two-phase confirmed apply and rollback workflow, and `/manage/audit` immutable history.
- Added hardened `deploy/systemd/nergal-agent.service` and `deploy/systemd/nergal-web.service` templates and [docs/deployment.md](docs/deployment.md).

### Verification
- Verified across deterministic xUnit unit suites (`Nergal.Core.Tests`, `Nergal.LocalState.Tests`, `Nergal.Web.Tests`) and unprivileged disposable user/network namespace kernel integration suites enforcing real dual-stack packet filtering, NAT/bridge compilation, cross-UID isolation, watchdog crash recovery, OIDC/HTTPS sessions, and end-to-end unprivileged Kestrel -> `nergal-agent` packet rollback.
