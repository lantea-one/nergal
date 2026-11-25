# Architecture & Trust Boundaries

Native nftables on Linux is the sole firewall/platform target. Other firewall
engines and Windows-native service deployments are outside scope. The pure policy
contracts, explicit native capabilities and controller/agent separation remain;
they do not imply a future-adapter roadmap. Browser clients are separate from the
Linux service deployment boundary. See
[ADR 0051](https://git.lantea.one/lantea-one/nergal/src/branch/main/docs/decisions/0051-nftables-only-linux-product.md).

nergal separates policy authoring, compilation, identity/session handling, and kernel firewall enforcement into explicit assemblies and OS processes.

## Solution Layering

Native source viewing/import shares one bounded analysis pipeline: a lossless
token document, immutable delimiter tree and masked inventory. Schema-3 reports
expose counts and diagnostic positions, without private tokens or partial results.
An ordered contextual statement partition retains every original node and raw
expression; unknown heads produce masked review gaps. Table/chain counts require
proper declaration scope. This head classification does not parse rule semantics.
A bounded literal expression parser now consumes complete rules or records a
positioned failure without a partial typed result. Schema-3 reports expose only
its counts/diagnostics. Structural completion does not grant conversion authority; semantic mapping and
explicit include resolution remain M4 work. See [the source workflow](native-source-library.md).

- **`Nergal.Core`**: Framework-independent domain POCOs (`FilterPolicy`, `NatPolicy`, `BridgePolicy`, `FirewallPolicyBundle`, `PolicyBundleJsonCodec`, `AgentControlRequest`/`Reply`, `ApplySession`). No ASP.NET, SQLite, or shell dependencies.
- **`Nergal.Nftables`**: Pure compilers (`NftFilterCompiler`, `NftNatCompiler`, `NftBridgeCompiler`, `NftPolicyBundleCompiler`) and strict JSON observation parsers (`NftTableObservation`, `NftReceiptVerifier`).
- **`Nergal.LocalState`**: Owner-only SQLite apply journal (`journal.db`, schema v3) storing enrollment identity, boot/namespace-bound receipts, and operation history.
- **`Nergal.ControllerState`**: Owner-only SQLite controller database (`controller.db`) storing managed hosts, monotonic policy revisions, and an append-only audit log.
- **`Nergal.LocalTransport` / `Nergal.RemoteTransport`**: Bounded length-prefixed framing over Unix domain sockets (`SO_PEERCRED` peer UID verification) and pinned TLS 1.3 mutual TLS (`AllowTlsResume = false`).
- **`Nergal.Agent` (`nergal-agent`)**: Privileged host daemon (`CAP_NET_ADMIN`) owning kernel `nft` execution and autonomous local watchdog rollback.
- **`Nergal.Web`**: Unprivileged ASP.NET Core MVC + Blazor controller (`CapEff == 0`).
- **`Nergal.Admin` (`nergal-admin`)**: Offline CLI for one-time local account DB initialization, password provisioning, and controller DB initialization.

## Two-Phase Confirmed Apply Sequence

```mermaid
sequenceDiagram
  participant Op as Operator (Administrator)
  participant Web as Nergal.Web
  participant Agent as nergal-agent
  participant WD as nergal-agent watch
  participant Kernel as Linux nftables

  Op->>Web: POST /manage/apply/start (CSRF + Admin role)
  Web->>Agent: PrepareApply (FirewallPolicyBundle, timeout)
  Agent->>Kernel: nft --terse --json list table + list tables
  Agent->>Kernel: nft --check (atomic delete + create batch)
  Agent->>WD: Spawn independent watchdog process
  WD-->>Agent: Armed (RollbackArmed in journal.db)
  Agent->>Kernel: nft --echo --handle --json (atomic replace)
  Agent-->>Web: AppliedPendingConfirmation (operationId, watchdogId)
  alt Operator confirms within timeout
    Op->>Web: POST /manage/apply/confirm
    Web->>Agent: Confirm (operationId, watchdogId)
    Agent->>Kernel: Verify live filter + auxiliary tables match
    Agent-->>Web: Confirmed (revision++)
  else Timeout expires without confirmation
    WD->>Kernel: Atomic rollback to prior enrolled artifact
  end
```

## Non-Negotiable Safety Invariants

1. **Foreign table preservation**: nergal never executes `flush ruleset` and never deletes or modifies tables lacking its own `nergal:v1:<owner>:<resource>` ownership comment.
2. **No shell interpolation**: Native `nft` invocations pass fixed argv arrays via `ProcessStartInfo.ArgumentList` and feed compiled artifacts over stdin.
3. **Fail-closed collision handling**: If an unowned `inet nergal_filter`, `inet nergal_nat`, or `bridge nergal_bridge` table exists, enrollment and apply refuse to proceed.

## Unreleased router and settings work

See [Router Migration & Local Sandbox](router-migration-and-sandbox.md) for the
current support matrix, supported apply scope and recovery limits, saved-settings/runtime distinction,
private source inspection, container isolation, verification limits, and screenshots.
This local development work is not a published release.

Reusable port-list versions can also be embedded in postrouting and bridge rules,
including regular chains. Framework-independent projection supplies existing
literal matchers; the database retains immutable identity/version/content and
saved usage paths. Complete native observations and protected receipts still gate
apply/rollback. No agent database lookup or new privileged browser operation is
introduced. See [reusable object contracts](reusable-object-library.md).

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
or controller database lookup during apply is introduced. See the reusable library.

Bridge address-list snapshots are embedded in immutable policy intent for both
forwarding and regular chains. Compilation resolves same-family snapshots without
a database lookup and retains every prefix through native reconstruction. Complete
address-set graphs use a v3 fingerprint; preceding scalar/port-only fingerprints
stay unchanged. MAC restrictions, explicit family, bridge master and jump/return
control flow remain conjunctive. Invalid dormant rules are denied too. See
[the list workflow](reusable-object-library.md).

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

Native static lists preserve enforcement references across every declared scope.
Receipts bind definitions, complete contents and lookup edges. Generation-bound
listings can complete nft creation-echo element omissions only when creation
handles agree and the reconstructed artifact exactly matches protected intent.
Missing provenance or conflicting data remains denied. The journal repeats exact
artifact verification; dynamic meter runtime contents retain their separate boundary.

## Native conversion review boundary

The source viewer and conversion planner share a bounded lossless document and
contextual partition. Explicit table roles and ordered uploaded include bindings
produce exhaustive source-bound mappings/gaps. Any unsupported statement removes
the complete candidate; source commands and server paths are never executed.
Controller schema 4 stores immutable plans, original digests and audit; separate
Administrator/CSRF commit recomputes the saved plan and atomically creates one
linked revision plus pinned lists. Apply remains a separate agent workflow.
Native meter update/add expiry is explicit intent and native operation-only drift
is detected. See the [conversion guide](native-source-library.md) for supported
grammar, offline upgrades and independent packet/rollback evidence.

The first M5 [appliance-console](appliance-console.md) slice separates presentation
from privilege. Pure state-based guidance only chooses navigation; pending/recovery
states outrank setup, and unknown observations never imply healthy/applied state.
A dedicated reader Hosts page retains existing Administrator/CSRF mutation routes.
Allowlisted firewall sections switch locally without changing the draft. See ADR 0057.
