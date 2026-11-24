# 0036. Complete bundle observations for auxiliary apply and rollback

- Status: accepted; complete native, packet, agent and mapped-identity conformance implemented
- Date: 2026-11-22

## Problem

Primary-table receipts currently bind filter identity, handles, and semantics.
Auxiliary presence checks bind only table names and ownership comments. That is
insufficient to authorize extended bridge or early inet replacement: changing a
rule or recreating an auxiliary table with a copied marker must be detected.

## Decision

Retain the protected receipt envelope and its boot, namespace, owner, resource,
and primary table handle. For multi-table observations, its state digest binds
an explicitly versioned complete bundle: the primary native fingerprint plus
all present NAT, bridge, and auxiliary inet native fingerprints. Each component
includes table/chain/rule/set handles and every supported semantic field.
Single-table fingerprints remain byte-identical. The observation reconstructs
and recompiles the entire bundle, not just its primary filter slice.

Parse bridge master/MAC/L3/L4 matches, priority, regular chains, and jump/return
strictly. Reject unknown fields/expressions, duplicate handles, missing targets,
cycles, and unexpected native objects. Canonicalize only equivalent native forms.
Early inet policy targets the fixed owned `nergal_aux` table and carries its own
priority and filter policy; no foreign table names enter the contract.

Collect complete observations under the resource execution lock. Validate both
complete creation echo and independent complete listing before recording a
candidate receipt. Prepare, status, confirmation, rollback, and boot reconciliation
use complete state and exact protected artifacts. Delete/recreate only explicitly
owned reserved tables in one checked atomic transaction. Keep the independent
local watchdog armed before applying, and refuse unexpected or ambiguous drift.

Existing primary-only receipts for multi-table deployments are not silently
upgraded by observing the host. They fail closed until an explicit trusted
maintenance/reconciliation procedure recreates and verifies the protected intent.
No database schema upgrade is implied by the opaque fingerprint extension; older
binaries cannot validate new composite fingerprints and must not run concurrently.

## Acceptance evidence required

- Complete native echo/list reconstruction and stable fingerprints for all tables.
- Auxiliary rule drift, copied-marker recreation, foreign collisions, missing tables,
  unknown syntax, and partial snapshots denied without mutating foreign state.
- Real dual-stack/bridge packet checks for priority and jump/return behavior.
- Independent timeout rollback, explicit rollback, confirmation, and restart checks
  for changes where the primary table remains identical.
- Updated controller readiness UI and documentation only after those checks pass.

All privileged conformance uses disposable namespaces and synthetic policy data.
No production configuration is applied during development.

## Rollback provenance and ambiguous crash windows

Before replacement, both explicit rollback and the independent watchdog must
compare the complete live observation with either the protected baseline receipt
or the operation's durably recorded candidate receipt. Matching compiled text or
copied ownership comments cannot authorize a replacement. The apply path repeats
its baseline check after arming the watchdog and reacquiring the execution lock.

Kernel replacement and SQLite acknowledgement cannot form one atomic transaction.
If a process dies after replacement but before durable native evidence is saved,
or after restoration but before its receipt is committed, a later observer cannot
prove the recreated objects' provenance. Preserve that state and enter
`RecoveryRequired` rather than adopting handles or overwriting unexpected state.
Ordinary recorded candidates still receive autonomous timeout rollback, including
controller loss and watchdog restart. These distinct cases require explicit tests;
restart safety does not imply automatic repair of every ambiguous crash window.

## Acceptance results

`check-auxiliary-apply.sh` verifies real IPv4/IPv6 bridge MAC+IP restrictions,
source/destination MAC negation with permitted control connections, bridge-name
exclusion, jump/return, and priority ordering against later foreign hook counters.
Its `--agent` cases verify confirmation, explicit and independent timeout rollback,
controller loss, watchdog restart, auxiliary removal/restoration, and preservation
of drifted/recreated/missing/unknown or foreign state. The mapped-identity HTTPS
fixture applies filter/NAT/extended bridge/early inet together through the
unprivileged web controller with pinned mTLS. Unit tests cover complete new-boot
intent and rejection of rollback without durable native evidence.

This acceptance covers the typed supported slice and disposable synthetic topology.
It does not establish lossless import of arbitrary native configurations or an
atomic kernel/SQLite acknowledgement. Those limits remain explicit above.

The runtime repeats its complete native receipt comparison immediately before
replacement validation. Its execution lock coordinates cooperating agent writers;
administrators must not run competing privileged writers against owned resources
during an operation. Native table deletion uses names: the tested nft userspace
crashes when handle-only deletion and rule-bearing recreation use JSON echo.
A separate observer cannot close the final observation-to-transaction race against
an unrelated privileged writer. Such concurrent modification is unsupported;
receipt checks detect subsequent drift but cannot provide kernel compare-and-swap.

[ADR 0047](0047-generation-consistent-native-observations.md) additionally binds
complete collection to one stable kernel transaction generation. It detects
configuration transactions during the separate listings but retains the final
observation-to-transaction race described above.
