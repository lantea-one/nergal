# 0036. Complete bundle observations for auxiliary apply and rollback

- Status: proposed implementation; apply remains gated until conformance passes
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
