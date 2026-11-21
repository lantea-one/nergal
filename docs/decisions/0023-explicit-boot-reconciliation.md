# ADR 0023 — Atomic replacement echo, confirmed-apply CLI, and boot reconciliation

- Status: accepted
- Date: November 21, 2026

## Decision

1. **Atomic native replacement echo (`NftTableObservation.ParseReplacementEcho`)**:
   Extend `Nergal.Nftables.NftTableObservation` to parse the `--echo --handle --json`
   output of an atomic `delete table inet nergal_filter` + `create table inet nergal_filter ...`
   transaction (as well as exclusive creation of a rule-bearing schema-1 baseline).
   Require `create` table (with canonical marker and positive handle), `add` chain
   (`input` base chain with `accept` or `drop` policy and positive handle), and zero
   or more ordered `add` rule objects parsed by `ParseSchema1Rule` with distinct
   positive handles. Reject any other object/operation shape with `observation.replacementEcho`.

2. **Explicit new-boot baseline reconciliation (`ApplyJournal.ReconcileBoot`)**:
   Extend `ApplyJournal` with explicit offline boot reconciliation. Require a bound
   resource, exact enrolled ownership/identity, `now.BootId != enrollment.Boot`
   (refusing same-boot calls with `reconcile.sameBoot`), verified matching
   creation-echo receipt and full listing in the current namespace, and exact schema-1
   compiler reconstruction equal to the last-confirmed `enrollment.Artifact`. If a
   prior-boot operation remained nonterminal in `enrollment.Active`, record
   `ApplyEvent.Interrupted` (`RecoveryRequired`) in that operation's retained event
   history before updating `enrollment.boot`, clearing `active`, and updating
   `resource_receipt` (`boot`, `namespace`, `handle`, `digest`) at the unchanged
   confirmed revision. Preexisting kernel tables on the new boot are never adopted:
   exclusive `create` fails atomically on collision.

3. **Local operator confirmed-apply and watchdog CLI (`Nergal.Agent`)**:
   Add `prepare`, `watch`, `apply`, `confirm`, and `reconcile` commands to
   `nergal-agent`. All commands acquire `ResourceExecutionLock`, validate full
   candidates with `/usr/sbin/nft --check --file -` before execution, derive candidate
   and restored handles from `--echo --handle --json`, verify independent full
   listings, and commit transitions through schema-3 receipt-aware journal operations.
   `watch` runs as an independent process that durably arms rollback before `apply`
   mutates the kernel and automatically restores the exact rollback artifact on
   deadline expiry or worker loss.

## Remaining boundary

`Nergal.Agent` executes only local CLI operations for the schema-1 `inet nergal_filter`
input slice. Forwarding/output chains, stateful tracking, IPv6 neighbor discovery,
per-source meters, NAT, bridge filtering, authenticated remote/controller apply
transport, and systemd packaging belong to Milestones B–D.
