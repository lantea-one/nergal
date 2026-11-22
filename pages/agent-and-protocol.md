# Agent & Control Protocol

`nergal-agent` is the sole privileged component that executes `nft` against the host kernel.

## Commands

| Command | Purpose |
| --- | --- |
| `nergal-agent enroll <state-dir>` | Exclusively creates `inet nergal_filter`, records owner identity and boot/namespace receipt in `journal.db`. |
| `nergal-agent status-serve <state-dir> <sock> <uid> [gid]` | Read-only Unix status listener authorized by kernel `SO_PEERCRED`. |
| `nergal-agent control-serve <state-dir> <sock> <uid> [gid]` | Local Unix two-phase control listener authorized by kernel `SO_PEERCRED`. |
| `nergal-agent tls-serve <state-dir> <ip:port> <cert> <key> <client-pins>` | Remote TLS 1.3 pinned mutual TLS control listener (`AllowTlsResume = false`). |
| `nergal-agent reconcile <state-dir>` | Explicitly re-creates the enrolled baseline on a new Linux boot without adopting foreign tables. |

## Control Protocol Framing & Commands

Requests and replies use a 4-byte big-endian length prefix (`AgentControlFrame`) carrying bounded UTF-8 JSON (`AgentControlCodec`):

- `status`: Returns `matched`, `drift`, `unbound`, `appliedPendingConfirmation`, `busy`, or `unavailable`.
- `prepareApply`: Carries `operationId`, optional `watchdogId`, `confirmationTimeoutSeconds`, and either a `policy` (`FilterPolicy`) or multi-table `bundle` (`FirewallPolicyBundle`).
- `confirm`: Commits an active `AwaitingConfirmation` operation after re-verifying both `inet nergal_filter` and auxiliary table presence/ownership.
- `rollback`: Immediately restores the enrolled rollback artifact and deletes any newly created auxiliary tables.

## Multi-Table Receipts & Autonomous Watchdog

1. Before any replacement, `AgentControlHandler` inspects `inet nergal_filter` and runs `nft --terse --json list tables` (`TryInspectAuxiliaryTablesAsync`) to verify that `inet nergal_nat` and `bridge nergal_bridge` match the enrolled artifact and have no unowned table collisions.
2. Replacement batches atomically delete only owned nergal tables (`bridge nergal_bridge`, `inet nergal_nat`, `inet nergal_filter` as present) and create the candidate bundle in a single `nft --file -` transaction, validated with `--check` and `--echo --handle --json` (`ParseBundleReplacementEcho`).
3. If confirmation does not arrive before the deadline, the independent `nergal-agent watch` process restores the prior enrolled artifact (and removes newly introduced NAT/bridge tables) without requiring the web controller to remain reachable.
