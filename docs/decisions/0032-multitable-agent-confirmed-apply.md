# ADR 0032 — Multi-table agent receipts and confirmed apply for NAT and bridge tables

- Status: accepted
- Date: November 21, 2026

## Decision

1. **Unified bundle JSON contract and protocol extension**:
   Extract canonical `FirewallPolicyBundle` (`Filter`, `Nat`, `Bridge`) JSON
   encoding and strict validation into `PolicyBundleJsonCodec` in `Nergal.Core`,
   reused by both `PolicyAuthoringService` in `Nergal.Web` and `AgentControlCodec`.
   Extend `AgentControlRequest` (`PrepareApply`) with an optional `Bundle`
   (`FirewallPolicyBundle`), serializing as `"policy"` for filter-only requests
   and `"bundle"` when `Nat` or `Bridge` sections are present.

2. **Coordinated multi-table ownership and atomic replacement**:
   `nergal-agent` continues binding the primary `inet nergal_filter` table receipt
   (`BootId`, `NetworkNamespace`, `Identity`, `TableHandle`, `StateDigest`) while
   verifying auxiliary owned tables (`inet nergal_nat`, `bridge nergal_bridge`) via
   `nft --terse --json list tables`. Pre-existing foreign or mismatched-comment
   tables under those names trigger fail-closed `AgentControlOutcome.Drift`
   (`resource.drift`) and are never modified or deleted.

3. **Single-transaction apply, echo verification, and watchdog rollback**:
   `AgentCommands.ReplaceAndVerifyAsync` and `AgentCommands.WatchAsync` prepend
   `delete table` statements only for verified owned tables currently present in
   the kernel and apply the full create-only multi-table batch atomically via
   `nft --echo --handle --json --file -`. `NftTableObservation.ParseBundleReplacementEcho`
   verifies every echoed object and owner comment across filter, NAT, and bridge
   tables before confirming or rolling back.
