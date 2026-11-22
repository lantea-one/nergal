# ADR 0030 — Web policy bundle authoring, capability verification, and audit views

- Status: accepted
- Date: November 21, 2026

## Decision

1. **Unprivileged compiler reuse in `Nergal.Web`**:
   Reference `Nergal.Nftables` from `Nergal.Web` exclusively as a pure in-memory
   validator, capability inspector (`BackendCompatibilityEvaluator`), candidate text
   compiler (`NftPolicyBundleCompiler`), and SHA-256 digester (`PolicyAuthoringService`).
   `Nergal.Web` still performs zero native `nft` execution, zero shell invocation,
   and carries no reference to `Nergal.LocalState`.

2. **Typed bundle authoring, deterministic diffing, and RBAC-gated views**:
   Enable `/manage`, `/manage/policies`, `/manage/policies/preview`,
   `/manage/policies/save`, `/manage/hosts/add`, `/manage/hosts/delete`, and
   `/manage/audit` only when `ControllerState:Enabled` and `LocalSessions:Enabled`
   are both explicitly configured on Linux. Enforce `NergalReader`
   (`Administrator` or `Auditor`) on read and deterministic preview/diff views,
   `NergalAdministrator` on host and policy-revision persistence, and strict
   antiforgery validation (`ValidateAntiForgeryToken`) on every state-changing
   POST.

## Remaining boundary

Dispatching saved policies to enrolled `nergal-agent` instances over
`UnixControlClient` / `TlsControlClient` for two-phase confirmed apply and timed
watchdog rollback remains Phase 13 (`#31`).
