# ADR 0031 — Two-phase web confirmed-apply workflow and authenticated agent dispatch

- Status: accepted
- Date: November 21, 2026

## Decision

1. **Unprivileged controller dispatch boundary**:
   `Nergal.Web` dispatches control commands exclusively as typed
   `AgentControlRequest` payloads over `UnixControlClient` (`SO_PEERCRED` peer-UID
   verification) or `TlsControlClient` (pinned TLS 1.3 mTLS). When
   `ControllerState:TlsClientCertificatePath` and
   `ControllerState:TlsClientKeyPath` are configured, the private key must be an
   owner-only `0600` regular file in a safe directory with no symlink ancestors,
   and every TLS host endpoint requires an explicit pinned SHA-256 server
   thumbprint.

2. **Two-phase confirmed apply and watchdog synchronization**:
   `ApplyWorkflowService` mediates `PrepareApply` (with bounded 1–3600s timeout),
   `Confirm`, `Rollback`, and `Status` polling for registered hosts, recording
   each action (`apply.start`, `apply.confirm`, `apply.rollback`) and outcome in
   `ControllerStateStore`'s append-only SQLite audit log and updating
   `hosts.last_known_revision` when live status or confirmation advances or
   rolls back the enforced baseline revision.

3. **Fail-closed single-table scope enforcement**:
   Because the Phase 10 `AgentControlRequest` contract applies typed
   `FilterPolicy` payloads to each host's owned `inet nergal_filter` table,
   bundles containing `nat` or `bridge` tables are rejected fail-closed
   (`policy.unsupportedScope`) and audited without dispatching partial policy.

4. **Strict RBAC and antiforgery enforcement**:
   `GET /manage/apply` and `GET /controller/apply/status` allow `NergalReader`
   (`Administrator` or `Auditor`) read-only inspection of live agent phase and
   countdown timers, while all `start`, `confirm`, and `rollback` mutations
   (`POST /manage/apply/*` and `POST /controller/apply/*`) require
   `NergalAdministrator` and validated antiforgery tokens.
