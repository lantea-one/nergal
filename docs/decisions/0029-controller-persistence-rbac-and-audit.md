# ADR 0029 — Controller persistence, role-based access control, and append-only audit log

- Status: accepted
- Date: November 21, 2026

## Decision

1. **Dedicated controller SQLite store (`Nergal.ControllerState`)**:
   Persist registered agent hosts, immutable policy revisions, and an append-only
   audit log in a controller-owned SQLite WAL database (`controller.db`) separated
   from agent local journals (`Nergal.LocalState`) and application accounts
   (`Nergal.Identity`). Both initialization and opening enforce an owner-only `0700`
   nonsymlink directory and `0600` regular database file (`PRAGMA application_id=0x4e524743`,
   `PRAGMA user_version=1`, `PRAGMA synchronous=FULL`, `PRAGMA foreign_keys=ON`).
   SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers on `audit_log` prevent mutation
   or deletion of recorded audit events.

2. **Explicit `Administrator` and `Auditor` RBAC (`Nergal.Core`, `Nergal.Identity`, `Nergal.Web`)**:
   Define canonical roles (`nergal:administrator` and `nergal:auditor`) and canonical
   actor attribution (`local:<uuid>` or `oidc:<issuer>:<subject>`). Map explicit
   local role claims and configured OIDC groups (`Oidc:AdministratorGroups` /
   `Oidc:AllowedGroups` and `Oidc:AuditorGroups`) into session principals at
   authentication time, keeping anonymous access denied and restricting mutating
   endpoints to `NergalAdministrator` while permitting read-only observation on
   `NergalReader` (`Administrator` and `Auditor`).

## Remaining boundary

Web policy authoring views, compatibility/diff previews, live agent two-phase
confirmed apply workflows from the browser, and systemd unit packaging remain
Milestone D (Phases 12–14).
