# Web Controller & RBAC

`Nergal.Web` provides the browser-facing management UI (ASP.NET Core MVC + Blazor components) and authenticated JSON control endpoints without holding kernel privileges.

## Authentication & Sessions

- **Local Sessions**: Offline-provisioned local accounts stored in a private SQLite database (`nergal-admin account init` / `provision`), PBKDF2-SHA512 password hashing, per-account lockout, HTTPS-only `HttpOnly` `SameSite=Strict` cookies, and durable Data Protection keys protected by a dedicated wrapping certificate.
- **Optional OIDC**: Supports OpenID Connect Authorization Code + PKCE with strict issuer, audience, nonce, and `auth_time` validation plus configurable group-to-role mapping. Local sign-in remains independently available.

## Role-Based Access Control (RBAC)

| Role | Capabilities |
| --- | --- |
| `nergal:administrator` | Register/delete hosts, edit rules via visual builder or JSON, save policy revisions, start/confirm/rollback applies, view audit log. |
| `nergal:auditor` | Read fleet status, inspect policy revisions, preview compatibility/diffs, inspect visual bundle summary, view audit log. All mutating endpoints fail closed with HTTP `403`. |

## Visual Rule Builder & Diff Preview

`/manage/policies` renders:
1. **`PolicyBundleSummary.razor`**: Structured read-only tables of Filter rules (including inline CIDR/port sets and ICMP types), NAT rules, and Bridge rules.
2. **Visual Filter Rule Builder** (Administrator only, CSRF-protected): Appends validated rules (`/manage/policies/rules/add`), reorders rules (`/manage/policies/rules/move`), and removes rules (`/manage/policies/rules/remove`) using pure POCO transformations in `PolicyAuthoringService`.
3. **Compatibility & Unified Diff**: Compiles the draft in memory via `NftPolicyBundleCompiler` and shows a unified diff against any prior saved revision before saving.

## Append-Only Audit Trail

Every host registration/deletion, policy revision save, and apply start/confirm/rollback is recorded in `controller.db` (`audit_log`) with actor identity, role, timestamp, target, outcome, and detail code, viewable at `/manage/audit` and `GET /controller/audit`.
