# Local administrator sessions

With local sessions disabled (the default), the scaffold exposes its informational
pages and health endpoint. Login, logout and session routes are absent. Enable
local sessions only for an explicitly provisioned Linux installation with direct
Kestrel TLS. The controller runs as the application credential owner, separately
from the privileged firewall agent. It can verify passwords and issue tickets.

| Configuration key | Required value when enabled |
| --- | --- |
| `LocalSessions:Enabled` | `true` |
| `LocalSessions:AccountDirectory` | Existing 0700 directory containing the initialized account store |
| `LocalSessions:KeyDirectory` | Separate existing 0700 protected Data Protection directory |
| `LocalSessions:CertificateFile` | Absolute path to a private 0600, single-link PKCS#12 wrapping credential under a service-owned 0700 directory |
| `LocalSessions:RetainedCertificateFiles` | Optional indexed list of up to seven prior private wrapping credentials for key rotation |

Files must be locally controlled, with trusted ancestors. The wrapping credential
uses an empty PKCS#12 transport password. Restrict access to the file and its
backups as private keys. Loading uses an ephemeral key set. Configure Kestrel TLS
separately using its normal endpoint/certificate settings. TLS termination at a
reverse proxy is outside this slice. A forwarded scheme alone cannot satisfy the
direct TLS check. Health checks on the authenticated host also require HTTPS.

Startup checks the provisioned account and exercises the configured key ring
before listening. Provisioning uses the offline command documented in
[local credentials](local-administrator-accounts.md). There is no automatic seed,
public registration or reset. [Optional OIDC](federated-login.md) uses
a separate cookie, group authorization and session registry. The host suppresses ASP.NET Core's
separate default key-ring preload so that authentication, antiforgery and page
protection use the selected provider without creating a second profile key ring.

Open `/` to reach `/login` and submit the antiforgery-protected form. Successful
local or OIDC sign-in opens the overview at `/manage` when controller state is
enabled. Authenticated visits to `/` or `/login` also open the overview. A
session-only installation without controller state uses `/session` instead.
Redirect destinations are fixed; submitted return URLs cannot change them.
The protected session page remains available with identity details and a logout form.
Signing out returns to `/login`; revisiting `/` after sign-out also opens sign-in. Both POSTs validate antiforgery
tokens. The host bounds request bodies to 8 KiB. Login allows ten submissions per
process per minute with no queue. That shared budget also limits availability
under heavy failed-login traffic. Account lockout persists independently.

The application and antiforgery cookies are host-only, secure, HttpOnly and
SameSite=Strict. The application ticket uses the account state verified with
the password, expires after fifteen minutes and is never renewed by activity.
Every authenticated request validates its security stamp and supported credential
state. Lockout blocks new logins. POSTing to `/logout` rotates the current local
account stamp and clears the cookie, invalidating its other outstanding tickets.
An already-authorized request can finish. The separately enabled [controller status route](controller-status.md) requires
this session. The application has no privileged interactive Blazor component.

See [the decision record](decisions/0014-local-administrator-sessions.md) and
[protected session keys](protected-session-keys.md) for the security boundaries.


[Local users and profiles](local-users-and-profiles.md) add Administrator-only
account management, current-role/stamp rechecks, last-enabled-administrator
protection and atomic identity-store audit. Disabling/role changes and password
changes revoke affected tickets; they cannot resurrect previous cookies. Profile
display names cannot affect authority. Account schema 3 requires fresh initialization;
there is no supported migration from unreleased schemas. Email/TOTP MFA and the
new provider integrations remain open M5 gates, not implemented session assurances.

Browser HTML navigation now redirects to a fixed `/login` when authentication is
required, including expired/revoked-cookie refreshes. JSON/API clients retain
401/403 status semantics. Themed error pages preserve error status and render
independently from profile/credential reads. Login failures still use their generic
credential form; no request return URL controls navigation.
