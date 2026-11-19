# Local administrator sessions

With local sessions disabled (the default), the scaffold exposes its informational
pages and health endpoint. Login, logout and session routes are absent. Enable
local sessions only for an explicitly provisioned Linux installation with direct
Kestrel TLS. The controller runs as the application credential owner, separately
from the privileged firewall agent. It can verify passwords and issue tickets.

| Configuration key | Required value when enabled |
| --- | --- |
| `LocalSessions:Enabled` | `true` |
| `LocalSessions:AccountDirectory` | Existing 0700 directory containing the initialized singleton account |
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
before listening. Provisioning still uses the explicit trusted library API in
[local credentials](local-administrator-accounts.md). There is no automatic seed,
operator CLI, registration, reset or OIDC login. The host suppresses ASP.NET Core's
separate default key-ring preload so that authentication, antiforgery and page
protection use the selected provider without creating a second profile key ring.

Visit `/login` and submit the antiforgery-protected form. A successful verification
redirects to `/session`. Redirect destinations are fixed. The protected page
shows the signed-in administrator and a logout form. Both POSTs validate antiforgery
tokens. The host bounds request bodies to 8 KiB. Login allows ten submissions per
process per minute with no queue. That shared budget also limits availability
under heavy failed-login traffic. Account lockout persists independently.

The application and antiforgery cookies are host-only, secure, HttpOnly and
SameSite=Strict. The application ticket uses the account state verified with
the password, expires after fifteen minutes and is never renewed by activity.
Every authenticated request validates its security stamp and supported credential
state. Lockout blocks new logins. POSTing to `/logout` rotates the singleton
account stamp and clears the cookie, invalidating its other outstanding tickets.
An already-authorized request can finish. There are no privileged interactive
Blazor components or agent-backed routes in this milestone.

See [the decision record](decisions/0014-local-administrator-sessions.md) and
[protected session keys](protected-session-keys.md) for the security boundaries.
