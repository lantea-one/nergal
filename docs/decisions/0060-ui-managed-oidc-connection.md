# ADR 0060 — UI-managed OIDC connection and trust generations

One optional OIDC connection is managed by local Administrators in the protected
identity database. Local sign-in remains independent and cannot be disabled here.
Exact issuer, client, callback, literal group claim and disjoint exact role groups
are explicit inputs. Save uses expected versions, current local authority, CSRF
and atomic identity audit. Secrets are write-only form inputs, encrypted with a
dedicated purpose under the certificate-protected application Data Protection ring;
blank retains an existing secret, and changing issuer/client requires a replacement.
No browser response, audit or diagnostic includes secret or ciphertext values.

Every request reads one immutable connection snapshot before authentication.
Framework OIDC options are cached by database generation in a bounded cache;
requests never mutate options already used by another handler. Signature, issuer,
audience, nonce, correlation, PKCE and fixed callback checks remain mandatory.
Protected challenge state and federated tickets bind the connection generation.
Retired state is rejected before authorization-code redemption, so a new provider
cannot receive a prior generation's code. Callback completion rechecks the latest committed generation, and subsequent cookie
validation denies tickets from retired generations, including secret/role edits or
disabling. No callback or session can silently adopt newly configured trust.

Before a database connection has been saved, explicitly supplied protected startup
OIDC configuration remains an operator bootstrap input. A saved row, including a
disabled row, always wins; deleting/unreadable state is never a fallback mechanism.
The configuration database is the source of truth for UI-managed connection state.
Fresh account schema 4 adds one typed connection row; no legacy product upgrade
path is shipped. Private development data is preserved with backed-up offline
maintenance while all consumers are stopped.

Saving performs no discovery or directory requests. Provider traffic occurs only
on an explicit sign-in and retains HTTPS certificate validation, exact discovery
issuer and same-origin restricted backchannel behavior. Authentication failures
never expose provider response bodies or secrets. This slice supports confidential
OIDC code flow, one provider, and existing RS256/group-role policy; generic OAuth,
LDAP, MFA and multiple-provider routing are separate work.

Sources: [ASP.NET Core OIDC](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/configure-oidc-web-authentication?view=aspnetcore-10.0)
and [named options](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/configuration/options?view=aspnetcore-10.0).

Remove the framework profile-key preloader after all authentication registration;
registering the optional handler must never recreate an ambient key ring. The real
HTTPS fixture verifies no profile key files are generated.
