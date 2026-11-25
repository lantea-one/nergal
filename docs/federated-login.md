# Optional OIDC administrator login

Enable OIDC alongside the [local administrator](local-sessions.md) to allow members
of configured identity-provider groups to use the controller. Each person retains
their own exact issuer and subject. The local account, password, security stamp and
provisioning database are independent. No local enrollment is required for group
members. User names, emails and display names cannot link identities or grant access.

Use the [UI-managed connection](oidc-connection.md) for normal administration.
The following protected startup keys are optional bootstrap inputs only, before
a database-managed connection exists. A saved disabled connection never falls back
to these inputs.

| Bootstrap configuration key | Meaning |
| --- | --- |
| `Oidc:Enabled` | Enable the external login button and callback on the direct HTTPS local session host |
| `Oidc:Issuer` | Exact HTTPS issuer identifier, including its realm path where applicable |
| `Oidc:ClientId` | Confidential web client ID and sole allowed ID-token audience |
| `Oidc:ClientSecret` | Supply through a protected configuration source and restrict access to that source |
| `Oidc:CallbackUri` | Exact registered HTTPS URI with path `/signin-oidc`, without query or fragment |
| `Oidc:GroupClaim` | Top-level signed ID-token claim containing an array of group strings |
| `Oidc:AdministratorGroups` | Indexed list of 1–32 exact, case-sensitive authorized values |

Configure the provider for code flow with S256 PKCE, form-post responses, a
confidential client secret and RS256-signed ID tokens. Put the group array in the
ID token for the requested `openid profile email` scopes. Discovery, signing-key and token
backchannels stay on the configured issuer's HTTPS origin and refuse HTTP
redirects. An external authorization endpoint must use the same origin. A provider
installation with split endpoint origins or a different signing algorithm needs
additional explicitly tested support. There is no provider-specific group default.

The login form starts the challenge with a CSRF-protected POST. The framework
validates state, correlation, nonce, signing key, token lifetime, issuer and
audience. The callback URI is fixed in configuration and must match the actual
request. Authorization also checks duplicate claims, exact audience (including
authorized party if present), bounded subject and group values, issuance time
and expiry. At least one configured group must match. The controller retains
only the issuer, subject, identity derived from that pair and session identifier.
It never requests downstream API access or stores access/refresh/ID tokens in
the session. Subject and issuer are available to application code for individual
attribution. Identity/profile changes and configuration saves use the identity-store audit;
controller actions use their separate controller audit boundary.

The protected federated cookie is nonpersistent, Secure, HttpOnly, host-only and
SameSite=Strict. Framework correlation and nonce cookies support the cross-site
form-post callback. Authorizations end at the earlier of token expiry and fifteen
minutes after ID-token issuance; activity cannot extend them. After group removal,
a previously validated session can therefore retain access for up to fifteen
minutes based on the old assertion. Continuing requires a fresh code exchange and
signed group evaluation. The identity provider must issue current group membership.

Each authenticated request must also match a bounded, in-process registration.
There are at most 1024 active registrations; expired entries are reclaimed at new
sign-in. Logout revokes that browser's registration and clears its cookie. Restart
invalidates all federated sessions. Other federated sessions and the local password
administrator remain independent. This is local RP logout, without global IdP logout,
multi-controller session sharing or back-channel revocation. The local password
method does not contact the issuer.

A federated administrator can use the same [read-only agent status](controller-status.md)
when enabled. Identity-provider membership grants no privileged journal or firewall
operation. See [ADR 0016](decisions/0016-federated-administrator-login.md).

An opt-in conformance fixture checks the upstream Keycloak 26.8.2 distribution
with its group-membership mapper in a synthetic realm. Both the provider and
controller use disposable loopback HTTPS. It confirms group-member admission and
outsider denial, including the provider's manual form-post fallback. Unrecognized
bounded callback fields are discarded under [RFC 6749 section 4.1.2](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2).
Duplicate fields and mixed token/code responses are rejected.
