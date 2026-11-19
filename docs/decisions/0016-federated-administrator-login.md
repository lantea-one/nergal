# ADR 0016 — Federated administrator identity and expiry

An explicitly configured group in a validated OIDC ID token grants administrator
access. The local password account remains independent. A federated identity is
the exact issuer and subject pair. Never enroll or link users by names or email.
Compare the configured group claim and group values ordinally, without case
folding, substring matching, implicit wildcard groups or automatic role mapping.

Use the authorization code flow with PKCE, state, correlation and nonce checks
through the ASP.NET Core OIDC handler. A fixed HTTPS issuer, client ID and exact
registered callback URI are trusted installation inputs. Never derive the redirect
authority from an arbitrary request Host. Require signed, current ID tokens for
the expected issuer and client. Group membership comes from the signed ID token.
No userinfo or browser claim overlay can add authority.

An administrator session ends at the earlier of token expiry and fifteen minutes
after token issuance. Activity cannot renew it. Further access requires another
authorization-code exchange with fresh claims. Group removal can therefore take
up to fifteen minutes to take effect. Local password verification and sessions
continue independently if the external provider is unavailable.

Use a separate, host-only cookie for federated sessions. Keep federated session identifiers and deadlines
in a bounded process-local registry, so local sign-out revokes replay of that ticket.
Restart requires a fresh OIDC login. No access, refresh or raw ID token is saved
in application cookies. Identity-provider global logout and multi-controller
session replication are outside this single-controller implementation.

Sources: [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
and [ASP.NET Core OIDC configuration](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/configure-oidc-web-authentication?view=aspnetcore-10.0).
