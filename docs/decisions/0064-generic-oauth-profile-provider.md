# ADR 0064 — Generic OAuth profile provider

Status: Accepted for M5.

Configure one optional confidential OAuth 2.0 connection alongside OIDC and
LDAP. Require authorization code with S256 PKCE, private client credentials
and exact TLS callback binding. Accept identity only from the configured
current-user endpoint using the server-redeemed Bearer token. The deployment
must trust that endpoint to return one immutable subject and authoritative
group membership for the token holder. Use explicit HTTPS endpoints on the
same provider origin, a bounded JSON object and literal field selectors.
No access or refresh token becomes controller profile or session state.

Consume the verifier once. Keep the browser correlation handle through the
session deadline so a newer sign-in choice can cancel an in-flight exchange
or revoke its session registration before a delayed response is used. Bind
antiforgery forms to the canonical application actor, including the provider
namespace, since upstream subjects may coincide across connections.

Use a dedicated OAuth actor namespace. Changes to the upstream identity
binding replace that namespace; changes to any connection setting retire
outstanding challenges, tickets and provider defaults. Profile email and
local overrides remain descriptive. Refresh metadata and record the sign-in
decision together under the current configuration and MFA policy. The
required local MFA policy denies OAuth sign-in unless a local Administrator
explicitly trusts the provider to enforce it. Signed ID-token assurance is
specific to OIDC.

See [OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html) and
[PKCE](https://www.rfc-editor.org/rfc/rfc7636.html).
