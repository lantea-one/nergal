# OAuth connection

Open **Settings → Authentication → Configure OAuth connection** as a local
Administrator. Use this connection with an OAuth 2.0 provider that offers a
confidential authorization-code client and an authenticated current-user JSON
endpoint. Nergal sends a Bearer token to that endpoint after exchanging the
code server-side. OAuth itself does not standardize a user profile, so verify
that your provider meets the contract below.

1. Register the exact controller HTTPS callback ending in `/signin-oauth`.
   Register a confidential client that supports S256 PKCE and
   `client_secret_basic` token endpoint authentication.
2. Enter the authorization, token and current-user endpoints on one HTTPS
   origin, the client ID and secret, and the scopes needed to read the current
   account and its groups. The token endpoint must return a Bearer token in a
   JSON response. If the response declares a lifetime in seconds, Nergal caps
   the application session at that deadline. The provider redirects
   to the callback with code and state. This connection does not support the
   optional RFC 9207 issuer response parameter.
3. Choose a current-user field containing an immutable nonempty string ID
   and a field containing an array of group names. Enter at least one exact
   Administrator or Auditor group. Nergal denies accounts that match both
   roles. Select optional descriptive fields such as display name or email
   with literal top-level JSON names.
4. Choose whether OAuth sign-in is allowed when the local policy requires
   MFA. The default is to deny it. Select explicit trust only when the
   provider independently enforces MFA for the admitted users.
5. Enable the connection, confirm the trust change and save. Try **Sign in
   with OAuth** from a separate browser session.

The controller keeps the encrypted client secret in the private account store
and displays its presence. Replacing the upstream identity binding requires a
secret and establishes a fresh actor namespace. Every save retires current
OAuth sessions and outstanding challenges. The current-user observation and
local profile overrides have separate provenance. A matching email does not
link OAuth, OIDC, LDAP and local identities. Access and refresh tokens do not
enter the account database, audit or browser session.

The controller accepts current-user and token responses up to 64 KiB as JSON.
The current-user endpoint and token endpoint use TLS certificate verification,
a bounded response deadline and no redirects. Reverse proxies and access logs
should omit query strings for the OAuth callback. Keep a local Administrator
available independently of the provider.
