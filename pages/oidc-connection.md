# Configure an OpenID Connect provider

Sign in as a **local Administrator**, then open **Settings → Authentication →
Configure active OIDC connection**. The same connection serves independent users
whose signed groups match the configured roles. Local sign-in stays available
when the provider is disabled or unavailable.

1. Create a confidential web client at your provider, using authorization code
   flow, S256 PKCE, form-post responses and RS256 ID tokens.
2. Enter the exact HTTPS issuer, client ID and registered HTTPS callback URL.
   The callback path is `/signin-oidc`, with no query, fragment or credentials.
   Nergal must be reached through that callback's exact host/port.
3. Enter the client secret. It is encrypted in the private identity database under
   the certificate-protected application key ring and never displayed again.
4. Enter the literal top-level signed groups claim, and one exact group per line
   for Administrator and/or Auditor. At least one role group is required, with at
   most 32 per role. Values are case-sensitive, distinct, and disjoint across roles.
5. Enable provider sign-in, review the replacement notice, and select **Save and
   replace provider settings**. Changes apply on the next request, without restart.
6. Use another browser session to test **Sign in with identity provider**. Configure
   [profile field mappings](oidc-profile-defaults.md) separately for descriptive
   defaults and personal overrides.

Saving does not contact the provider or verify its availability. Provider discovery,
keys and token requests happen during explicit sign-in. HTTPS trust validation is
mandatory, endpoints must remain on the issuer's origin and HTTP redirects are
refused. Split-origin endpoints, different signing algorithms, generic OAuth,
LDAP, multiple concurrent providers and MFA are not implemented by this screen.
Requested scopes are fixed to `openid profile email`; group data must be in the
signed ID token. There is no UserInfo lookup or downstream API token storage.

![OIDC connection form in dark mode](assets/screenshots/oidc-connection-dark.jpg)

The screenshot shows an **unsaved synthetic example**. It does not configure a live
provider or demonstrate a successful live-provider connection.

## Replacing or disabling a connection

Every save uses the displayed configuration version and atomically records an
attributed identity audit event. Reload if another administrator changed it first.
Saving retires all existing federated sessions and in-flight federated sign-ins,
even if only groups or the secret changed. Fresh sign-in uses the new generation.
Local sessions are unaffected. Only a currently authorized local Administrator can
change connection trust; external Administrators can view its credential-free status.

Leave the secret field blank to retain the stored secret for the same issuer and
client ID. Changing either requires a replacement secret. Disabling retains the
configuration and encrypted secret while hiding the provider sign-in button.
No secret/ciphertext is returned in forms, errors or audit events. The total form
body is bounded to 32 KiB; unknown/repeated fields or unconfirmed replacement fail.


## Storage and bootstrap

Fresh account schema 4 stores one typed OIDC connection row, its version, UTC
update time and protected secret in the private account database. Keep the entire
protected session key ring and current/retained wrapping certificates with backups:
losing them prevents decryption. Timestamps display in the browser's local timezone.
Normal startup never upgrades, replaces or resets an old account schema.

Before a UI-managed row exists, protected `Oidc:*` startup configuration can supply
an optional operator bootstrap connection. The first UI save requires its secret
again. Afterwards the saved row always wins, including while disabled; unreadable,
missing previously saved or corrupt state fails closed instead of reverting to
bootstrap trust. General Settings authentication fields remain saved intent and do
not control this connection. The dedicated screen reports active managed settings.

## Verified boundary

Real loopback HTTPS checks exercise UI-only setup, signed code/PKCE exchanges,
secret retention, denial of secret reflection, expected versions, local versus
external authority, CSRF, audit-failure rollback, old-cookie and in-flight callback
retirement, disabling/re-enabling and restart persistence. Unit tests verify exact
trust validation, defensive groups, real SQLite transactions, wrong-key/tampered
secret denial and missing-row failure. Browser checks cover the connection fields, keyboard switch, secret-empty state
and dark desktop layout. New light/mobile connection captures remain unverified;
existing shared form/theme coverage does not establish this screen's visual acceptance. No production identity provider or account is changed.
See the repository decision record ADR 0060.
