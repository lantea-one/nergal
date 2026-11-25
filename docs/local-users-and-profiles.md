# Local users and personal profiles

Local users are application identities, separate from Linux accounts and enrolled
agents. A trusted operator initializes the private account database and provisions
its first account once. Administrators then use **System / Local users** for
routine access management. There is no public registration or password recovery.
This unreleased schema targets fresh installations; no previous account-store
version is adopted, migrated or reset by the application.

## Access management

- Create an explicitly named local Administrator or Auditor. Names use 1–64 ASCII
  letters, digits, dots, underscores or hyphens and are case-insensitive. Initial
  passwords use the existing Identity hasher and 15–128 Unicode-character bounds.
  A local Administrator is required to grant or restore local Administrator access.
- Change a role or use the switch in **Access**, then choose **Save access**. Disabling retains
  the account identity, profile and history. It blocks password sign-in and
  invalidates existing tickets; reenabling cannot resurrect old tickets.
- Keep at least one enabled local Administrator. The check runs inside the same
  serialized transaction as the change. Concurrent self-demotions cannot remove
  the last Administrator. External group membership is not counted as a local
  recovery account. A deliberately Auditor-only bootstrap cannot manage users.
- **Revoke sessions** rotates the selected account's stamp without resetting its
  password. Security changes and password changes also revoke affected tickets.
  An already-authorized request may finish, but a subsequent mutation rechecks a
  local actor's current stamp, role and enabled state under reservation.
- Expected versions reject stale forms. Unknown/repeated fields, unsupported roles,
  absent CSRF and unauthorized callers cannot change account state. The current
  installation limit is 256 local accounts.

Auditors can edit their own profile and local password. They cannot list other
accounts or read identity audit. Local account deletion and remote credential
reset are not exposed. Credential changes are explicit local-user operations;
none modify production accounts automatically.

## Profiles and credentials

**System / My profile & session** shows the verified sign-in name and role
separately from optional display-name, given-name, family-name and profile-email overrides. The override is database-backed,
versioned, escaped on output and used in the desktop profile link. It cannot grant
a role or change/link identity. Blank fields use current provider defaults; display name falls back to the verified identity name. Profile email does not verify delivery or enroll MFA. Names
can contain up to 80 Unicode characters, with malformed Unicode/control characters
denied. Profile reads do not create rows or audit entries.

Profiles use canonical local, OIDC, OAuth or LDAP actors. Equal display names
or email claims cannot merge identities. Provider users can save their own local
overrides and manage their credentials at their provider.

A local password change requires the current password. Incorrect verification
persists lockout accounting even when the HTTP caller disconnects. Successful
change revokes old tickets, clears the browser cookie and returns to sign-in.
Both sign-in and password-change endpoints have independent process-wide limits
of ten submissions per minute; per-account failure lockout remains independent.
Passwords never enter view models or audit events.

## Storage and audit

The private credential database uses account schema 8 with explicit role claims,
per-account state, personal profiles and append-only identity audit. Mappings and provider observations remain separate from local metadata overrides. The former
singleton slot is removed. Missing roles fail closed; there is no implicit
Administrator default. Initialization creates no user; offline provisioning remains
one-time bootstrap even though authenticated management can add more accounts.
Ordinary startup refuses old/unknown or incomplete storage.

**Local users / User and profile activity** shows the latest 100 identity events.
Account changes, stamp rotation and identity audit commit atomically in the same
protected account store. They are not falsely presented as one transaction with
`controller.db`. Configuration history remains under **Activity & audit**. Audit
rows contain identifiers, stable actions and UTC instants, not passwords/hashes.
Update/delete triggers and their definitions are checked. Displayed timestamps
use the browser timezone and retain explicit UTC details.

See [ADR 0058](decisions/0058-local-users-and-profile-boundary.md),
[local sessions](local-sessions.md) and [private credentials](local-administrator-accounts.md).
The existing private-path, protected-key, fifteen-minute session, CSRF and Linux
process/agent boundaries remain in force.

## Authenticator sign-in and LDAP

A signed-in local or LDAP user can open **Profile → Authenticator**, start
setup, and enter the displayed manual key in a six-digit TOTP authenticator.
Confirm a current code to activate the factor, then sign in again. Save the
authenticator securely. Setup keys are displayed during enrollment only.

A local Administrator manages **Settings → Authentication → MFA policy**.
Optional mode asks enrolled users for their factor. Administrator and
all-user modes also deny sign-in to required users who lack a verified factor.
Enroll the relevant users before enforcement. A policy change retires old
sessions. OIDC users subject to the policy need an explicit provider assurance
configuration under **OIDC connection**, with signed-token assurance available.

A local Administrator manages the active connection in **Settings →
Authentication → LDAP connection**. Enter one LDAPS endpoint and dial IP, the
read-only search account, the user search base, and the two direct role groups.
The LDAP sign-in form appears after the connection is enabled. LDAP shares
the authenticator flow and populates descriptive defaults from verified
directory attributes. Personal edits override defaults field by field.

### Email and recovery

A local Administrator configures the SMTP relay from **Settings →
Authentication → Email delivery**. The relay must support STARTTLS with a
certificate trusted by the controller. Local and LDAP users verify an explicit
mailbox under **Profile → Email factor**. Sending a code does not change the
profile email. An enrolled authenticator remains the preferred factor.
Local Administrator access always retains a path independent of the relay.

A local Administrator can issue a one-time authorization under **Settings →
Authentication → Issue MFA recovery authorization**. Give it to the intended
account holder through a private channel. The recipient selects recovery on
the sign-in page, provides their current credentials and verifies a new
authenticator. The authorization grants access only to setup. A protected
offline command supports local Administrator recovery.

OIDC connections can deny sign-in for roles requiring MFA, explicitly trust
the provider to enforce MFA, or require an exact assurance value in a signed
ID token. Configure the mode in the active OIDC connection. Generic OAuth
remains open.

Browser page navigation redirects to sign-in when a session is required. API
clients keep status-code responses. Themed 403/404/503 pages retain the original
status and offer a fixed local recovery link without showing exception details.
They render without profile-store dependencies. The main content uses the width
beside the icon-based sidebar, with centered browser timezone at the sidebar bottom
and no page footer. Profile sections adapt to that space; shared form fields use
consistent surfaces, sizing, hints and focus/error states.

## Screenshots

These screenshots use an isolated synthetic installation. They contain no private
server exports, credentials or production accounts.

![Local users in dark theme](../pages/assets/screenshots/m5-users-dark.jpg)

[Light theme](../pages/assets/screenshots/m5-users-light.jpg),
[personal profile](../pages/assets/screenshots/m5-profile-light.jpg),
[dark profile](../pages/assets/screenshots/m5-profile-dark.jpg),
[mobile profile](../pages/assets/screenshots/m5-profile-mobile.jpg),
[mobile navigation](../pages/assets/screenshots/m5-navigation-mobile.jpg) and
[error recovery](../pages/assets/screenshots/m5-error-dark.jpg) show the shared UI.

The same control appears in [dark settings](../pages/assets/screenshots/enablement-settings-dark.jpg)
and [light settings](../pages/assets/screenshots/enablement-settings-light.jpg).
