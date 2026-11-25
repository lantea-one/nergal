# ADR 0062 — Complete local authentication after MFA

Status: TOTP and local/LDAP browser implementation for M5. Email delivery
and per-provider assurance remain separate acceptance gates.

Local passwords and LDAP binds establish first-factor proof. The protected
identity store decides whether that proof can become an authenticated session.
Keep the existing local account verification and attempt accounting. For LDAP,
carry the verified directory identity, role, first-factor UTC time and committed
connection generation. Keep directory and email I/O outside database
transactions. Fresh account schema 6 seeds the policy and stores pending
proofs, factors, LDAP sessions and LDAP profile observations.

The local policy has three modes: optional enrollment, required for
Administrators, and required for every local or LDAP sign-in. A user who enables
a factor must present it on future sign-in. Requiring MFA blocks sign-in for
users without a verified factor. Enrollment or recovery after enforcement
requires an explicit authorization separate from a password-only proof.
A fresh installation explicitly initializes optional mode. Missing or unreadable
policy denies completion. Before enforcing
a policy that requires MFA for Administrators, require at least one enabled
local Administrator with a verified usable factor. Apply the same invariant to
account, factor and delivery changes. LDAP, OIDC and OAuth accounts do not count
toward local recovery.

Store the pending proof server-side. Give its browser a short-lived protected
continuation identifier that cannot authorize application endpoints. Bind the
proof to the browser, actor, verified role and relevant account, provider and
policy generations. Limit attempts per proof and across retries for the same
actor. Completion rechecks all generations, current authority, proof ordering
and expiry. In one transaction consume the pending proof and accepted factor,
commit any authorized LDAP profile refresh, retire superseded sessions and
append identity audit. Only then issue the protected session cookie. An older
pending proof cannot restore a role or session superseded by a newer sign-in.

Start with TOTP enrollment and verification using RFC 6238, a 30-second step and
six digits. Encrypt independently generated seeds per actor and enrollment.
Activate enrollment only after verifying a current code. Store the accepted
time step and advance it atomically to deny reuse across concurrent requests
and process restarts. Never expose an enrolled seed again. Keep success,
failure and administration audit free of secrets and codes.

Implement email as a separate factor with an independently verified delivery
address and administrator-managed delivery settings. Profile email remains
descriptive. Email code delivery, resend limits and consumption need separate
acceptance before email can satisfy the policy. OIDC and OAuth bypass require
an explicit provider decision and, when configured, the required signed MFA
assurance. LDAP always follows the local policy. Until provider-specific assurance is
available, the OIDC flow denies roles that require MFA under the local policy.
Changing policy retires old browser sessions across the three sign-in methods.

Verify wrong, expired and reused codes, concurrent completion, policy and
connection edits during a pending proof, rollback on audit failure, last
Administrator recovery, and replay of retired protected cookies. Exercise the
local and LDAP HTTPS sign-in paths with independent synthetic identities, and
preserve existing OIDC issuer and session-generation checks.

Sources: [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) and
[RFC 4226](https://www.rfc-editor.org/rfc/rfc4226).
