# ADR 0063 — Email factors, enrollment recovery and OIDC assurance

Status: Accepted for M5 identity completion.

Local Administrators configure SMTP delivery in the protected identity store.
Require validated TLS peer trust for SMTP STARTTLS. Bind any encrypted delivery
credential to the server and credential identity, and version changes with
audit. Profile email is descriptive. An address can become a second factor only
after the actor verifies a code delivered to that address. Bind verification
and sign-in codes to their exact purpose, actor, expiry and generation. Persist
only protected verification material. Limit sends and attempts across replaced
proofs, and consume a matching code atomically with the identity decision.
Reserve delivery in the database and perform network I/O after commit.
An enrolled TOTP authenticator remains the preferred factor. Keep local recovery
independent of SMTP. Before a local Administrator enrolls email as their only
factor, confirm another enabled local Administrator can sign in independently
of the relay. Use the same eligibility checks when enforcing MFA or removing
local Administrator access inside the serialized account transaction. Only a
local Administrator can confer usable local Administrator access.

Recovery requires an explicit short-lived, single-use authorization from a
current local Administrator or a protected offline recovery operation. Bind
authorization to one actor and the current MFA policy and first-factor trust.
Require fresh local or LDAP credentials and prove possession of a new TOTP
authenticator before replacing an existing factor. Pending enrollment grants
no application authority. Consume recovery and the accepted code together,
retire older sessions and proofs, and append audit. Recovery does not link
identities through profile email or a directory login name.

OIDC assurance is configured per connection by a local Administrator. When the
current local policy requires MFA for the proven OIDC role, require an explicit
connection bypass decision, optionally backed by an exact signed ID-token
assurance claim and value. Never use user-info claims for this decision. Reject
missing, invalid or ambiguous evidence. Bind accepted sessions to both the
connection and local policy generations, including the current callback and
transactional profile-refresh checks.

Read the managed connection and its audit watermark in one SQLite snapshot.
Absent managed configuration can use operator bootstrap. An unreadable or
rolled-back managed connection disables OIDC while local recovery remains
available. Bind bootstrap challenges to the startup that created them so a
new process cannot redeem a challenge under different bootstrap settings.

References include [.NET SMTP STARTTLS behavior](https://learn.microsoft.com/en-us/dotnet/api/system.net.mail.smtpclient.enablessl?view=net-10.0)
and [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html).
