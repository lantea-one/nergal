# Local administrator credential foundation

`Nergal.Identity` is Linux application-account infrastructure built on ASP.NET Core
Identity and EF Core SQLite. It does not depend on policy, compiler, privileged
journal or transport. The user selected local account/password authentication for
basic installations, with optional OIDC; ADR 0012 records that direction.

This document covers credential storage and verification. Web optionally adds
[local browser sessions](local-sessions.md). No public registration endpoint, default
account, automatic initialization or password reset exists.
Application accounts are not Linux users: no host account/group changes occur.

## Explicit creation and bootstrap provisioning

A trusted operator must first provision an existing nonsymlink service-owned 0700
local directory. `LocalAccountOptions` requires its explicit absolute NUL-free path;
it creates nothing. `LocalAccountDatabase.InitializeAsync` creates only a **new**
0600 `accounts.db`, schema 8 and application ID `0x4e524741`. Any existing database
or sidecar is refused. It creates no administrator and never adopts, upgrades or
repairs existing/partial state. A canceled/failed initialization can leave an
incomplete new file; subsequent access fails closed pending explicit offline repair.
The offline `nergal-admin` command exposes these operations to the store owner.
It never starts Web, contacts an identity provider, touches the agent journal or
changes a host account. The operator supplies an existing private directory.
Run the following as the application credential owner, with an absolute path:

```sh
nergal-admin account init "$account_directory"
nergal-admin account provision "$account_directory" "$administrator_name"
```

The second command reads and confirms a password from the terminal with echo
disabled before either prompt. The Linux terminal mode is captured and restored
through the fixed system utility `/usr/bin/stty`. No password is passed to a
subprocess. Normal completion, input errors and handled termination signals restore
the original mode. An uncatchable kill or loss of the terminal can prevent cleanup.

For automation append `--password-stdin` and supply a protected redirected input
stream. The command reads one bounded UTF-8 line to EOF with an optional final
LF or CRLF. Other whitespace is preserved. Multiple lines, malformed UTF-8 and
excess input fail. It accepts no password argument or password environment setting.
The existing Identity validation and store rules apply. CLI input buffers are
cleared; managed password strings used by Identity cannot be explicitly erased.

Use the Release apphost from `src/Nergal.Admin/bin/Release/net10.0` or invoke
`dotnet` with `nergal-admin.dll` from that build. Exit 0 means success, 2 means
invalid invocation/input mode, and 1 means provisioning or storage failed.
Initialization and provisioning can be retried independently after checking their
result. Neither command replaces an existing credential. A lost password still
requires a separately designed recovery procedure.

`AddLocalAdministratorAccounts` registers a single existing-store configuration,
standard Identity services and scoped `LocalAdministratorAccounts`; duplicate
store registration is refused. Each operation needs a fresh DI scope. The library
registers no browser authentication scheme. `ProvisionAsync` is an explicit trusted
local operation for the first administrator. It returns stable validation codes
without descriptions, supplied input or credentials. An immediate serialized
transaction prevents competing bootstrap accounts. Bootstrap cannot add a second
account or replace one; additional accounts use authenticated Administrator
management. Public signup and unattended credentials are not accepted. Normal verification never creates a missing database.

## Password and lockout behavior

Identity's versioned PBKDF2 hasher uses an explicitly configured 210,000 iterations
and fresh salts. Passwords are stored as hashes, never reversible text. Provisioned
passwords must contain 15–128 Unicode scalar values, with strict valid Unicode,
no normalization and no mandatory punctuation/case/digit rules. User names are
1–64 ASCII letters, digits, dot, dash or underscore and use Identity's normalized
case-insensitive lookup. Examples/tests contain synthetic credentials only; there
is no shipped production credential.

`VerifyAsync` returns only success plus a verified administrator UUID, or identical
failure with no identifier for unknown, incorrect and locked-out credentials.
Invalid-shaped names/passwords fail before verification. Unknown and already
locked accounts with valid-shaped input still incur a real dummy Identity password
verification; this does not claim perfect timing indistinguishability.

Five valid-shaped failed password attempts lock the account for fifteen minutes.
Successful verification resets failures. Each verification reserves a SQLite write
transaction before lookup and standard Identity sign-in checks/failure updates, so
concurrent callers cannot lose increments. State survives reopen. No session is
issued. Cancellation can stop before reservation; after credential evaluation
begins its decision commits despite caller disconnect, preventing cancellation
from rolling back failed-attempt accounting. A failed database operation throws a
stable store failure, never successful/partial credentials. Web rate limiting and
safe error presentation remain required before exposing this service over HTTP.
Two-factor/passwordless account state and disabled lockout are explicitly refused;
this password-only foundation must not silently bypass an unsupported second
factor or weaken its failure policy. Invalid administrator identifiers and malformed
stored hash encodings are stable store failures. There is no two-factor or passkey
enrollment/verification flow yet.

## Private storage and limitations

The database belongs to the controller's identity service account, separate from
the privileged firewall agent's account and state. The owner-only directory/file
policy checks effective UID, type, mode, link count and symlinks before SQLite opens;
known journal/WAL/SHM sidecars receive the same checks. Connections use no pooling,
explicit schema/application identity, integrity/foreign-key checks, DELETE journaling
and synchronous EXTRA. Identity/schema are rechecked under each reserved credential
transaction. No live mixed-version migration is supported. Existing directories
and trusted ancestors must be provisioned externally. Same-account/root attackers,
hostile ancestor races, remote filesystems and multi-node account storage remain
outside the prototype contract. Connection strings/queries are parameterized and
sensitive-data logging is not enabled.

Unit tests use real Identity hashing and private SQLite files for explicit creation,
concurrent bootstrap provisioning, concurrent failures, persisted lockout/reset,
Unicode/input bounds, pre-reservation cancellation, schema mismatch, unsafe files
and absence of plaintext credentials. The distinct-UID isolation fixture exercises
both stores independently: namespace UID 0 represents each store's service owner
and UID 1 an unrelated untrusted process. That fixture role choice does not imply
sharing controller/agent service identities in deployment. It verifies real DAC
denial, foreign-owner rejection, sidecars, hard links and FIFOs without host users.

Separate [protected Data Protection key storage](protected-session-keys.md) is now
implemented as a library. The optional session host now implements HTTPS login/logout, CSRF, rate limiting
and revocation. Authenticated agent status remains a separate milestone.
Optional [federated login](federated-login.md) uses separate issuer/subject identities and exact configured groups.


Authenticated Administrators now manage additional local accounts through
[Local users](local-users-and-profiles.md). Offline provisioning remains a
one-time bootstrap and cannot add or replace an existing account. Fresh account
The current schema removes the singleton constraint and requires explicit role claims,
per-account state and atomic identity audit. Prior unreleased account stores are
not supported by the web host; it never auto-migrates or resets them.

## Offline authenticator recovery

If a local Administrator cannot complete MFA, an operator with access to the
protected account directory can issue an authorization from a private
terminal:

```sh
nergal-admin account recover /absolute/private/accounts LOCAL_ADMINISTRATOR_UUID
```

Use the intended enabled local Administrator's stable account UUID. The command
shows the ten-minute authorization once on the terminal. Keep it out of logs
and use the local account recovery form with the account's current password.
Confirm a code from the newly configured TOTP authenticator, then sign in
normally. Issuance records the offline operator in the identity audit. Recovery
supersedes the prior authenticator only after the confirmation commits.
