# ADR 0012: explicit local administrator credential foundation

- Status: accepted
- Date: November 19, 2026

The user selected a local administrator account/password for a basic installation,
with OIDC as an optional future login method. Build credential storage before
exposing authenticated controller routes. Local application accounts are separate
from Linux users, firewall enrollment and the privileged agent journal.

Use ASP.NET Core Identity's versioned password hasher, user manager and sign-in
verification/lockout logic, backed by its EF Core SQLite store. Do not invent a
password hash or store reversible passwords. Set PBKDF2 iteration count explicitly
to 210,000, require 15–128 character passwords without composition rules, and
configure five failures to lock the account for fifteen minutes. No password,
hash, raw database error or distinction between unknown/bad/locked-out accounts
is returned by the verification contract. Unknown users still incur a real dummy
Identity password verification. Verification and failure/reset updates share a
serialized database write transaction, avoiding lost lockout updates across callers.
Cancellation after verification starts cannot roll back failure accounting.
Unsupported two-factor/passwordless state and disabled lockout are refused rather
than silently bypassing those semantics; no two-factor flow is implemented here.

Provision exactly one local administrator through an explicit trusted local API,
never a browser registration endpoint, startup seed, default password or automatic
recovery/reset. A database constraint backs the singleton boundary. Initialize and
provision are distinct operations; normal use never creates or migrates a database.
Unknown/partial schemas fail closed and no existing file is adopted. No host
accounts/groups or production application accounts are created during development.

Keep the database under a service-owned 0700 nonsymlink trusted directory, with
0600 single-link database/sidecars and ownership/type checks before connection.
Use a separate application/schema identity, real SQLite transactions and no pooling.
Do not share storage, credentials or authority with the privileged journal. Hostile
ancestors, same-account/root attacks and multi-node account storage are outside the
prototype boundary. No secret is logged or shipped in examples/defaults.

This foundation issues no browser cookie and configures no login endpoint. Before
real sessions, add explicitly provisioned durable protected Data Protection keys,
HTTPS-only cookies/forms, CSRF, session revocation, rate limiting, local-return-URL
validation and isolated HTTP tests. OIDC issuer/audience/claims validation remains
future work, not an implicit login fallback.

Sources: [Identity configuration](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-configuration?view=aspnetcore-10.0),
[Data Protection](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/introduction?view=aspnetcore-10.0).
