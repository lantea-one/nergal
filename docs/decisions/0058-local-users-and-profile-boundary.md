# ADR 0058: Local users, profiles and credential audit

Status: Accepted for M5 implementation; the milestone remains open.

Extend the explicitly provisioned private account store to support local
Administrator/Auditor accounts. Offline provisioning remains a one-time bootstrap;
there is no public registration, automatic seed or password recovery. Additional
users require an authenticated Administrator. Disable accounts rather than delete
identities referenced by history. Role changes, disablement, password changes and
explicit revocation invalidate the affected account's existing tickets. Logout
continues to revoke that account's local sessions only.

Use serialized account-store transactions for the current actor recheck, expected
version, last-enabled-local-administrator invariant, account mutation, stamp
rotation and append-only identity audit. Do not count a configured external group
as an available local recovery administrator. A concurrent demotion/disable cannot
remove the last enabled local Administrator. Existing Auditor-only bootstraps can
still sign in but require offline operational recovery before user administration.

Keep credential decisions and their audit in the same protected account database;
pretending to atomically write the separate controller audit database is unsafe.
The Users page exposes identity audit separately and explains this boundary. Audit
records contain actor/target identifiers, action and UTC time, never passwords or
hashes. Guard audit definitions and append-only triggers when opening the store.
Profile metadata is separate from authentication identity and authority. Profiles
are keyed by canonical local UUID or exact validated issuer/subject actor identity;
never link accounts through display name or email. Local profile overrides must
remain distinct from provider-supplied defaults and their provenance.

This project is unreleased: target freshly initialized account schema 2 only.
Remove the singleton slot/index entirely. No account upgrade command or legacy
compatibility path is shipped. Ordinary web startup never migrates or resets
storage. Keep the existing disposable sandbox data protected separately; that
local development maintenance is not a supported product migration. M6's SQL
backend/schema work remains deferred until the logical model stabilizes.

All mutating forms require current authorization, CSRF, bounded strict inputs and
explicit expected versions. Revalidate local actor authority inside the serialized
mutation, rather than trusting a previously issued cookie role. OIDC authority
retains its validated issuer/subject/group/expiry boundary. Provider profile
mapping must not mint roles or change identity. LDAP and OAuth-only authentication
and profile mappings require their own verified integration contracts; they are
not interchangeable with OIDC tokens. No production account/provider changes
follow from implementing or testing these features.

Verify real SQLite races, stale/invalid/denied operations, audit rollback and
immutability, fresh initialization and unknown-schema denial; real HTTPS role/CSRF,
revocation/replay and profile isolation; and synthetic light/dark/mobile workflows.

Additional M5 identity requirements: direct LDAP sign-in/profile mapping and
configurable OIDC/OAuth profile defaults with local overrides. Local MFA must
support email and TOTP, optional enrollment plus administrator policy requiring
MFA for Administrators/all/neither. Existing development configurations begin
with no requirement until enrollment and delivery configuration are usable.
Federated bypass is explicit per provider, optionally gated on a configured MFA
assurance claim; LDAP follows the local MFA policy. These require separate
implementation/verification gates and are not completed by this storage slice.

The OIDC handler now clears default claim actions because Nergal builds its own
bounded principal from the verified signed payload. Framework defaults otherwise
remove `iss` after token validation. Reassert issuer/subject/actor binding before
registration; reject missing identity fields in the registry. This preserves the
original authorization boundary for profiles rather than accepting weaker metadata.
See [the framework defaults](https://github.com/dotnet/aspnetcore/blob/v10.0.0/src/Security/Authentication/OpenIdConnect/src/OpenIdConnectOptions.cs).

Federated actor keys use `oidc:<issuer-length>:<issuer>:<subject>` with an explicit
UTF-16 issuer length. A plain colon join can collide for a colon-containing issuer
path and an opaque subject containing colons. Length framing preserves exact pairs
without normalization and stays within the bounded actor size. Profiles and audit
use the same unambiguous key. No earlier unreleased actor encoding is accepted.

Browser navigation explicitly requesting HTML redirects authentication challenges
to a fixed local sign-in path; API requests retain 401/403 statuses. Error pages
render a standalone compiled Razor view without MVC profile-result filters or
credential/controller queries, retaining error status and no-store headers. This
avoids an error-page dependency loop when account storage is unavailable. Never
reflect exception messages, submitted URLs or secrets in the view. Failed login
forms retain their existing generic credential failure response.

The sidebar now fills the viewport beside full-width content, with local decorative
line icons and a centered browser-timezone label at its bottom. No page footer is
rendered. Uniform shared control styles include implicit text, URL, email and
other text-like types while preserving checkboxes, radios and real code editors.

Build-time static asset endpoints remain explicitly anonymous and short-circuit
after HTTPS enforcement/routing. A broken credential store must not prevent CSS,
icons or scripts from styling sign-in/error pages. This applies only to mapped
public build assets, never configuration or controller routes. The HTTPS damage
fixture verifies this dependency boundary. See [framework static assets](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/static-files?view=aspnetcore-10.0#short-circuit-the-middleware-pipeline).
