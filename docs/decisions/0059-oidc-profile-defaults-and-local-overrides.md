# ADR 0059 — OIDC profile defaults and local overrides

Implement administrator-managed, versioned profile mappings for exact HTTPS OIDC
issuers in the private identity database. A mapping selects literal top-level
signed ID-token claim names for display name, given name, family name and profile
email. Empty names disable individual fields. There are no expressions, templates,
remote lookups or UserInfo requests. Creating a mapping cannot activate a provider,
change the protected issuer/client/callback/group trust configuration or grant roles.
LDAP and generic OAuth authentication remain separate M5 gates.

Consume metadata only after the OIDC handler completes signature, issuer, audience,
nonce, correlation and protocol validation. Keep the verified payload request-local;
never save raw tokens or profile payloads in cookies, logs or audit events. The
serialized identity-store transaction reads the current mapping, projects bounded
string fields and stores current provider defaults with exact issuer/subject actor,
mapping version and UTC observation time, alongside an attributed audit event.
Duplicate JSON members are rejected. Missing or malformed optional values become
empty fields with explicit value-free diagnostics; they cannot affect authority.

Profiles keep provider observations separate from personal overrides. Blank local
fields use current provider defaults; nonempty local fields override them. Mapping
changes or disabling immediately make observations from older mapping versions
ineligible. Fresh successful sign-in refreshes defaults without overwriting local
edits. Reads never write. Equal names or email values never link identities.
Profile email is descriptive metadata, never verified delivery, MFA enrollment,
account recovery or authorization. A provider email_verified claim cannot change
that boundary. No external avatar or directory HTTP requests are introduced.

Local and external users can edit only their own bounded metadata with expected
versions and CSRF. Administrators alone configure mappings; every mutation rechecks
current local role/stamp/enabled state under serialized reservation and commits its
audit with the change. Unknown/repeated form fields and stale versions are denied.

Fresh unreleased account schema 3 adds typed mapping/observation tables and personal
metadata columns. Application startup does not adopt, reset or upgrade previous
schemas. Private development stores are backed up and advanced offline while all
consumers are stopped, preserving existing accounts, overrides and audit. Product
SQL migration/backup verification remains M6; this slice adds no legacy release
compatibility contract.

Sources: [OIDC standard claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims)
and [ASP.NET Core claim mapping](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/claims?view=aspnetcore-10.0).
