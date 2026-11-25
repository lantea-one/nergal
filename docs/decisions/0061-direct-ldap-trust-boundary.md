# ADR 0061 — Direct LDAP authentication and profile defaults

Status: Implemented for OpenLDAP, with browser sign-in and profile persistence
through the shared TOTP completion flow in ADR 0062.

Expose LDAP through an explicit sign-in action with the same HTTPS, antiforgery,
form size and rate-limiting protections as local credential sign-in. Local
password authentication and the enabled-local-administrator invariant remain
independent of LDAP. The controller settings form currently stores LDAP intent;
that intent must never activate the live adapter.

Use one protected, versioned connection configured by a current local
Administrator. The first adapter targets a single LDAPS endpoint validated
against a trusted CA and the configured peer name. Disable referrals, alias
expansion and insecure fallback. Bound connection time, operation time, returned
entries and attributes. Saving settings performs no directory I/O. Protect the
write-only search-account password with a separate purpose in the existing key
ring, bound to the destination and bind identity. Replacing the endpoint or
user search base allocates a new directory identity. Changing the endpoint, user
search base or bind identity requires a replacement bind secret. Settings writes
use expected versions and commit with the identity audit. Store the singleton
connection and its independent audit action in the protected identity database.
Bind ciphertext to the directory ID, exact endpoint, dial IP, search base and
bind DN. A dial IP replacement also allocates a directory ID and requires a
replacement secret. Bind-DN rotation alone preserves the directory ID. The
connection version advances on each save. A previously saved row that disappears
is an integrity error.

An explicit LDAP attempt loads the protected configuration after verifying the
form generation. Local sign-in performs no LDAP work and does not decrypt LDAP
secrets. Account schema 6 adds browser sessions and LDAP profile observations.
Older account schemas stay subject to the pre-release unsupported-schema policy. Keep the
running development sandbox on its current build and preserve its state for a
separate protected offline maintenance operation.

The lookup uses one of `uid`, `cn` or `mail` and a structured UTF-8 equality
assertion below the configured base. A least-privilege search account locates
exactly one entry. A separate connection verifies the supplied nonempty password
against that entry. Require a single valid `entryUUID` and recheck the binding
between user DN and UUID on the bound connection before trusting the directory's
role and profile data. Check the UUID again when reading those attributes with
the search account. These checks detect observable DN changes. Simple bind accepts
a DN, so this slice requires the trusted directory to prevent concurrent DN reuse
during authentication. Untrusted directory users must lack write access to names,
entry IDs and role groups. Only `groupOfNames` entries and their `member` attribute
are eligible for directory-native direct membership comparison. A user must
match exactly one configured role. Read both role groups by base DN before and
after the membership comparisons. Require each group's `entryUUID`, returned DN
and OpenLDAP `entryCSN` to stay identical, and require different group UUIDs.
This relies on one coherent directory peer and change sequences that advance
on every group edit. Reject any missing or changed evidence. The first slice
targets OpenLDAP with readable operational attributes and direct group memberships. AD `objectGUID`, nested groups and StartTLS need their own
acceptance evidence.

Use the exact pair of Nergal-assigned directory identity and directory-assigned
entry UUID for the LDAP actor. Usernames, DNs, profile attributes and email cannot
link accounts. Project selected literal single-valued `cn`, `displayName`,
`givenName`, `sn` or `mail` attributes into the four descriptive profile fields.
Include `entryUUID` in the explicit search selection even when all profile fields
are disabled. Missing or invalid optional attributes yield value-free diagnostics.
Store current provider defaults by actor and mapping version with a UTC observation
timestamp. Existing per-field override semantics apply independently. Directory
data must never supply delivery or MFA enrollment addresses through profile metadata.

Bind the rendered sign-in form to its connection version so that a stale form
cannot send credentials to a replacement endpoint. Recheck the committed version
before issuing an authenticated session. Bind protected LDAP tickets to that
version, an absolute lifetime of at most 15 minutes from the directory proof and
a revocable session identifier. Configuration changes invalidate those tickets.
An issued ticket can retain its original authority after a directory-side
account or membership change, until its proof expires. When a new authorized
sign-in for the same actor commits, retire older proofs for that actor before
issuing the new ticket. LDAP password verification must feed the
[local MFA policy](0062-local-mfa-completion.md) before session issuance.
Keep credential and directory protocol failures generic, and never persist or
log submitted passwords, raw directory entries or native error messages.

Acceptance requires a disposable LDAP directory with a synthetic CA, real binds,
wrong-password and ambiguous-user denial, denial on observed rename or DN reuse
during verification, exact membership comparisons including owner-only entries,
TLS trust and peer-name failures, loss of directory availability, local recovery
sign-in, role and profile isolation, revocation, and HTTPS workflow tests.

## Transport evaluation

The reviewed Novell 4.1.0 release waits for bind responses without the caller's
cancellation token and can reconnect during bind. The Linux path in Microsoft
System.DirectoryServices.Protocols 10.0.15 uses synchronous native simple bind
without exposing a bind deadline. An outer task timeout does not stop either
underlying operation. Keep provider activation gated on a proven transport.

The transport accepts a single configured dial IP and the LDAPS URI's port and
TLS peer identity. The dial IP is part of administrator-managed trust and must be
bound to the search secret when settings persistence is introduced. This avoids
resolver delays and address retries within the authentication deadline. An IP
literal in the URI must equal the dial IP. Named endpoints can use a DNS
certificate with an explicitly configured dial IP.

Use one ten-second budget for connect, TLS, writes and responses across the
search-account and user connections. Validate system trust and the peer identity
before sending either bind. Certificate validation disables issuer downloads
and revocation checking to keep peer-controlled destinations outside the
credential path. Send a single BER-encoded equality assertion per
search. Bound frame size and search results independently of the server defaults.
Use successful correlated terminal responses as proof of a complete search.
Referrals and unknown controls fail the verification attempt. Keep the directory
proof internal until a separate sign-in flow validates current trust and MFA.

Client sources: [Novell 4.1.0 bind and reconnect](https://github.com/dsbenghe/Novell.Directory.Ldap.NETStandard/blob/1565853a9ba99eaca42f95d6332fff678d4829dd/src/Novell.Directory.Ldap.NETStandard/LdapConnection.cs)
and [.NET Linux bind interop](https://github.com/dotnet/dotnet/blob/8e0f8ed2312954727f8919d7d1c2f78b483b4ee7/src/runtime/src/libraries/System.DirectoryServices.Protocols/src/System/DirectoryServices/Protocols/Interop/LdapPal.Linux.cs).

Protocol sources: [OpenLDAP Administrator's Guide](https://cvs.openldap.org/doc/admin25/guide.html),
[RFC 4511](https://www.rfc-editor.org/rfc/rfc4511),
[RFC 4513](https://www.rfc-editor.org/rfc/rfc4513),
[RFC 4515](https://www.rfc-editor.org/rfc/rfc4515), and
[RFC 4530](https://www.rfc-editor.org/rfc/rfc4530).
