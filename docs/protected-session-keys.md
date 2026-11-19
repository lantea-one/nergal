# Protected persistent session-key foundation

`ProtectedSessionKeyRing` in `Nergal.Identity` implements an explicit Linux Data
Protection provider. It persists certificate-encrypted framework keys and returns
purpose-isolated checked protectors. It enables no login, browser cookie, endpoint,
OIDC integration or privileged agent access. Web still uses its separate ephemeral
provider until authenticated-host configuration is implemented.

## Provisioning and certificate boundary

`ProtectedSessionKeyOptions` requires an explicit absolute directory and a stable
bounded ASCII application discriminator, default `nergal.local-administrator`.
Provision the nonsymlink directory as service-owned 0700, separately from account
and privileged-agent storage. The library never creates a missing directory or
uses a machine profile/default key directory.

`ProtectedSessionKeyRing.Open` requires a currently valid RSA wrapping certificate
with its private key and at least 3072 bits; a key-usage extension, when present,
must allow key encipherment. Local self-signed wrapping certificates are supported;
no public CA or identity provider is required. This is **not** a TLS certificate,
OIDC signing key or remote identity assertion. Up to seven distinct prior private
RSA certificates can be retained for decryption, including expired certificates.
Certificate handles and the input collection are copied; caller disposal/mutation
cannot change the configured ring. No private-key export or file loading occurs
inside this library. Operators must protect/provision private wrapping keys and
retain backups and historical decryption keys; rotation/recovery is not automated.
Current-certificate validity is checked at open; running processes must be rotated
before their configured wrapping certificate expires.

Open loads **every** recognized key descriptor and forces decryption, comparing the
complete loaded key count with the repository snapshot. Wrong/missing historical
certificates, invalid descriptors or skipped framework keys fail before a provider
is returned. Empty private directories permit first key generation. Losing the
entire key history cannot be reconstructed; old tokens then cannot be decrypted.
There is no import, reset, deletion or stale-key cleanup API.

## Fixed cryptographic/storage slice

Payload protection uses ASP.NET Core's AES-256-CBC/HMAC-SHA256 authenticated
protection and certificate XML encryption. The library implements no payload cipher
or password-based key wrapping. Stored XML accepts only version-1 key/revocation
records, the fixed framework descriptor/decryptor types and supported algorithm
metadata. Unknown types are rejected before activation.

Certificate envelopes must have the exact supported encrypted-data/key/X509/cipher
shape and refer to an explicitly supplied private certificate's public DER bytes.
Key names, retrieval methods, cipher references and unknown certificates are refused
before framework decryption. This is needed because the general framework XML
[decryptor can fall back to ambient certificate/key resolution](https://github.com/dotnet/aspnetcore/blob/v10.0.0/src/DataProtection/DataProtection/src/XmlEncryption/EncryptedXmlDecryptor.cs).
No host certificate-store fallback or URI resolution is admitted by this slice.
Encryption at rest does not authenticate hostile injected key files: the private
filesystem ownership boundary is still essential, as the framework's
[configuration guidance explains](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/overview?view=aspnetcore-10.0).

The append-only repository checks:

- Service owner, regular file/directory type, nonsymlink paths, 0700 directory,
  0600 single-link files and trusted ancestors as a provisioning prerequisite.
- Canonical generated file names; friendly names never become paths or filenames.
- At most 256 entries including pending files, 64 KiB per file and XML depth 16.
  DTDs, processing instructions, external resolution, plaintext master keys,
  duplicate key IDs and malformed metadata are refused.
- A fresh private pending file, file flush, atomic non-overwriting publication and
  directory fsync before persistence returns. No copy/NFS fallback is used.
- Whole-set failure on invalid committed files. Only known, correctly protected,
  bounded pending files left by interruption are inertly ignored, never adopted or
  automatically removed.

Files use this repository's naming contract; unrelated framework repositories are
not silently imported. Filesystem synchronization was exercised on Linux x64;
arm64 and physical power-loss behavior are unverified. Local trusted filesystems
are required; metadata checks are not descriptor-relative protection against
hostile ancestor replacement or a malicious same-account/root actor.

## Cache and lifecycle behavior

The public provider checks the complete repository before and after every crypto
operation. Committed bytes are immutable within a provider lifetime: changes or
missing known files fail even when the framework has cached keys. A newly observed
key/revocation generation rebuilds the private framework provider and verifies its
complete descriptors. Existing purpose chains resolve through the current provider,
so an appended valid revocation cannot remain hidden by an earlier key cache.

If the generation changes during crypto, the result is discarded/cleared and the
operation is reevaluated against the new generation, with at most three attempts.
Continued change returns `keys.concurrentChange`, never an unvalidated result. No
atomicity against an external privileged filesystem writer is claimed. Disposal
invalidates all purpose chains, releases provider references and disposes owned
certificate handles. This is key-level revocation; per-account session revocation
and browser session policy remain separate work.

## Evidence and next boundary

Unit tests use real framework protect/unprotect, synthetic RSA certificates and
private files. They cover restart, caller disposal, historical/expired certificates,
rotation, purpose/application/payload denial, live revocation through cached
protectors, changed/deleted files, unsafe paths, duplicate IDs, XML bounds/DTD/type
rejection, ambient-resolution denial and oversized encrypted output. The real
mapped-UID isolation fixture checks key files alongside journal/account stores,
including owner, sidecar, hard-link and FIFO denial. It creates no host accounts and
uses only synthetic certificate/key material in disposable directories.

The next milestone is explicitly configured HTTPS-only login/logout with CSRF,
rate limits, revocable local sessions and isolated HTTP conformance. Protected key
persistence alone does not establish browser authentication or production readiness.
