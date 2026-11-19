# ADR 0013: protected durable application session keys

- Status: accepted
- Date: November 19, 2026

Local credentials do not establish safe browser sessions. Before login routes,
configure explicit ASP.NET Core Data Protection persistence isolated from machine
profiles, other applications and the privileged agent journal. Require an already
provisioned service-owned 0700 nonsymlink local directory and a caller-supplied RSA
certificate/private key. A self-signed local wrapping certificate is supported;
no external identity provider or public CA is required. This certificate is not a
TLS identity, and no production certificate is generated/imported during tests.

Use the framework's certificate XML encryption and versioned Data Protection
cryptography (AES-256-CBC/HMAC-SHA256), not custom payload encryption. Require a valid current encryption
certificate with at least 3072-bit RSA and private key; retained decryption-only
certificates may be expired. Snapshot certificate handles and configuration so
caller disposal/collection mutation cannot invalidate the configured key ring.
Operators retain/protect certificate private keys and older decryption certificates
for the lifetime of the corresponding persisted keys and sessions.

The XML repository is append-only and bounded: owner-only single-link regular
files, known generated names, at most 256 entries, each at most 64 KiB and XML depth
16. Prohibit DTDs/external resolution; reject unknown roots and plaintext master-key
material. A new key must contain framework-encrypted secret material. Write a
fresh 0600 pending file, flush data, atomically publish without overwrite, then
fsync the local directory before returning. Ignore only bounded, properly protected
pending files left by interruption; they never become authority automatically.
Invalid committed entries fail the whole read, never a partial key set or repair.
No automatic deletion, stale-file cleanup, NFS/copy fallback or host key-store access.
Only the fixed framework descriptor/decryptor types and certificate envelope shape
are supported. Require an exact supplied private-certificate match before decryption,
rejecting key names, retrieval/cipher references and ambient certificate fallback.
Open must force every retained descriptor to decrypt, never accept a partially
loaded ring or replace unreadable history with newly generated keys.

Wrap the private framework provider: check the complete repository before/after
every crypto operation, bind known committed bytes to immutable SHA-256 snapshots,
and rebuild/verify the provider on a newly observed generation. Existing protectors
retain purpose chains, not stale underlying providers, so appended revocation is
observed. A generation change during crypto discards/clears the result and reevaluates
with a maximum of three attempts; continued change fails closed. Same-account/root,
hostile ancestor races and atomicity against external privileged writers remain
outside the prototype boundary. No browser session or HTTP endpoint is enabled;
per-account session revocation and login conformance are separate next steps.

Tests use synthetic certificates, actual protect/unprotect across new providers,
certificate rotation, wrong-certificate/purpose/application denial and private-file
failure cases. No real key material, topology or credentials enter the repository.

Source: [ASP.NET Core Data Protection configuration](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/overview?view=aspnetcore-10.0).
