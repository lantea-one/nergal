# ADR 0009: bounded read-only local status protocol

- Status: accepted
- Date: November 18, 2026

## Protocol and authority boundary

Implement a version-1 status-only local protocol with immutable Core reply contracts
and pure bounded framing/JSON codecs. The sole request is exactly schemaVersion 1 and
command status. No identity claim, policy, native text, apply, confirmation or recovery
command is accepted. Replies expose a typed classification and, only for resource
classifications, a canonical decimal-string revision. Error/denial replies contain
no enrollment metadata or arbitrary caller/native text.

Use a four-byte big-endian payload length, 1–4096 UTF-8 bytes, JSON depth at most 8,
exact known fields/values and duplicate-key rejection. One request/reply per connection;
the client half-closes its write side after the frame so trailing bytes can be rejected
before dispatch. A request/response deadline bounds incomplete frames and provider work.
Decoding a valid request never establishes authorization.

Linux Unix stream transport must obtain SO_PEERCRED from the accepted socket and
compare kernel UID with a defensive explicitly configured allowlist before reading
request bytes or invoking a provider. Never use JSON UID/group/role claims as authority,
and do not implicitly trust root. Reject invalid/overflow UID authority. Filesystem
socket permissions and peer UID checks are independent layers; a group member able to
connect still requires explicit UID authorization. Remote/multi-host TLS and OIDC user
authorization are separate future boundaries, not approximated by this local channel.
SO_PEERCRED captures the connection creator, not each subsequent writer. Trusted
callers must not delegate descriptors to untrusted processes. Check the configured
kernel overflow UID at startup and every connection, since its value can change.

## Infrastructure and conformance

Share the Linux statx metadata boundary between the local journal and transport,
keeping Core free of OS/database/ASP.NET dependencies. Socket paths require a trusted
service-owned nonsymlink parent with no group/other writes. A group-access directory
uses explicit setgid group/execute policy and a matching owned socket inode; owner-only
mode remains available. Never unlink/adopt an existing path as a stale socket. Cleanup
may remove only the created matching socket inode. Same-account/root path races and
hostile parents remain outside the prototype boundary; no service installation or
account/group changes occur.
An internal endpoint adapter delegates Unix address encoding without enabling
.NET's unconditional bound-path deletion on Socket disposal. The replacement-path
fixture guards this runtime interaction. Interop supports Linux x64/arm64; current
native test evidence is Linux x64.

The transport invokes only an injected status provider after peer/framing/schema
validation. It has no firewall executor. Web gains no reference to local state or
transport. A test-only provider can collect a full native table snapshot and compare
protected expected state inside disposable namespaces. Tests use distinct mapped
agent/controller/browser UIDs, actual sockets and real kernel peer credentials. They
must prove unauthorized/malformed requests do not reach the provider, including when
filesystem permissions allow connection.

## Limits

This is a read-only local control boundary, not a production daemon, authenticated
remote transport, browser session policy, live mixed-version upgrade, receipt-aware
apply/recovery or arbitrary-rule driver. No test may touch a production firewall or
host account/group. Existing rollback, resource and storage fixtures remain separate
conformance evidence.

## Sources

- [Linux Unix sockets and peer credentials](https://man7.org/linux/man-pages/man7/unix.7.html)
- [Linux user namespace credential mapping](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
