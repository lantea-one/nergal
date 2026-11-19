# Local read-only status protocol

`Nergal.Core.Agent` defines a versioned status contract and pure UTF-8 JSON/frame
codecs. `Nergal.LocalTransport` implements a Linux pathname Unix stream listener
with kernel peer-UID authorization. It contains no SQLite, native firewall executor,
web framework or shell. `Nergal.Linux` supplies shared no-follow filesystem metadata
and process-identity inspection. Web references none of this infrastructure.

## Wire contract

Each connection carries one request frame, followed by one reply frame. A frame
starts with a four-byte unsigned big-endian payload length from 1 through 4096,
then that many UTF-8 JSON bytes. The client must half-close its write side after
its request. The listener checks EOF before dispatch, rejecting trailing bytes.
JSON allows at most eight levels of depth; duplicate keys, unknown fields,
unknown versions and commands are rejected. No request identity claim is trusted.

The sole request is:

```json
{"schemaVersion":1,"command":"status"}
```

Resource replies contain exactly schemaVersion, outcome and revision. Revision is
a canonical nonzero unsigned 64-bit decimal **string**, preserving precision in
clients that cannot represent all such integers as JSON numbers:

```json
{"schemaVersion":1,"outcome":"matched","revision":"1"}
```

| Outcome | Meaning | Revision |
| --- | --- | --- |
| `matched` | Trusted provider compared the complete recognized observation with protected expected state | Required |
| `drift` | Trusted provider found a recognized observation different from protected expected state | Required |
| `unbound` | Trusted provider found enrollment without a bound expected resource | Required |
| `unavailable` | Provider cannot establish status safely | Forbidden |
| `denied` | Kernel peer identity is not authorized | Forbidden |
| `invalidRequest` | Authorized caller supplied an unsupported/malformed request | Forbidden |

Neither denial nor error replies carry resource metadata, native text, paths or
caller input. A valid codec result is only parsed intent, never authorization or
proof of kernel state. An observation outside the supported empty-chain slice is
unavailable, rather than a successful match or an invitation to adopt new state.

## Peer and filesystem boundary

The listener obtains SO_PEERCRED from each accepted socket **before** reading a
frame or invoking the provider. Its immutable explicit UID allowlist has no
implicit root exception. It refuses the reserved invalid UID and the kernel
configured overflow UID; the latter is checked at binding and per connection so
unmapped identities cannot become authority. Failure to establish credentials or
overflow policy fails closed. Group membership grants filesystem access only;
it does not replace the UID check. SO_PEERCRED identifies the connection creator,
not each writer: trusted callers must not delegate connected descriptors to
untrusted processes. This is service-account authorization, not end-user identity.

The caller must provision a service-owned nonsymlink parent. Owner-only mode is
0700 with a 0600 socket. Explicit shared-group mode requires a matching setgid
02710 parent and a 0660 socket owned by the service and configured group. The
listener checks type, owner, mode, link count and inode/device identity. Existing
paths are always refused, including stale-looking sockets. Cleanup removes only
the matching created socket; a replacement is preserved with `socket.pathChanged`.
The internal endpoint adapter prevents .NET's default unconditional pathname
cleanup from bypassing that check. Normal process death can leave a stale socket:
this prototype never automatically removes or adopts one.

Ancestor trust is an installation prerequisite. Metadata/path checks are not a
race-proof descriptor-relative sandbox against a hostile service account, root,
or mutable ancestors. No accounts, groups, service units or host sockets are
provisioned by this library. Native transport interop is restricted to Linux x64
and arm64; current integration evidence is Linux x64 only.

## Dispatch and deadlines

`UnixStatusServer.ServeAsync` invokes an injected trusted read-only asynchronous
provider only after peer, frame and schema checks. The provider receives only a
cancellation token, not request fields. The listener serves sequentially with a
bounded backlog and one deadline per accepted connection, default two seconds,
configurable up to thirty seconds. The deadline includes framing, provider and
reply. Expiry closes the exchange without granting extra error-write time.
Rejected surplus data is not drained without bound; a malformed exchange may
close/reset after its error frame. Clients must handle incomplete/closed replies
as failure, never as matched status.

Providers must honor cancellation and avoid blocking synchronous work. A managed
callback is trusted code: a deadline cannot terminate arbitrary noncooperative
code or undo its side effects. Callers cancel and await serving before disposing
the listener. Rate limits, availability under connection floods, process
supervision and authenticated client APIs remain future work.

## Evidence and next work

The disposable [local-status fixture](../tests/integration/local-status/README.md)
uses real separate mapped UIDs, sockets, kernel peer credentials, protected SQLite
state and native observations. It proves independent-client matched/drift replies,
filesystem denial of direct journal access, pre-dispatch denial, malformed-frame
bounds, provider timeout and preservation of replacement paths/foreign tables.
Unit tests cover codec/constructor failures and defensive snapshots.

There is no installed daemon, production collector, browser integration, remote
transport or receipt-aware apply/confirmation/recovery command. Bound apply stays
disabled. The next safe boundary is a peer-authenticated bounded status client,
with hostile-server conformance, before wiring any controller to an agent. A
production receipt-aware apply path additionally needs resource locking, complete
candidate validation, atomic receipt transitions and independent timed recovery.
