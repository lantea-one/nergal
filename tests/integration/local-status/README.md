# Isolated local status conformance

After a Release solution build, run `bash tests/integration/local-status/check.sh`.
Requires Linux, dotnet, nft, Python 3, unshare, newuidmap/newgidmap and existing
subordinate UID/GID ranges. The script creates fresh user/network namespaces and
refuses the host namespace; no fallback is available. A sandbox that prevents the
mapping helpers acquiring their normal capabilities must run this specific fixture
outside that sandbox. It does not create host accounts/groups or modify host rules.

The harness owns namespace UID 0 (agent), UID 1 (controller) and UID 2 (browser).
Controller/browser clients drop credentials then exec a fresh Python process with
zero effective capabilities. Both have socket-group access; only UID 1 appears in
the server's explicit allowlist. Neither can directly read the agent's journal.

Assertions use actual Unix sockets and kernel SO_PEERCRED, not mocked identity:

- Reject writable/symlink socket parents, preserve an existing foreign pathname,
  and refuse overflow UID authority before listening.
- Deny browser and unlisted root without reading any body or calling the provider.
  Mutation of the original configured UID collection cannot expand authorization.
- Reject apply/identity claims, duplicate/unknown fields, malformed/oversized/zero
  frames, truncation and trailing data before provider dispatch. Missing EOF times
  out and closes the connection.
- An independent fragmented-frame client receives matched status from a real
  protected receipt, then drift after test-harness mutation. Status leaves protected
  database bytes unchanged and exposes no direct database access to the client.
- A corrupt synthetic database stays unchanged; denied callers never reach it and
  authorized callers receive unavailable without revision metadata.
- A canceled slow provider closes on deadline; subsequent peer checks still work.
- Graceful stop removes its own socket. Replacing its pathname with a foreign file
  causes explicit cleanup refusal and leaves the replacement intact.
- Synthetic foreign tables in ip, ip6, inet and bridge remain unchanged.

The managed client is also run after dropping to UID 1, against both the native
status provider and independent Python wire servers. The harness copies only the
built fixture and framework runtime into disposable readable directories; it never
loosens host home/toolchain permissions. The adversarial server suite verifies:

- A correctly owned socket inode can still have a wrong kernel server UID. The
  server calls listen after an actual UID drop; the client sends zero request bytes.
- All typed replies, including full UInt64 revisions, survive fragmented frames.
- Zero/oversized lengths, truncated frames, duplicate/unknown fields/outcomes,
  lossy/noncanonical revisions, error metadata and surplus bytes return no status.
- Missing reply data or missing EOF after a complete frame expires. Explicit caller
  cancellation stays cancellation; the server waits for actual disconnect rather
  than treating the client's request half-close as full closure.
- Missing, regular-file, public-write and shared-inode endpoints, writable parents
  and overflow UID authority are rejected without altering the paths.

Only the harness writes the synthetic namespace rules. The server's test provider
uses fixed argv for read-only nft JSON collection, never shell/request interpolation.
This fixture has no daemon deployment, controller/browser integration, live host enrollment,
remote authentication or apply command. It establishes the documented local status
slice, not production security, flood resistance or general policy correctness.

The fixture also launches the real HTTPS controller under mapped UID 1 with a
private synthetic administrator, TLS certificate and session keys. It enables only
loopback in the disposable network namespace. Anonymous, malformed and logged-out
requests leave the native provider count unchanged. An authenticated GET returns the
matched resource revision. Parking the fixture socket produces an empty 503 and
the fixture restores it before listener teardown. This portion also needs OpenSSL,
iproute2 and the Release Web and isolation-probe build outputs.

With a separate disposable HTTPS issuer, an unlisted group receives no session and
causes no agent dispatch. A signed administrator group receives the expected native
status under its distinct federated identity. The issuer's private signing key stays
outside the mapped controller UID's private storage.
