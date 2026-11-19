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

Only the harness writes the synthetic namespace rules. The server's test provider
uses fixed argv for read-only nft JSON collection, never shell/request interpolation.
This fixture has no daemon deployment, controller client, live host enrollment,
remote authentication or apply command. It establishes the documented local status
slice, not production security, flood resistance or general policy correctness.
