# Protected expected resource binding and reconciliation

After the pinned SDK Release build:

```sh
bash tests/integration/enrollment/check.sh
```

Requires Linux, .NET, Python 3, nftables and unprivileged user/network namespaces.
Each collision/binding scenario has fresh namespaces and a private synthetic journal.
The wrapper/harness check both namespace identities before native commands. No host
fallback, Docker, bus, production firewall or private topology is used. The managed
probe performs only storage/context/observation operations; all nft execution belongs
to the explicitly guarded harness.

The harness records a protected canonical baseline intent before exclusive native
creation. A preexisting conflicting tagged table causes check/apply to fail, remains
unchanged and cannot be bound to the journal's different owner/intent. In the successful
scenario, binding compares explicit expected receipt, actual observation/current
context and the exact protected baseline reconstruction. Reopening/retrying the same
binding is idempotent. Legacy apply is then unavailable for the bound resource.

Real policy drift, same-name/same-marker recreation and a second real network
namespace cannot satisfy or replace the protected expected receipt. Reconciliation,
denied rebinds and denied legacy starts leave database bytes unchanged. Foreign
ip/ip6/inet/bridge sentinels remain unchanged in both scenarios.

This is explicit trusted fixture bootstrap and read-only classification, not a
production enrollment authority or receipt-aware apply/recovery engine. The receipt
is never automatically replaced to match rejected actual state. The observer still
supports only the empty-chain slice. Concurrent privileged writers, protected
exclusive-creation proof, reboot recovery and production transport remain unimplemented.
Migration is tested separately using actual private schema-1 databases and retained
literal legacy event identifiers; no production/user journal is upgraded by this fixture.

The family-rule scenario compiles and binds an ordered IPv4-drop/IPv6-accept
baseline. It sends real loopback UDP packets before and after applying the
synthetic candidate, inserts a first IPv4-accept rule and verifies both the
changed packet outcome and protected receipt drift. A counter expression makes
the observation unsupported. The original receipt and foreign tables survive.

The `cli` and `cli-collision` scenarios execute `nergal-agent enroll` against
disposable state directories inside isolated user/network namespaces. They verify
exclusive creation of `inet nergal_filter` with an empty `accept` input chain,
binding against an independent listing, preservation of a preexisting conflicting
table without adoption (`cli-collision`), and refusal of repeated enrollment
(`journal.exists`) without mutating kernel or journal state. In `cli`, the fixture
also launches `nergal-agent status-serve`, queries live `matched` and `drift`
classifications over the protected Unix socket, and checks clean `SIGTERM` socket
cleanup.
