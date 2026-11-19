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
