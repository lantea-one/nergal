# Native resource receipt conformance

After the pinned SDK Release build:

```sh
bash tests/integration/ownership/check.sh
```

Requires Linux, .NET, Python 3, nftables and unprivileged user/network namespaces.
The wrapper creates fresh namespaces; the harness checks both identities before
any native command. No root/host fallback, Docker, host firewall export or credential
is used. The managed probe only emits compiler candidates and parses/compares supplied
JSON; it has no host execution or enrollment functionality.

All addresses/state are synthetic. The harness creates a tagged empty input policy
and retains an expected receipt in private process memory after exclusive fixture
creation. It then verifies:

- Native check/apply accepts the real tagged candidate and its observation matches.
- Real default-policy drift is detected and unexpected extra objects are rejected.
- Parsing/comparison does not change the ruleset.
- A recreated table with the same name/comment/policy has a different kernel handle
  and is not adopted as the expected resource.
- A second real network namespace cannot satisfy the first namespace's context.
- Foreign ip/ip6/inet/bridge sentinel tables remain unchanged.

Receipt/context data is supplied to the managed probe over stdin and is not printed
in test logs. Expected receipts are harness assertions, not a production protected
store. The fixture does not prove enrollment, arbitrary ruleset observation, concurrent
kernel mutation safety, protected receipt persistence or a privileged apply path.
The observation slice intentionally rejects rule-bearing tables and other unsupported
objects. Existing packet/watchdog fixtures remain separate behavior evidence.
