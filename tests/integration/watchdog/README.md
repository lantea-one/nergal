# Independent watchdog conformance prototype

After the pinned SDK Release build:

```sh
bash tests/integration/watchdog/check.sh
```

Requires 64-bit Linux, unprivileged user/network namespaces, nftables, ip, Python 3
and .NET. There is no root, host-namespace or Docker fallback. Every scenario gets
fresh user/network namespaces, synthetic documentation addresses and a private
0700 temporary journal. The wrapper and executable verify isolation before work;
the executable additionally requires a single non-root-host-UID mapping. An ordinary
host status invocation must fail at the guard before opening state. This prevents
accidental launches; it is not an adversarial production authorization boundary.

The executable is test-only and is not referenced by Web or shipped as a host agent.
Its only artifacts are compiler-generated empty accept/drop input policies. Stored
bytes must equal those fixed artifacts before execution. It never executes arbitrary
stored policy or shell text. Native commands use fixed arguments and stdin. The
fixture replaces only its known `inet nergal_filter` table, in an atomic delete/create
batch, after strict structured observation and full native check. The normal compiler
remains create-only. Foreign ip/ip6/inet/bridge sentinel tables must remain unchanged.

The separate worker, confirmer and watchdog serialize side effects with an OS process
lock. The watchdog durably arms the journal before the worker may apply. Confirmation
and timeout use journal write transactions with the clock sampled inside the lock.
Timeout commits RollbackRequired before restoration; confirmation cannot overtake it.
Watchdog restart retains the exact original deadline. Successful restoration verifies
the known live baseline before recording completion; unexpected state blocks recovery.

## Scenarios

- Worker is killed while holding the execution lock before apply: baseline remains usable.
- Worker is killed after kernel apply but before acknowledgment: real IPv4/IPv6 TCP/UDP
  traffic is denied by the candidate, then restored by the independent watchdog.
- Watchdog is killed/restarted after apply: persisted deadline remains identical and
  packet restoration still completes.
- Watchdog is killed after restoration but before acknowledgment: a new watchdog
  recognizes the exact baseline and records completion without reopening confirmation.
- Timely confirmation commits revision 2 and survives the old deadline and a later
  watchdog invocation; candidate packet denial remains enforced.
- Unexpected extra table contents cause RecoveryRequired and no destructive overwrite.
- Corrupt or missing journal causes watchdog/confirmation failure with no kernel writes.
- Late/repeated confirmation and new work while recovery-blocked are rejected.

Readiness and kill points use pipe acknowledgments, not startup sleeps. Real socket
connect/receive timeouts establish denied packets. The confirmation scenario deliberately
waits through the real former deadline to catch stale rollback behavior. Every process
has a bounded harness timeout, and remaining children are killed before namespace exit.

## Limits

This validates a constrained synthetic resource, not arbitrary table ownership or
production deployment. Bootstrap is an explicit fresh-namespace assertion. General
host enrollment, service-account isolation, hardened path ownership, authenticated
transport, supervised daemon lifecycle, reboot recovery, arbitrary snapshot restore,
physical power loss, forwarding/NAT and production privilege distribution are absent.
Corrupt state blocks writes; it cannot provide automatic recovery without trustworthy
artifacts. These limitations are deliberate and visible, not silent successful rollback.

The fixture is opt-in and currently runs locally, separate from default CI/unit tests.
See [ADR 0005](../../../docs/decisions/0005-isolated-watchdog.md) for the ordering contract.
