# Testing standards

Tests are production code: keep them standardized, reusable, documented,
deterministic and efficient. Explain why a safety property matters. Use synthetic
RFC documentation addresses and avoid real credentials or exported host state.

The SDK is pinned in `global.json`. Update it and regenerate the dependency
lockfiles together: Blazor includes SDK-selected asset package versions. CI
installs that exact SDK. Coverage tooling must support the selected runtime;
a report containing no executed lines must be investigated, not presented as
evidence of tested behavior.

## Unit tests

Run `dotnet test Nergal.sln --configuration Release`. Unit tests must not need
root, Docker, network access, an identity provider or a live firewall. The Linux
local-state suite uses real SQLite databases in private temporary directories and
explicit test clocks; it needs no host-service access. Test
semantic validation, denied/unknown inputs, defensive snapshots and stable
results. Avoid implementation-mirroring assertions and unnecessary mocks.

Coverage collection after building the Release configuration:

```sh
bash scripts/test-unit.sh
```

The script requires one generated report with executed lines per `*.Tests.csproj`,
so a collector failure in one project cannot be hidden by a successful report from
another. New test projects must be included in the solution. It does not enforce a
percentage target.

On Linux, coverage instrumentation uses named synchronization objects. If a
sandbox makes the inherited `XDG_RUNTIME_DIR` read-only, point it at a private,
writable directory owned by the test user (mode 0700); do not loosen the host
runtime directory permissions. Check the test output and report for collector
errors even when the test process exits successfully.

Coverage is a diagnostic, not evidence of correct packet handling. The current
suite tests capability selection, policy snapshots, network validation and compiler
rejection/determinism, exact artifact digests and confirmed-apply state transitions.
Confirmation tests use explicit monotonic elapsed durations without sleeps. They
cover stale bindings, deadline boundaries, failed apply/rollback, interruption and
terminal states. No working watchdog or rollback executor is exercised. These unit
tests do not establish packet behavior or agent correctness. Local-state tests cover
real transactions, reopen/replay, content integrity, path protection, stale/reused
operations and concurrent reservations/confirmation-timeout decisions. Process death
and physical power-loss durability require additional integration evidence.

## Integration and conformance tests

Kernel behavior needs isolated integration tests. Tests must own a disposable
network namespace and never mount a host system bus, Docker socket, firewall
configuration or credentials. Packet fixtures must eventually verify dual-stack
filtering, NAT return paths, per-source meters, IPv6 control traffic, foreign-table
preservation, failed validation, interrupted apply, confirmation timeout and rollback.
A successful reload is not proof of forwarding correctness.

The native compiler fixture is under tests/integration/nftables. After the Release
build, run:

```sh
bash tests/integration/nftables/check.sh
```

It requires Linux with unprivileged user/network namespaces, nft, ip, ping and
Python 3. It fails if isolation is unavailable and never falls back to the host.
See its [README](../tests/integration/nftables/README.md) for exact assertions and
limits. It is opt-in, separate from dotnet test and the default CI job. Successful
local execution does not establish NAT, forwarding, neighbor discovery or rollback.

The independent watchdog fixture is under tests/integration/watchdog. Run
`bash tests/integration/watchdog/check.sh` after the Release build. It uses actual
process termination, durable journal decisions, native atomic replacement and real
IPv4/IPv6 packet recovery in disposable namespaces. Its README lists eight scenarios
and the strict synthetic-resource boundary. It is opt-in, separate from default CI.
It does not establish a production watchdog, account isolation or arbitrary restore.

The filesystem account-isolation fixture is under tests/integration/isolation. Run
`bash tests/integration/isolation/check.sh` with existing subordinate UID/GID ranges
and newuidmap/newgidmap available. It tests actual distinct-UID filesystem denial,
foreign-owner rejection and shared-inode/FIFO refusal in disposable namespaces. It
requires no host account/group changes or firewall access. Its README documents the
trusted-parent boundary and sandbox-helper requirements.

The native identity/receipt fixture is under tests/integration/ownership. Run
`bash tests/integration/ownership/check.sh` after the Release build. It compares real
kernel observations, detects policy drift and same-name/same-comment recreation, and
rejects a receipt in a second real network namespace. It observes only the documented
empty-chain slice and does not establish protected receipt persistence or enrollment.

The protected binding fixture is under tests/integration/enrollment. Run
`bash tests/integration/enrollment/check.sh` after the Release build. It records a
protected synthetic intent before exclusive native creation, persists/reopens the
expected receipt and rejects drift, copied-marker recreation, conflicting foreign
resources and a second actual namespace without managed-side kernel writes. Bound
legacy apply is denied. Unit tests exercise explicit quiescent schema migration and
unchanged state after denied migration; no production/user journal is upgraded.

The firewalld research fixture is under tests/integration/firewalld. It checks
basic configuration and generated rule semantics; it is not a full packet-level
firewalld equivalence test. It is opt-in and is not part of dotnet test.

## Web and identity tests

Future tests must cover OIDC claim validation, group denial, revoked access,
CSRF, session lifecycle and prevention of direct agent access. Integration and
browser tests supplement unit tests rather than replacing them.

## Continuous integration

The Forgejo workflow builds, checks formatting, runs unit tests with coverage
and starts the real read-only MVC/Blazor application for a smoke check. Set the
repository variable `CI_RUNNER_LABEL` to a suitable trusted Linux runner label;
otherwise it uses `ubuntu-latest`. Action revisions are pinned. CI has no
production deployment step or host firewall access. Automatic fork-PR execution
is intentionally not configured in the initial workflow; contributor code can
be reviewed and tested through the normal trusted-branch process.
