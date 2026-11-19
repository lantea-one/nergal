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
root, Docker, network access, an identity provider or a live firewall. Test
semantic validation, denied/unknown inputs, defensive snapshots and stable
results. Avoid implementation-mirroring assertions and unnecessary mocks.

Coverage collection after building the Release configuration:

```sh
bash scripts/test-unit.sh
```

The script requires a generated report with executed lines, so a collector
failure cannot silently pass CI. It does not enforce a percentage target.

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
tests do not establish packet behavior or agent correctness.

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
