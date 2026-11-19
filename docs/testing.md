# Testing standards

Tests are production code: keep them standardized, reusable, documented,
deterministic and efficient. Explain why a safety property matters. Use synthetic
RFC documentation addresses and avoid real credentials or exported host state.

## Unit tests

Run `dotnet test Nergal.sln --configuration Release`. Unit tests must not need
root, Docker, network access, an identity provider or a live firewall. Test
semantic validation, denied/unknown inputs, defensive snapshots and stable
results. Avoid implementation-mirroring assertions and unnecessary mocks.

Optional coverage collection:

```sh
dotnet test Nergal.sln --configuration Release --collect:"XPlat Code Coverage"
```

Coverage is a diagnostic, not evidence of correct packet handling. The current
suite tests the capability boundary only; it does not claim compiler or agent coverage.

## Integration and conformance tests

Kernel behavior needs isolated integration tests. Tests must own a disposable
network namespace and never mount a host system bus, Docker socket, firewall
configuration or credentials. Packet fixtures must eventually verify dual-stack
filtering, NAT return paths, per-source meters, IPv6 control traffic, foreign-table
preservation, failed validation, interrupted apply, confirmation timeout and rollback.
A successful reload is not proof of forwarding correctness.

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
