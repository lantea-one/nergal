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

The local administrator suite uses real Identity hashing and private SQLite stores,
without HTTP, live credentials or creating host users. It tests explicit singleton
bootstrap (including concurrent callers and the database constraint), absence of
default/plaintext credentials, Unicode bounds, indistinguishable credential-denial
results, serialized concurrent failures, persisted lockout/reset, schema mismatch,
unsafe path denial, corrupt credential identifiers/hashes, unsupported security
state and pre-reservation cancellation. Lockout expiry uses a persisted past
deadline rather than a sleep. No browser session is issued.

Protected session-key tests use actual framework cryptography and synthetic RSA
certificates/private files, without machine-profile key storage. They verify restart
and certificate rotation (including expired historical certificates), purpose/app
isolation, tamper denial, cached-protector revocation, immutable stored bytes,
XML/type/envelope bounds, explicit-certificate-only resolution and persistence output
limits. Passing them does not establish browser sessions or physical power-loss recovery.

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
The same reusable conformance checks independently exercise application-account
storage with synthetic credentials. Separate mapped UIDs prove direct-file denial,
foreign-owner/sidecar rejection and shared-inode/FIFO refusal for both stores;
fixture service-owner UID reuse is not a deployment recommendation.
Encrypted session-key storage is exercised as a third independent private store,
using only synthetic wrapping material outside the repository.

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
legacy apply is denied. The `cli` and `cli-collision` scenarios additionally run
`nergal-agent enroll` in disposable namespaces to check exclusive creation, handle-bearing
echo binding against an independent listing, foreign-table preservation on collision,
and repeat-invocation refusal (`journal.exists`) without modifying state. Unit tests
exercise `ParseEnrollmentEcho`, `InitializeResourceIntent` (denying replay and legacy
`Start` before binding), explicit quiescent schema migration and unchanged state after
denied migration; no production/user journal is upgraded.
Status tests cover one-snapshot revision/binding classification, unavailable status
for active/recovery-blocked work, missing observations and changed unbound boot,
drift without receipt replacement, and corruption rejection even without an observation.

The firewalld research fixture is under tests/integration/firewalld. It checks
basic configuration and generated rule semantics; it is not a full packet-level
firewalld equivalence test. It is opt-in and is not part of dotnet test.

The local status fixture is under tests/integration/local-status. Run
`bash tests/integration/local-status/check.sh` with existing subordinate UID/GID
ranges and mapping helpers, as for the isolation fixture. Independent clients use
real separate UIDs and actual SO_PEERCRED. It tests denial before provider access,
strict bounded framing/schema, incomplete-frame and provider deadlines, protected
native matched/drift status, corrupt-state errors and replacement-path preservation.
It also tests the managed status client against independent Python servers: wrong
kernel UID behind a correctly owned inode receives no intent; complete fragmented
UInt64 replies pass, while hostile/truncated/trailing replies, missing EOF, timeouts,
cancellation and unsafe endpoint metadata fail without partial status.
No daemon is installed; only the harness writes synthetic namespace rules. See its
[README](../tests/integration/local-status/README.md) for the exact scope.

The controller status fixture also checks the complete HTTPS-to-Unix path between
separate mapped process identities. It counts native provider calls through
authorized and rejected requests, including a temporarily missing socket.
The Web unit suite checks HTTP presentation for every protocol outcome and
preservation of a maximum UInt64 revision.

## Web and identity tests

After the Release build, `python3 -B tests/integration/admin/check.py` runs the
offline commands on a temporary private account directory. A real pseudo-terminal
checks terminal echo at each prompt, absence of the synthetic password in output
and full mode restoration after success, mismatch and SIGTERM. Pipe and duplicate
failures do not create or overwrite an administrator. The HTTPS fixtures provision
their synthetic account through the same operator command.


After the Release build, run `python3 tests/integration/local-sessions/check.py`
with Python 3 and OpenSSL. The fixture starts independent Kestrel processes on
dynamic loopback ports, creates separate synthetic TLS/wrapping certificates and
uses the real singleton account store. Checks cover spoofed HTTP, antiforgery,
duplicate and oversized forms, fixed redirects, cookie flags, anonymous and
tampered tickets, restart, logout replay, lockout, rate limiting and absence of
profile-key persistence. A unit test advances the cookie handler clock past the
absolute expiry. The default smoke test checks that session routes are absent.

Run `python3 -B tests/integration/oidc/check.py` for a real loopback HTTPS issuer
and Kestrel login. OpenSSL generates synthetic signing and TLS keys. The fixture
checks code redemption with PKCE, signature, issuer, audience, nonce, state, group
and token-age denial, logout replay, restart invalidation and independent local login.
No machine trust anchor is installed. Clock-controlled tests exercise absolute expiry
and issuer/subject binding. The mapped-UID native fixture also checks federated
group denial and authorized read-only status. For upstream provider interoperability, run
`bash tests/integration/oidc/check-keycloak.sh /path/to/keycloak-26.8.2.tar.gz`
with the official [Keycloak release archive](https://github.com/keycloak/keycloak/releases/tag/26.8.2),
Java, Python 3.12 or later, OpenSSL, iproute2 and unprivileged namespaces. The
fixture verifies the release SHA-256, extracts a fresh copy, imports only its own
synthetic realm and uses new user/network namespaces. No existing server or
database is opened. This check runs separately from the ordinary CI fixture.
Multi-controller sessions remain unverified. Integration and
browser tests supplement unit tests rather than replacing them.

## Continuous integration

The Forgejo workflow builds, checks formatting, runs unit tests with coverage
and runs the default MVC/Blazor smoke check and isolated HTTPS session fixture. Set the
repository variable `CI_RUNNER_LABEL` to a suitable trusted Linux runner label;
otherwise it uses `ubuntu-latest`. Action revisions are pinned. CI has no
production deployment step or host firewall access. Automatic fork-PR execution
is intentionally not configured in the initial workflow; contributor code can
be reviewed and tested through the normal trusted-branch process.
