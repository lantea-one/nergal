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
limits (input filtering, 3-namespace routed IPv4/IPv6 forwarding, `iifname`/`oifname`,
`ct state` return traffic, IPv6 Neighbor Discovery, per-source dynamic rate limiting,
dual-stack DNAT/explicit SNAT/`ct status dnat`, Linux bridge `br0` L2 filtering,
atomic multi-table transactions, and live observation round-tripping).
It is opt-in, separate from dotnet test and the default CI job.
Successful local execution establishes the native nftables semantics slice,
not production remote transport, controller persistence, or web-driven rollback.

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
legacy apply is denied. The `cli` and `cli-collision` scenarios additionally run `nergal-agent enroll` in
disposable namespaces to check exclusive creation, handle-bearing echo binding
against an independent listing, foreign-table preservation on collision, and
repeat-invocation refusal (`journal.exists`) without modifying state; the `cli`
scenario also starts `nergal-agent status-serve`, queries live `matched` and
`drift` classifications over the Unix socket, verifies clean `SIGTERM` socket
removal, rejects same-boot `reconcile`, and exercises `prepare`, `watch`, `apply`,
and `confirm` for both timeout-triggered IPv4/IPv6 packet rollback and confirmed
revision-2 enforcement. The `schema1` scenario binds a full schema-1 policy (CIDR prefixes, TCP/UDP
ports, ICMP/ICMPv6), checks loopback packet enforcement, and detects rule drift. Unit
tests exercise `ParseReplacementEcho`, `ReconcileBoot`, full schema-1 observation/reconstruction (`Schema1Rules_ReconstructPolicyAndBindDigest`),
`ResourceExecutionLock` contention/inode hardening, `AgentStatusProvider`, CLI argument
parsing, `ParseEnrollmentEcho`, `InitializeResourceIntent` (denying replay and legacy
`Start` before binding), explicit quiescent schema migrations (`UpgradeFromVersion1` and
`UpgradeFromVersion2`), receipt-aware bound operations (`StartBound`,
`RecordCandidateAppliedBound`, `ConfirmBound`, `RecordRollbackSucceededBound`, and
`resource.boundReceiptRequired` guards), and unchanged state after denied migration;
no production/user journal is upgraded.
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
`tests/integration/local-status/control-check.py` (invoked by `check.sh`) additionally runs
real `nergal-agent control-serve` (peer-UID `SO_PEERCRED`) and `nergal-agent tls-serve`
(TLS 1.3 pinned mTLS) processes in disposable user/network namespaces, verifying UID and
certificate/EKU/key-mode denials alongside Schema 1 and Schema 2 `prepare-apply`, live UDP
packet filtering, explicit `rollback`, `confirm`, and autonomous `watch` timeout rollback.
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

The `tests/Nergal.Web.Tests` suite also verifies `ControllerStateStore` permissions,
monotonic policy revisions, SQLite append-only audit triggers (`UPDATE`/`DELETE`
denial and missing-trigger tamper detection), local/OIDC role claim resolution,
`NergalAdministrator` vs read-only `NergalReader` policy enforcement, and
`PolicyAuthoringService` / `ManagementController` bundle decoding, compatibility
evaluation, deterministic candidate compilation, and unified line diffing.

The local session fixture (`tests/integration/local-sessions/check.py`) additionally
provisions a `fixture-auditor` account (`--role auditor`) against an initialized
`controller.db`, confirming `Auditor` can inspect `/controller/audit`,
`/controller/hosts`, `/manage`, `/manage/policies`, `POST /manage/policies/preview`,
and `/manage/audit` (`200`) while mutations on `/controller/hosts` and
`/manage/policies/save` fail with `403`. `tests/integration/oidc/check.py` verifies
`Oidc:AuditorGroups` (`403` on host and policy mutations) vs `Oidc:AdministratorGroups`
(`201`/`204` host lifecycle and `302` policy revision saves with valid CSRF) and checks
that both `oidc:<issuer>:<subject>` and `local:<uuid>` audit attributions persist
across both JSON and MVC audit views.

`tests/integration/local-status/web-apply-check.py` (invoked by `tests/integration/local-status/check.sh`)
stages `Nergal.Web` under unprivileged mapped UID `1` (`CapEff == 0`) against
root-owned `nergal-agent control-serve` and `nergal-agent tls-serve` processes in
fresh user/network namespaces, verifying `Auditor` mutation denial (`403`),
MVC `/manage/apply/start` real UDP loopback packet enforcement + autonomous
watchdog rollback after missed confirmation, MVC confirmation revision promotion,
TLS 1.3 pinned mTLS explicit rollback and confirmation, and multi-table
(`inet nergal_filter` + `inet nergal_nat` + `bridge nergal_bridge`) watchdog
rollback and confirmed persistence while preserving foreign tables.

## Continuous integration

The Forgejo workflow builds, checks formatting, runs unit tests with coverage
and runs the default MVC/Blazor smoke check and isolated HTTPS session fixture. Set the
repository variable `CI_RUNNER_LABEL` to a suitable trusted Linux runner label;
otherwise it uses `ubuntu-latest`. Action revisions are pinned. CI has no
production deployment step or host firewall access. Automatic fork-PR execution
is intentionally not configured in the initial workflow; contributor code can
be reviewed and tested through the normal trusted-branch process.

## Router constructs and settings regression checks

After a Release build, run `bash tests/integration/nftables/check-router-constructs.sh`.
This guarded disposable three-namespace fixture verifies dual-stack masquerade and
return exemptions, MAC+IP mismatch denial, MSS 1360 in a captured forwarded IPv4 SYN,
destination-keyed meters, IPv4 reverse-path denial and UDP source-port bypass.
Fixed synthetic neighbor entries isolate firewall behavior from NDP timing; the
existing router fixture independently tests live IPv6 Neighbor Discovery.
Filter/NAT native echo and terse listings must reconstruct byte-identical candidates
and equal fingerprints. The dedicated auxiliary acceptance launcher below verifies extended bridge/early
inet packet and receipt-bound recovery behavior separately.

Run `python3 -B tests/integration/local-sessions/check-settings.py` for HTTPS settings
save/validation, CSRF denial, exactly one successful audit record, and Auditor denial
of mutations and private native source inspection. This uses disposable synthetic
accounts and sources and never executes a firewall command. Unit regressions cover
nested snapshot isolation, unknown/corrupt input, preserved advanced matchers during
visual editing, missing/cyclic jump targets, complete auxiliary dispatch and
preservation of agent denials in the audit.

The screenshots in `pages/assets/screenshots/` capture the local test controller
with synthetic/default UI data. They demonstrate appearance and readable UI state,
not packet enforcement or production deployment.

### Complete bundle observation work

`bash tests/integration/nftables/check-complete-observation.sh` applies only a
synthetic four-table candidate in a fresh user/network namespace. It compares
native creation echo with independent terse listings, reconstructs every table,
and requires identical complete fingerprints and byte-identical recompiled intent.
Unit checks independently reject auxiliary handle recreation, unknown expressions,
wrong ownership, missing objects, inconsistent priorities and invalid jump targets.
Protected journal tests deny primary-only baseline binding and auxiliary-only
candidate drift while the primary policy remains identical.

This check proves native observation only. Dedicated packet, independent watchdog
and restart conformance below establishes the supported auxiliary confirmed-apply
slice under [ADR 0036](decisions/0036-complete-bundle-observation-and-rollback.md).

`npm ci --prefix tools/web-assets --ignore-scripts` followed by
`npm run verify --prefix tools/web-assets` verifies the committed CodeMirror bundle
and complete dependency license notices against the locked packages. CI performs
this check independently of the .NET build. Browser QA additionally exercises
edited form submission, invalid JSON retention, semantic/duplicate-key rejection,
keyboard navigation and live light/dark switching. See
[asset maintenance](../tools/web-assets/README.md).

`bash tests/integration/enrollment/check-bundle-control.sh` independently exercises
the real Unix agent and watchdog in a fresh user/network namespace: complete
multi-table confirmation, agent restart, explicit rollback, timeout rollback for
an auxiliary-only policy change, dual-stack packet continuity and copied-marker
auxiliary recreation denial. It deliberately uses the same namespace UID for the
client and agent. It does **not** verify the separate-UID authorization boundary
or replace `tests/integration/local-status/check.sh`, which requires working
subordinate-UID mapping helpers.

### Test framework maintenance

All three unit projects use the stable `xunit.v3.mtp-off` package (4.0.3) as executable
.NET 10 test assemblies. VSTest, its existing Visual Studio adapter and Coverlet
collection remain in use so `dotnet test` and `scripts/test-unit.sh` retain the same
entry points and required three usable coverage artifacts. Async tests pass the
runner cancellation token where supported; denied-operation cases are retained.
The CLI argument theory uses explicit string-array rows for the v3 data contract.
The explicit `mtp-off` variant follows the upstream VSTest template and avoids
implicitly selecting the Microsoft Testing Platform runner. The repository no
longer references the deprecated `xunit` v2 metapackage.

Renovate closes its dependency dashboard automatically when no pending dependency
work remains, and can recreate/reopen it for later work. Dependency updates still
require review; automerge remains disabled.

### Container fallback for mapped-identity conformance

When host `newuidmap` cannot obtain its required capabilities, run
`bash tools/integration/check-mapped-identities.sh` after building Release with the
pinned SDK. The existing separate-UID fixtures run unchanged inside a disposable
container and nested fresh user/network namespaces. Synthetic account/subordinate
ID setup exists only in the image. Public test builds and SDK files are read-only
mounts; credentials, private exports, host buses and the Docker socket are absent.
The container has no external network or published ports. Only its nested-namespace
test tooling receives `SYS_ADMIN` and a container-local relaxed seccomp profile.
This is not a production controller deployment configuration.

Verified on November 22, 2026: all isolation and local-status/client/control/HTTPS
apply checks pass through this runner, including real separate-UID denial, pinned
mTLS, dual-stack packets, autonomous rollback, confirmation and basic multi-table
apply/rollback. The host mapping restriction remains; the container fallback
resolves test execution without weakening the fixtures or modifying host identity
configuration. The HTTPS apply fixture now includes filter/NAT/extended bridge
and early inet tables together; packet-specific acceptance runs separately below. See [runner details](../tools/integration/README.md).

### Documentation appearance

The Pages portal imports byte-identical copies of the application's stylesheet
and early theme initialization. `python3 scripts/verify-pages.py` rejects styling
asset drift as well as broken links and missing screenshots. Run
`python3 scripts/pages_assets.py` after changing the application theme source.
`node --test scripts/pages-theme.test.mjs` checks preference precedence, system
theme selection and storage-denial fallback. Browser checks cover both themes,
reload persistence, search, navigation, diagrams, code/tables, skip navigation and
the mobile menu/content width. See [Pages styling maintenance](pages-styling.md).


### Extended bridge and early inet acceptance

After a Release build, run:

```sh
bash tests/integration/enrollment/check-auxiliary-apply.sh
bash tests/integration/enrollment/check-auxiliary-apply.sh --agent
```

Every case uses fresh user/network namespaces, synthetic bridge/veth peers, static
neighbors and private temporary state. Native packet checks cover IPv4/IPv6 MAC+IP
pinning, source/destination MAC negation with working control connections, bridge
master matching and jump/return. Foreign counters at priority -4 establish that
priority -5 drops run first. Early inet acceptance never bypasses a later primary
drop. Agent checks keep primary semantics identical across auxiliary-only changes,
and cover confirmation, controller loss, independent timeout rollback, watchdog
restart, agent restart, explicit rollback and removal/restoration of auxiliary
scope. Foreign probe semantics remain unchanged throughout.

Separate cases preserve drifted auxiliary rules, copied-marker recreation, missing
tables, unknown native expressions and foreign collisions rather than repairing
or adopting them. Explicit and watchdog rollback require durable native receipts;
unit tests deny unacknowledged replacements and verify complete new-boot intent.
A replacement or restoration interrupted before its native receipt is durably
acknowledged is ambiguous and requires manual recovery. The original generic
watchdog kill-point fixture is separate from production receipt-aware agent logic;
its semantic retry assumptions do not establish safe adoption of recreated tables.

Run `bash tools/integration/check-mapped-identities.sh` for the complete distinct-UID
HTTPS/mTLS and all-four-table path. Real server imports and production packet
outcomes remain unverified. Native observations retain their documented 64 KiB
bound; this acceptance is not a large-policy capacity claim.

### Private migration review

`NativeMigrationReviewerTests` checks source line bindings, exclusion of comments,
quoted strings and variables, immutable reports, explicit byte/token/encoding and
malformed-input failures, and conversion denial for empty/unknown input. Web
source tests deny anonymous/auditor report access, reject path-shaped selectors,
and bind report content to the immutable source digest after its file changes.
These tests cover lexical inventory, not native parsing or conversion equivalence.
Run `python3 -B scripts/test-dev-watch.py` to check source/test refresh detection
and exclusion of generated build artifacts from the sandbox supervisor.

### Database source ingestion

`NativeSourceContentTests` and `NativeSourceStoreTests` verify strict UTF-8 byte
bounds, rejected names, exact BOM/CRLF content, independent duplicate identities,
reopen persistence, atomic audit failure, role denial, retained-byte/record caps,
immutability trigger definitions and digest corruption denial. Offline SQLite
upgrade tests preserve hosts, settings, revisions/audit and reject unknown versions,
source-table collisions or forged legacy protections without partial changes.

The local-session HTTPS fixture exercises staged import and multipart upload,
original attachment downloads, database persistence across restart without an
operator staging directory, source escaping,
CSRF, invalid UTF-8, maximum valid file size, request/file size rejection and
anonymous/Auditor boundaries. The admin fixture checks explicit idempotent schema
upgrade and unknown-version denial. These checks add no native firewall operation;
conversion equivalence and generated export remain unverified/unimplemented.

### Local timestamp presentation

`node --test scripts/local-time.test.mjs` uses real Intl timezone data for date
boundaries, both DST transitions, half-hour/southern offsets and unchanged UTC
attributes. It checks invalid or offset-less input, unavailable Intl, interactive
component updates and system-timezone changes. Controller SQLite tests verify UTC
persistence even with offset-bearing input/clocks. HTTPS checks assert UTC instant
markup and local-display labels; browser QA verifies rendered values and the named
viewer timezone. Server-local time is never the display default.

### Typed object library

`ReusableObjectContentTests` verifies defensive snapshots, canonical normalization,
family/type/entry bounds and unsupported-input denial. `ReusableObjectStoreTests`
uses real SQLite for immutable history, stale-edit/duplicate-name/type-change/RBAC
denial, transactional audit failure, capacity, digest/protection tampering and
explicit schema-2 upgrade. The existing UTC test includes object version storage.
The local-session HTTPS fixture exercises all three types, invalid/duplicate/unknown
fields, retained stale input, escaping, history/search, restart persistence, CSRF
and anonymous/Auditor boundaries. No native set or packet behavior is added by this
slice; policy-reference and native compilation conformance remains future work.

### Pinned policy object references

`PolicyObjectReferenceTests` checks strict codec/digest/unknown-field denial,
reference equality, schema/family/protocol/literal conflicts, overlap rejection,
singletons and byte-identical native projection with MAC/negation preserved.
`PolicyObjectBindingTests` uses real SQLite for version pinning, usage, forged and
missing reference denial, and ordinary edit/reorder/removal preservation. HTTPS
checks select a version, save a revision, edit the library and verify unchanged
policy bytes plus historical reference visibility; CSRF and Auditor writes fail.

Run `bash tests/integration/nftables/check-pinned-objects.sh` after Release build.
It validates actual IPv4/IPv6 UDP admission and independent source/destination/port
mismatch denial in a fresh user/network namespace, preserving foreign tables and
round-tripping complete native echo/list observations. No host namespace fallback
exists. `bash tools/integration/check-mapped-identities.sh` now pins controller-created
IPv4/IPv6 source objects through the actual UI before its existing Unix/mTLS agent
packet, confirmation and independent timed rollback checks. These verify static
resolved references, not native named sets or semantic import.
