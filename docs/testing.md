# Testing standards

Whole-rule expression tests cover typed literal/direction/family retention,
repeated predicate order, negation, complete consumption, exact diagnostics,
unresolved references, ambiguous/invalid values and inclusive predicate/set bounds.
No partial rule survives failure. Schema-3 HTTPS checks verify value-free summaries,
viewer positions and unchanged source bytes; structural failure makes rule parsing
unavailable. These checks do not establish native semantic or packet equivalence
(ADR 0054). Representative inet and bridge literal examples were also checked
with `nft --check` in disposable Docker network namespaces using synthetic inputs;
this checks syntax/kernel acceptance without applying rules or testing packets.

Declaration partition regressions cover every original node in scope/order, named
blocks versus anonymous expressions, directive/command retention, continued
headers, unknown head positions, immutable collections and maximum-width input.
HTTPS checks verify contextual table/chain counts, masked unknown diagnostics and
unchanged original downloads. These tests do not establish semantic conversion or
packet equivalence (ADR 0053).

Native structure regressions cover exact ordered token coverage, nested spans,
opaque quoted/comment contents, unknown input, immutable nodes, inclusive 64-group
depth and value-free missing/mismatched delimiter positions. The shared review
returns no partial inventory on structural failure. HTTPS checks verify schema-3
source-bound reports, matching viewer positions and exact original downloads after
failure. Legacy report constructors retain schemas 1/2. These checks establish
structural contracts, not complete nft syntax or packet equivalence (ADR 0052).

Saved revision export regressions cover exact native digests, every table scope,
native/literal list projections, dormant intent, deterministic bytes, invalid or
mismatched revision denial and Administrator authorization. The real HTTPS fixture
checks attachment names/content types, no-store responses, invalid identifiers,
anonymous/Auditor denial and unchanged database/audit contents. These download
checks do not establish native source conversion equivalence. See
[policy exports](policy-exports.md) and ADR 0049.

Native source frontend tests reconstruct every original UTF-16 code unit from
immutable token spans, verify CRLF/CR/LF and continuation positions, retain opaque
quoted/reference values and unknown input, reject hidden controls and independent
UTF-8/significant/total token limits, and ensure diagnostics/formatting omit private
values. Viewer and review tests use the shared analyzer and preserve blocked
conversion. These are lexical contracts, not native syntax or packet equivalence.
See [the source workflow](native-source-library.md) and ADR 0050.
The real HTTPS fixture also imports a source with a hidden control character and
a separate continued CRLF/CR source. Viewer and report agree on blocked/complete
inventory, source-line references and exact SHA-256; original downloads retain all
bytes even when analysis fails. No partial topic inventory is returned on failure.

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

CI and Pages use shared organization runners with dedicated `-ci` labels,
with verification pinned to `asgard-ci` and Pages to `heimdall-ci`. Private
infrastructure runners and generic fallback labels are prohibited. `vidar-ci` is
limited to small, short jobs, never the full build/integration/package workflow.
Run `python3 -B scripts/test-ci-runner-policy.py` to verify literal reviewed labels
and workload restrictions. This offline check cannot establish runner registration
scope; verify organization ownership and no repository binding in Forgejo as well.
Historical queued runs retain their selections and must be cancelled if disallowed.
See [the runner guide](../pages/deployment-and-packaging.md).

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
conversion equivalence remains unverified. Saved revision exports have separate
unit/HTTPS checks described above; original-source ingestion is not conversion.

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

### Versioned rule state

`RuleEnabledStateTests` verifies every supported location, exact re-enable output,
immutable retained settings/references/order, meter omission, validation of dormant
rules and strict non-boolean denial across all rule types/MSS. Web authoring tests
check every visual edit path retains state, and intent diffs expose dormant changes
with identical native candidates. The HTTPS fixture checks inline controls, CSRF,
role/unknown/duplicate/location denial, exact pinned intent, saved revision history
and re-enable behavior.

Run `bash tests/integration/nftables/check-rule-states.sh` for real dual-stack packet
admission changes when accept/drop rules are disabled/restored. The router-constructs
fixture additionally disables/restores dual-stack NAT return exemptions and checks
actual packet source translation. Foreign tables are preserved. The mapped-identity
runner submits disabled/enabled rules through the UI before its Unix/mTLS packet,
confirmation and independent watchdog rollback cases. These do not establish
semantic source import, generated export or arbitrary production equivalence.

### Guided router form checks

`RouterFormAuthoringTests` verifies explicit MAC/IP restrictions, destination
meter keys, reject, complete postrouting edits, dormant state/order retention,
and denied unknown keys, invalid MACs, unbound negation and incompatible action
fields. `tests/integration/local-sessions/router_forms.py` exercises the real
HTTPS routes, CSRF, duplicate/unknown/malformed inputs, anonymous/Auditor denial,
pinned list retention and unchanged saved revisions. These UI changes reuse the
native compiler; generated text is not new packet-level proof. Existing router
namespace packet checks cover the underlying matcher and NAT semantics.

`RawFormAuthoringTests` and `local-sessions/raw_forms.py` cover ordered raw
exceptions/FIB rules, source ports, dormant-state preservation, raw defaults,
MSS resize/removal, DNAT negation and NAT reordering. HTTP cases include missing
CSRF, invalid integer binding, unknown/duplicate fields, incompatible matcher
combinations and unchanged saved revisions. The unit runner uses one MSBuild node
to avoid isolated-runner worker-pipe collisions while retaining all coverage checks.

`AuxiliaryFormAuthoringTests` and `local-sessions/auxiliary_forms.py` verify
priority/defaults, complete filter matchers, destination meters, disabled-state
retention, order, explicit empty-table removal, unchanged primary/NAT/bridge
sections and immutable saved revisions. Malformed/duplicate/unknown requests,
CSRF and anonymous/Auditor access remain denied. Shared condition parsing is also
covered by primary router-form tests; auxiliary forms add no compiler semantics.

`BridgeFormAuthoringTests` and `local-sessions/bridge_forms.py` cover complete
bridge-master/MAC/IP/transport matching, priority, local chain creation, jump and
return, dormant edits/reordering, explicit empty removal and immutable graph saves.
They deny malformed/unknown input, missing/cyclic jumps, base-chain returns,
referenced-chain removal, incompatible matchers and anonymous/Auditor mutations.
The HTTPS fixture restarts the host and verifies Auditor read-only bridge fields.
`check-auxiliary-apply.sh` independently exercises real packet outcomes for early
inet/bridge tables and local control flow in disposable namespaces; screenshots
and native generated text alone do not establish packet behavior.

Auxiliary-reference unit/HTTPS checks cover explicit table selection, legacy
primary-only submissions (including ignored query scope), retained MAC/negation and
dormant state, stable primary intent, immutable saved old versions after library
updates and saved auxiliary usage paths. Unknown/empty/duplicate scopes and wrong
matcher kinds remain denied; unknown filter schemas are never normalized.

### Transport list references

`TransportObjectReferenceTests` covers strict JSON round-trips in every scope,
independent literal/native equivalence for singleton/multi-port and enabled/dormant
rules, type/literal/protocol denial and malformed snapshots. `TransportPolicyObjectTests`
and `local-sessions/transport_references.py` cover scoped selection/removal,
ordinary-edit pin preservation, immutable database history/usage, forged versions,
CSRF/RBAC and unrelated matcher retention. All existing immutable saved revisions
remain independently validated.

Router namespace fixtures now compile referenced NAT port matchers. Auxiliary
native/agent fixtures carry referenced bridge-forward and regular-chain ports
through dual-stack packet acceptance, native echo/list reconstruction, apply,
confirm, independent watchdog rollback and drift/recreation/collision denial.
The mapped-identity web fixture selects the port versions through the actual UI
before its Unix/mTLS multi-table apply/confirm/rollback scenarios. No host accounts,
production sockets, foreign host rules or production exports are modified.


### Object version comparison

`ObjectVersionComparisonTests` verifies directional entry differences, unchanged
entries, metadata-only changes, same-version results, defensive collections and
rejection of unrelated identities/types. Overlapping IPv6 prefixes remain exact
entry differences; the view does not infer network coverage or traffic outcomes.
The object-library HTTPS fixture verifies forward/reverse/same-version pages,
escaped descriptions, local time markup, missing/out-of-range/duplicate version
inputs, read-only historical/Auditor access and unchanged database/audit counts.
No compiler, agent or native enforcement semantics change in this view.

Application theme action labels are verified by `scripts/app-theme.test.mjs`:
saved/configured/system preferences, first-render accessible labels, unrelated
clicks, system theme changes and switching with storage denied. The application
and Pages both label the destination theme explicitly. These are browser
presentation preferences; configured defaults and saved policies are unaffected.

The HTTPS object-library fixture also verifies content-versioned URLs for the
shared theme/time/application scripts, stylesheet and bundled policy editor.
It fetches each asset and checks the URL's version against the SHA-256 of the
served bytes. Script/link MVC tag helpers are enabled explicitly without
changing form tag-helper or CSRF behavior. Changed assets receive new URLs on
upgrade so browser caches cannot keep the preceding editor/theme code by URL.

History-selector unit checks use real SQLite state to verify one-list expansion,
other-current-only choices, defensive snapshots and unchanged revision/audit state.
HTTPS checks cover retained rule/matcher/version selections in all five supported
reference scopes, unchanged draft contents, exact old/new version attachment and
denial of missing versions, invalid scope/chain/rule/slot and unknown operations.
No compiler, ownership, agent or rollback contract changes in this UI workflow.

### Postrouting address sets and references

Core checks cover defensive source/destination snapshots, strict malformed/unknown
JSON rejection, family/cardinality/conflict/overlap/adjacency denial including dormant
rules, singleton/multiple reference equivalence and complete native echo/list
fingerprints. Canonical native host addresses are strings, not /32 or /128 prefix
objects. Web real-SQLite/unit/HTTPS checks cover both address slots/families, readonly
pin fields, guided/legacy edit retention, forged history/usage and required-SNAT-source
removal denial. Later library versions cannot modify saved policy bytes.

The router namespace fixture observes actual dual-stack packet sources for set
membership, independent source/destination misses, negation, return exemptions
and disabled/restored exemptions. It round-trips complete native set observations.
Agent auxiliary lifecycle now carries address-set NAT tables through confirm,
explicit/independent watchdog rollback, removal/restoration and restart. The new
`nat-set-drift` case changes native address-set contents and requires recovery
without overwriting unexpected state. The mapped-identity HTTPS fixture selects
address versions through the real UI before Unix/mTLS apply/confirm/rollback checks.
These remain synthetic isolated fixtures, not real-server conversion acceptance.

### Bridge address sets and references

`BridgeAddressTests` covers both families/chains, singleton/set snapshot equivalence,
defensive collections, malformed strict JSON, family/conflict/overlap denial and
complete native fingerprints. Web tests use real SQLite history and saved usage;
HTTPS checks attach all eight scoped address pins, retain MAC/graph/state through
guided edits, reject forged versions and preserve previous revision bytes.

The auxiliary namespace fixture carries referenced sets in forwarding jumps and
regular returns. Real dual-stack TCP checks verify permitted traffic, source and
destination misses, MAC denial, and the unchanged default verdict when a base
matcher excludes traffic. The eighth agent case, `bridge-set-drift`, changes set
contents at the same native handle and requires recovery without overwriting drift.
Distinct-UID Unix/mTLS web apply tests select bridge versions through actual UI
endpoints before complete apply/confirm/rollback. No production firewall is used.

### DNAT original-port sets and references

Core tests cover singleton/set equivalence in both families, dormant validation,
defensive snapshots, strict JSON, type/protocol/literal conflicts and complete
native set fingerprints. Real-SQLite web tests retain translation/negation/state,
usage and immutable history. HTTPS fixtures cover attachment/history/removal,
read-only fields, ordinary edits, forged versions, CSRF/RBAC and malformed or
duplicate numeric/form fields that must not fall back to unrestricted defaults.

The three-namespace DNAT fixture sends both referenced original ports to one
translated backend port and checks nonmember denial in both IP families, including
explicit SNAT and `ct status dnat`. Auxiliary agent lifecycle carries referenced
DNAT sets; the ninth recovery case, `dnat-port-drift`, replaces a set at the same
handle and requires recovery without overwriting unexpected state. The distinct-UID
web fixture selects the list through the real UI endpoint before Unix/mTLS
apply/confirm/independent rollback. All addresses and namespaces are synthetic.

### DNAT address sets and references

Core checks cover both families, singleton/set references, dormant validation,
defensive snapshots, missing/conflicting/wrong-family/overlapping restrictions,
strict JSON and complete native echo/list fingerprints including negation. Real
SQLite and HTTPS checks retain all three pins, translation, rule state and immutable
usage/history; forged versions, literal injection and required-destination removal
are denied. Explicit source removal also clears its negation.

The three-namespace NAT fixture checks both source/destination set members,
independent misses and negated sets with positive controls in both IP families.
It verifies complete echo/list round-trips before and after negation. Auxiliary
agent lifecycle carries referenced DNAT addresses and ports through confirmation,
restart and rollback. The tenth recovery case, `dnat-address-drift`, changes only
an address-set entry at the same handle and requires recovery without overwriting
unexpected state; the port-drift case now preserves all address matchers too.
Mapped-UID web apply selects source/destination versions through real endpoints
before complete Unix/mTLS apply/confirm/rollback. Fixtures remain synthetic.

## Native observation generation consistency

After the Release solution build, run:

```sh
bash tests/integration/nftables/check-generation.sh
```

This opt-in Linux fixture requires `dotnet`, `unshare`, `nft`, `ip`, `ping`, Python 3
and `capsh`. It refuses matching parent user/network namespaces. Fixed synthetic
objects exist only inside the disposable namespaces. Real generation reads must
stay stable across queries and dynamic meter packet traffic, change on table
creation/deletion and same-handle static-set element updates, and fail without
`CAP_NET_ADMIN`. It adds no support for compiling named sets. Unit tests separately
reject malformed, unknown, truncated and uncorrelated replies, mixed-generation
collections, query failure and cancellation. Existing agent and mapped-identity
apply/confirm/watchdog suites exercise the guard on complete receipt collection.
See [ADR 0047](decisions/0047-generation-consistent-native-observations.md) for the
remaining observation-to-transaction race and conservative foreign-write denial.

## Native static list references

After a Release build, run:

```sh
bash tests/integration/nftables/check-native-static-sets.sh
bash tests/integration/enrollment/check-auxiliary-apply.sh --named-sets
bash tools/integration/check-mapped-identities.sh
```

The native fixture verifies complete echo/list identity and artifact round-trips in
all four owned tables, actual routed dual-stack DNAT source/destination/port members
and independent misses, complete-set negation, pinned filter admission, coexistence
with populated dynamic meters and low IPv6 singleton/prefix member/miss packets.
Static collection joins separate listings with exact definition/handle agreement;
terse static contents alone are refused. Five named agent cases cover native bridge
packets, confirm, explicit/independent watchdog rollback, restart and preservation
of lookup/content/handle drift. The mapped-UID HTTPS fixture uses actual UI native
attachments before Unix/mTLS apply and confirmation/rollback.

Core tests check shared definitions, singleton/dormant behavior, strict projection
flags, snapshot conflicts, unknown/partial/orphan objects, lookup/handle fingerprints,
bounded collection and early observation-budget denial. Creation-completion tests
remove emitted elements and require matching original definitions/handles, complete
listings and an exact protected artifact. Conflicting echo values, listing handles,
missing definitions/listings and changed artifacts fail. Real-SQLite tests also
exercise native candidate/baseline mismatch and new-boot reconciliation. Unit tests
establish these data/provenance contracts without kernel access; packet evidence
comes from the disposable native fixtures above.

HTTPS checks retain native projection through ordinary edits, history, immutable
saves and inline disable/re-enable, including omission/restoration of unused native
objects. Existing literal-projection tests remain for older revisions. See
[the native static-set guide](native-static-lists.md) and ADR 0048 for support limits.
