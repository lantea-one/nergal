# Testing & Conformance

nergal requires deterministic unit tests plus real kernel verification in disposable Linux user and network namespaces (`unshare --user --map-root-user --net`). Production host firewalls are never touched during development or CI.

## Verification Layers

| Layer | Command | What It Verifies |
| --- | --- | --- |
| Build & Format | `dotnet restore --locked-mode && dotnet build -c Release && dotnet format --verify-no-changes` | Locked dependencies, zero analyzer/XML-doc warnings (`TreatWarningsAsErrors=true`), consistent formatting. |
| Unit Suite | `bash scripts/test-unit.sh` | Domain POCOs, JSON codecs, compilers, observation parsers, RBAC, apply state machine, and coverage artifacts. |
| Web Smoke | `bash scripts/smoke-web.sh` | MVC, Blazor, health endpoint, and absence of unauthenticated firewall-write endpoints. |
| Kernel nftables | `bash tests/integration/nftables/check.sh` | Dual-stack packet filtering, routed forwarding, DNAT/SNAT, bridge L2 filtering, inline address/port sets, IPv4 ICMPv4 `parameter-problem`, and foreign table preservation. |
| Ownership & Watchdog | `bash tests/integration/ownership/check.sh` & `watchdog/check.sh` | Exclusive creation, collision refusal, and autonomous timeout rollback. |
| Enrollment & Control | `bash tests/integration/enrollment/check.sh` & `local-status/check.sh` | `SO_PEERCRED` Unix control, TLS 1.3 pinned mTLS, unprivileged `Nergal.Web` (`CapEff == 0`) end-to-end multi-table confirmed apply & rollback. |
| Identity & OIDC | `tests/integration/admin/check.py`, `local-sessions/check.py`, `oidc/check.py` | Offline CLI provisioning, HTTPS cookie/CSRF/lockout/RBAC, and PKCE OIDC group mapping. |
| Docs & Packaging | `python3 scripts/verify-pages.py` & `bash scripts/package-release.sh --verify` | Pages link/content integrity and `.tar.gz`/`.deb`/`SHA256SUMS` package verification. |

## Unreleased router and settings work

See [Router Migration & Local Sandbox](router-migration-and-sandbox.md) for the
current support matrix, supported apply scope and recovery limits, saved-settings/runtime distinction,
private source inspection, container isolation, verification limits, and screenshots.
This local development work is not a published release.

## Unit framework maintenance

Unit tests use `xunit.v3` executable .NET 10 assemblies while retaining the VSTest
and Coverlet workflow. `scripts/test-unit.sh` requires one nonempty coverage report
from each of the three test projects. The framework migration retains all denied
operation and safety regressions; it is independent of native packet conformance.

## Reproducible mapped-identity checks

`tools/integration/check-mapped-identities.sh` runs the existing separate-UID
isolation and status/control/HTTPS fixtures inside a disposable container and fresh
nested namespaces. The full suite passed on November 22, 2026, including kernel
peer authorization, pinned mTLS, packet enforcement, independent rollback and basic
multi-table confirmation/rollback. The runner changes no host accounts or mapping
files and mounts neither private exports nor credentials. Its namespace capability
and relaxed container seccomp configuration belong only to test tooling; the web
sandbox remains unprivileged. Extended auxiliary dispatch now has dedicated packet and receipt-bound recovery
acceptance evidence, documented in the router support matrix.


List comparison unit/HTTPS checks cover directional/same-version entry differences,
metadata changes, exact CIDR handling, unrelated-identity rejection, escaped text,
bad/duplicate/missing version requests, Auditor access and unchanged database/audit
counts. Browser checks cover light/dark and mobile layouts. This read-only view
adds no native enforcement semantics or traffic measurement.

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

Bridge address references are checked in both chain scopes and both IP families:
strict JSON, immutable SQLite usage/history, HTTPS selectors and read-only pinned
fields, actual MAC-plus-IP/set packet outcomes, complete native reconstruction,
Unix/mTLS apply/confirm/rollback and same-handle set drift preservation. The agent
auxiliary launcher now runs eight recovery scenarios. Fixtures remain synthetic
and isolated; this does not establish private-source import equivalence.

DNAT original-port list checks cover immutable SQL pins/usage, strict JSON and
HTTPS forms, dual-stack members/nonmembers reaching one translated target, complete
native echo/list fingerprints and same-handle port-set drift preservation. All nine
auxiliary agent recovery scenarios and distinct-UID Unix/mTLS web apply/confirm/
rollback are verified in isolated synthetic fixtures.

DNAT address-list checks cover both families/slots, immutable SQL history and usage,
strict forms and required-destination removal denial, complete native fingerprints,
actual set members/independent misses/whole-set negation, and ten agent recovery
scenarios including same-handle DNAT address drift. Distinct-UID Unix/mTLS web apply
selects complete snapshots through actual UI endpoints. No production apply occurs.
