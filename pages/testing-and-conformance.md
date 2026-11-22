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
current support matrix, preview-only apply limits, saved-settings/runtime distinction,
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
sandbox remains unprivileged. Extended auxiliary dispatch is still gated pending
its own acceptance evidence.
