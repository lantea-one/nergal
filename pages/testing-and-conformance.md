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
