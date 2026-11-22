# Release Notes

nergal uses Calendar Versioning (`YYYY.MM.DD` and `YYYY.MM.DD.N` for same-day releases) and targets `.NET 10` LTS.

## `2026.11.21.1` (Milestone E)

- **Multi-table agent confirmed apply & rollback**: `nergal-agent` and `Nergal.Web` now dispatch, verify, confirm, and roll back full `FirewallPolicyBundle` policies spanning `inet nergal_filter`, `inet nergal_nat`, and `bridge nergal_bridge` with auxiliary ownership checks and coordinated `--echo --handle --json` validation.
- **Inline address/port sets & IPv4 ICMPv4**: Added schema-2 `sourcePrefixes`, `destinationPrefixes`, and `destinationPorts` (with disjoint/non-adjacent `UInt128` interval validation) plus IPv4 ICMP `parameter-problem`.
- **Visual rule builder & Blazor summary**: Added `PolicyBundleSummary.razor` and CSRF-protected Administrator MVC rule-builder actions (`/manage/policies/rules/{add,move,remove}`).
- **Forgejo Pages portal**: Added this static Docsify + Mermaid documentation site deployed automatically from `pages/` on `main`.
- **Linux release packaging**: Added `nergal.sysusers`, `nergal.tmpfiles`, and `scripts/package-release.sh` producing verified `.deb`, `.tar.gz`, and `SHA256SUMS` artifacts.

## `2026.11.21` (First Code-Complete Release)

- Completed Milestones A–D (Phases 1–14): native `nftables` dual-stack filter/NAT/bridge compilers, exclusive ownership & boot/namespace receipts, autonomous timed watchdog rollback, `SO_PEERCRED` Unix and pinned TLS 1.3 mTLS control protocols, local sessions + optional OIDC + RBAC, MVC/Blazor management UI, and end-to-end confirmed apply over HTTPS.

## Unreleased router and settings work

See [Router Migration & Local Sandbox](router-migration-and-sandbox.md) for the
current support matrix, preview-only apply limits, saved-settings/runtime distinction,
private source inspection, container isolation, verification limits, and screenshots.
This local development work is not a published release.
