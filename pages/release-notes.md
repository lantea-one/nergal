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
current support matrix, supported apply scope and recovery limits, saved-settings/runtime distinction,
private source inspection, container isolation, verification limits, and screenshots.
This local development work is not a published release.

## Source-bound migration review

Native source inspection includes a bounded lexical inventory, line references
and a private administrator-only report download. Conversion remains blocked:
review signals do not establish syntax validity, exhaustive coverage or semantic
equivalence. Named maps, tracking bypass and counters need explicit preservation
work. No private sources or topology are published in these notes.

## Database-backed native source library (unreleased)

Administrators can upload bounded UTF-8 native sources into immutable controller
schema-2 records, review one source, download its exact original bytes and obtain a
source-bound lexical report. Optional file-directory snapshots are staging only.
Imports and their audit records are atomic; no configuration is executed or
converted. Existing controllers require an explicit offline `controller upgrade`.
Additional SQL providers and semantic/generated-policy import/export remain future
work. See [the source library guide](native-source-library.md).

## Local timestamp display (unreleased)

Dashboard/apply audit rows, audit/revision history and native source imports now
render stored UTC instants in the viewer's browser timezone and locale. The page
names that timezone and each timestamp retains its original UTC instant. DST uses
the offset applicable to the event. Explicit UTC remains the fallback without
JavaScript/Intl. Database and API timestamps remain UTC.

## Unreleased typed object library

[Sets & IP lists](reusable-object-library.md) now supports typed IPv4/IPv6/port
lists with accessible forms, search, immutable version history, UTC storage/local
display, transactional audit and stale-edit protection. Controller schema 3 has an
explicit offline upgrade preserving schema-1/2 state. Policy references, native
named sets and impact review remain a separate milestone; library saves do not
change policies or firewalls.
