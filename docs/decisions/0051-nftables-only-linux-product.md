# ADR 0051: Native nftables on Linux as the sole firewall target

Status: Accepted, November 24, 2026. Supersedes the future-backend scope in ADR 0001.

## Decision

Focus Nergal exclusively on native nftables on Linux. Other firewall engines,
translation adapters, Windows Firewall and Windows-native controller/agent
deployments are outside the product scope. Do not maintain a secondary-backend
roadmap, adapter extension promise or lowest-common-denominator policy model.
The web UI remains a browser application; this decision concerns deployed services
and firewall management, not which desktop operating system can view the UI.

Preserve direct nftables semantics and explicit support limits in authoring,
native source viewing/import, reusable objects, compilation, observation,
ownership, confirmed apply and rollback. Every supported construct needs complete
validation and conformance; unsupported input must be reported rather than silently
approximated. Native syntax coverage is incremental, not a promise to implement
every nftables expression.

Keep Core POCOs free of ASP.NET, SQL and host dependencies. Explicit capability
checks still describe supported native features and deny missing semantics; their
existence is not a commitment to other firewall engines. Preserve the unprivileged
controller/privileged-agent separation, protected receipts, atomic owned-table
transactions and independent rollback. Never adopt or modify another firewall
manager's tables. Historical firewalld research remains evidence for the original
decision, not a supported adapter or acceptance target.

This narrows firewall/platform scope, not deployment topology or database scope.
General-purpose FOSS, independent single/multi-host installations, optional OIDC,
UI-first administration and SQLite/PostgreSQL/MariaDB completion remain the agreed
targets. The initial private deployment remains an acceptance environment rather
than a required topology.

## Consequences and verification

Remove future-adapter language from current product documentation and explain the
fixed native target in application guidance, Pages and repository agent rules.
Use existing native compilation/packet/apply conformance rather than adding adapter
tests. Keep the existing `/backend-decision` URL as a stable route with the current
decision. Verify its content and the ordinary web/authorization suite; this scope
decision adds no privileged operation, schema migration or firewall change.
