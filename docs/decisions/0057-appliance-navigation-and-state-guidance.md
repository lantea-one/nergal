# ADR 0057: Appliance navigation and state-based overview

Status: Accepted for the first M5 usability slice; M5 remains open.

Use an independently implemented firewall-appliance interaction model: persistent
section navigation, focused rule/NAT/bridge/alias pages, contextual editors and a
compact overview. OPNsense's documented category/function navigation, data grids
and advanced-form disclosures, and pfSense's documented rule/alias workflows are
interaction references only. Retain Nergal styling and native nftables semantics;
copy no implementation, assets, branding or PF evaluation assumptions.

Move host connection management out of the overview into a dedicated reader page.
Keep host registration/removal Administrator/CSRF gated at the existing routes.
A pure presentation decision chooses the next useful read/navigation action from
current saved revision/host state. Pending confirmation and drift/recovery take
priority over setup. Auditors receive inspection guidance, not mutation prompts.
Unavailable or unqueried status is not proof that a host is offline, and a matching
agent baseline is not proof that the latest controller revision is applied.

The sidebar links to supported functions only. Firewall subsection navigation
preserves the current unsaved draft when enhanced locally; normal links remain
usable without JavaScript. Section selectors accept only a fixed allowlist. A
mobile menu, skip link, visible focus and accurate current-page state must work in
light/dark themes. Keep native rule ordering, source positions, pins and confirmed
apply/rollback boundaries intact. This slice adds no agent commands, enrollment,
account changes, telemetry, database migration or policy semantics.

Verify pure guidance priority/role/unknown-state cases, actual HTTPS route/RBAC and
host-registration behavior, draft-preserving navigation, and synthetic desktop,
keyboard and mobile workflows. Update application/Pages documentation and real
screenshots. Local users/profiles, observation-backed charts and the rest of the
M5 authoring redesign remain required before declaring M5 complete.

References: [OPNsense GUI](https://docs.opnsense.org/manual/gui.html),
[pfSense rule configuration](https://docs.netgate.com/pfsense/en/latest/firewall/configure.html).
