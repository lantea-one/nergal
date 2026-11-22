# UI-first product workflow

The product must support ordinary administration entirely through the UI, with
progressive detail for different experience levels. JSON remains an optional
expert representation, not a prerequisite for supported policy authoring.

## Product scope

Nergal is intended to become a fully functioning, general-purpose FOSS firewall
manager. The initial private deployment guides prioritization and migration
acceptance; it does not define the limits of the product or its policy model.
Features must remain useful to independent operators with different hosts,
interfaces, identity providers, services and network layouts.

- Support a basic single-host installation and optional multi-host management.
- Keep site names, addresses, service ports and identity/group mappings in optional
  deployment configuration and private migration data.
- Implement missing semantics as reusable typed contracts with explicit validation,
  complete native observation, ownership and rollback support where applicable.
- Cover independent synthetic host, routed gateway, dual-stack and bridge scenarios
  in public tests; passing the initial deployment alone is not general conformance.
- Keep public installation, upgrade, recovery, contribution and support-limit
  documentation usable without access to the initial private environment.

Migration support is one product workflow. Operators must also be able to author
and maintain policies through the UI without importing an existing ruleset.

## Implementation sequence

1. Completed: auxiliary/extended bridge ownership, complete observation, atomic
   confirmed apply and independent rollback under ADR 0036.
2. Completed: dedicated auxiliary packet/recovery acceptance and a working
   mapped-UID runner. Additional real-server combinations remain part of migration
   gap assessment; synthetic conformance is not production equivalence.
3. In progress: source-bound lexical reviews expose migration topics and downloadable
   reports without claiming conversion. Build reusable semantic mapping and conversion
   support, using the initial private deployment as acceptance cases. Account for
   every declaration and rule, preserve semantics, report gaps explicitly, and verify
   independent synthetic topologies before claiming general support. Include the
   `nftables.conf` import/export workflow and reusable named-object preservation.
4. Complete structured authoring for every supported construct, with plain-language
   intent, contextual help, precise validation, complete review, and confirmed apply.
   Provide a dedicated reusable sets and IP lists library with reference and impact
   visibility, integrated with policy authoring.
5. Improve navigation, dashboard charts, user profiles, and setup workflows with
   accessibility and light/dark consistency. Keep documentation and screenshots current.

## Interaction requirements

- Guided tasks explain source, destination, service, interfaces, identity restrictions,
  ordering, and expected effects without requiring nftables syntax knowledge.
- Every individual rule has an inline enabled/disabled checkbox with a clear state
  label and keyboard access. Disabling preserves the rule, its settings and order;
  enabled state is versioned, visible in review/diffs, and preserved by supported
  import/export. Disabled rules do not enforce traffic policy. Changing an active
  rule's state follows revision review and confirmed apply rather than an immediate
  browser-to-kernel toggle. Define intent/native observation handling explicitly.
- Forms provide concise contextual hints for fields and choices: what each value
  means, required versus optional input, units, defaults and effect. Use synthetic
  examples and plain language, with progressive expert detail and actionable inline
  validation. Associate hints/errors with their controls for assistive technologies;
  guidance must be accessible by keyboard and not depend solely on hover tooltips.
- Expert controls expose the same full typed contract without a lossy alternate model.
- Editing JSON/code uses a real locally served code editor with highlighting,
  indentation, line numbers, keyboard support, and syntax diagnostics. Server-side
  typed validation remains authoritative. No CDN or telemetry is required.
- Charts use observed data and state their scope, collection time, and missing-data
  conditions. Do not invent traffic metrics from configuration counts or health probes.
- Profiles separate editable display/preferences from immutable identity and authorized
  role assignment. A user cannot promote their own role. Account changes need explicit
  authorization, CSRF, audit, session revocation, and last-administrator protection.
- Everyday operations stay in the UI. Initial privileged host trust/bootstrap remains
  an explicit local operator boundary, represented by a guided enrollment workflow;
  the browser never gains a shell or direct privileged host capability.

This is an active implementation plan, not a claim that all listed workflows exist.

## Database source of truth and later SQL migrations

The database is the rolling, authoritative store for application-managed state:
policies, reusable sets/IP lists, host configuration, settings, profiles, imported
source snapshots, semantic mapping reports, revisions and audit history. UI edits
must persist validated changes transactionally. Exports and generated configuration
are derived artifacts of an explicitly selected database revision; local files,
browser state and build artifacts must not become competing canonical stores.
Preserve immutable revisions and enough change history to review and recover state.
Store timestamps in UTC; display instants in the viewer's browser timezone with a
clear timezone indication. APIs and exports retain UTC instants. See [timestamp
presentation](time-display.md).

Keep desired, dispatched, confirmed and observed state distinct. A database edit
must not imply that a policy is active in the kernel. Store observations with their
provenance and collection time. Privileged agents retain their independently
protected local journal, ownership receipts and rollback decisions; the controller
database cannot grant host ownership or replace live verification. Credentials and
key material retain explicit encryption and bootstrap trust boundaries rather than
being moved into ordinary configuration rows.

This direction is not yet fully implemented. Native source uploads now persist
immutable database snapshots with transactional audit and exact original downloads
under ADR 0038. Operator-configured files are optional staging inputs. Some runtime
configuration still comes from protected deployment files. Typed reusable lists now
have immutable database history; policy-reference integration, semantic mapping
records and other planned state remain future work.
Deployment/bootstrap trust remains a separate boundary.

Stabilize the logical schema before implementing migrations for additional SQL
backends. Each supported backend needs explicit schema versions, ordered upgrade
migrations, compatibility checks and tested failure/recovery behavior, including
existing data, constraints, audit integrity and revision history. Document backup
and recovery requirements and test on the actual database engine. Avoid announcing
an adapter as supported merely because it appears in saved settings. Keep backend
persistence details outside framework-independent domain contracts.

## Reusable sets and IP lists

Provide a dedicated UI library for creating, naming, describing, editing, searching
and reusing typed sets and IP lists. Address lists support IPv4/IPv6 addresses and
CIDR prefixes with explicit family/type validation. Other set types are exposed
only as their semantics are implemented. Policies reference named objects rather
than requiring operators to repeat literal lists in every rule.

Show where an object is used before changing or deleting it. Reject dangling or
incompatible references. Object updates must produce reviewable policy changes;
saved revisions retain their original object contents and cannot silently change
when a shared list is edited. Define controller reuse and per-host native set scope
explicitly. Apply/rollback must cover the resolved objects and every affected rule.
Dynamic elements, timeouts, interval behavior and unsupported flags need explicit
support or a clear rejection, never silent flattening into weaker lists.

## nftables.conf import and export

Provide UI file import and download/export for `nftables.conf`. Preserve the exact
uploaded source separately from any converted managed policy, with a content-bound
mapping report accounting for declarations, named sets/maps, references, hooks,
priorities, ordering, control flow and rule semantics. Resolve unsupported constructs
and external includes explicitly; uploading a file grants no execution or ownership
authority. Parsing and review stay separate from saving a revision and confirmed
apply. The database source ingestion and lexical reviews are not semantic policy conversion.

Export an explicitly selected managed policy revision and its resolved reusable
objects as a deterministic native configuration. Identify its scope and revision;
do not imply that it is a complete host ruleset or include unrelated host tables.
Distinguish downloading the original source from exporting generated managed policy.
Test supported semantic import/export round trips, named-object references, denied
and invalid imports, and packet outcomes in disposable namespaces. Source formatting
or comments must not be claimed as losslessly preserved unless verified. Raw code
editing, where offered, uses the actual code editor and authoritative server validation.

The [typed list library](reusable-object-library.md) now supports create/edit/search
and immutable history. Policy references, impact visibility, native named sets and
generated export remain planned capabilities.

## Code editor delivery

Policy JSON now uses a local CodeMirror 6 bundle with syntax highlighting, line
numbers, folding, undo/redo, search, bracket matching and JSON syntax diagnostics.
Theme colors follow the console live. Tab leaves the editor; **Indent lines**
uses parser-aware indentation without rewriting or dropping duplicate keys.
Invalid JSON remains visible after preview, with the server's validation result.
The strict server contract, role and CSRF checks remain authoritative.

See [asset maintenance](../tools/web-assets/README.md) for locked dependency and
reproducible bundle/license verification. JavaScript-disabled browsers retain the
textarea and the same server validation. Native candidate and source views are
read-only; no raw nft transaction can be submitted from this editor.

## Verification runner milestone

The separate mapped-UID fixture environment is now reproducible through
`tools/integration/check-mapped-identities.sh`. Its full isolation and status/
control/HTTPS suite passes using disposable container-local accounts and nested
namespaces. No host account/mapping changes or fixture guard relaxations are
required. The auxiliary/extended bridge packet and watchdog acceptance milestone now also
passes under ADR 0036. The next milestone is explicit private server conversion,
followed by complete structured authoring and the broader UX/profile/chart work.
