# Architecture

The first milestone is an independently implemented, nftables-first management
application, not a new packet-filtering engine. The kernel continues to enforce
policy when the web console or identity provider is unavailable.

## Boundaries

1. MVC owns HTTP controllers and conventional views. Blazor provides reusable
   interactive components. Neither is a privileged firewall agent.
2. The core contains typed policy concepts, requirements, validation results and
   capability contracts. It has no knowledge of a particular site's addresses,
   authentication directory or deployment system.
3. A future compiler produces deterministic candidates from the policy model.
   Kernel JSON is an observation/command interface, not a lossless replacement
   for source metadata, comments and named definitions.
4. A future restricted agent validates owned-table operations and executes
   narrow native nftables transactions. It will not accept arbitrary shell scripts.
5. Deployment coordination must validate a complete candidate, snapshot owned
   state, arm local rollback, apply atomically, verify and confirm. Persistence,
   revisions and runtime state need explicit reconciliation.

Do not treat a capability declaration as evidence that a driver is implemented,
connected, authorized or healthy. The first core types only prevent lossy
backend selection. There is no privileged agent or policy compiler in this revision. The read-only
web foundation uses an ephemeral, application-scoped Data Protection provider
to avoid creating or sharing machine-wide keys. Durable authenticated releases
will require an explicit persisted and protected key store before session support.

## Optional site integration

OIDC identity providers, group names, agent endpoints and revision storage are
configuration concerns. A deployment can select AD-backed Keycloak roles, but
basic installations must not require that infrastructure. Unsupported or unknown
policy semantics must fail closed. Raw shell execution is not an extension API.

## Future adapters

A backend interface is a boundary, not a commitment to multiple implementations.
Only native nftables is selected. A firewalld adapter would require its own
semantic conformance suite and an accepted decision record before implementation.
Do not edit firewalld-owned tables from a native adapter.
