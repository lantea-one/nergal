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
3. The unprivileged `Nergal.Nftables` compiler produces deterministic, create-only
   candidates from schema 1 input-filter policies (see [the contract](policy.md)).
   It performs no host operations and the web host does not reference it.
   Kernel JSON is an observation/command interface, not a lossless replacement
   for source metadata, comments and named definitions.
4. A future restricted agent validates owned-table operations and executes
   narrow native nftables transactions. It will not accept arbitrary shell scripts.
5. `Nergal.LocalState` persists explicit enrollment assertions, exact artifacts and
   replayable transitions in a private SQLite journal. Transactions serialize
   confirmation/timeout and commit revisions with confirmation. It has no kernel
   access and is not referenced by Web. See [the journal contract](local-journal.md).
6. Core now models ownership/revision/artifact bindings and confirmed-apply state
   transitions (see [the contract](confirmed-apply.md) and ADR 0003). This is a pure
   model with no timer, watchdog or executor. Future coordination must
   validate a complete candidate, snapshot owned state, arm local rollback, apply
   atomically, verify and confirm. Revisions and runtime state need explicit
   reconciliation even with a durable journal.

Do not treat a capability declaration as evidence that a driver is implemented,
connected, authorized or healthy. The capability contracts prevent lossy
backend selection; the compiler implements only the subset in ADR 0002, not all
features represented by capability enums. No privileged agent exists. The read-only
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

## Next milestone

Implement an independent local watchdog prototype using the journal, limited to
disposable namespace resources. ADR 0003 defines crash-safe
ordering, confirmation/timeout serialization and recovery requirements; the current
state model supplies no durability or execution guarantees. Replacement transactions
and rollback need isolated packet and failure conformance tests before any host apply
path. NAT, forwarding, connection state and IPv6 neighbor discovery remain outside
the tested input-filter slice.
