# ADR 0065 — Fresh schemas for prerelease database development

Status: Accepted for M6.

Nergal has no supported public release baseline yet. Initialize each application
store from its current schema. Reject an obsolete or unknown schema under the
store's ordinary integrity checks. Remove the controller's offline conversions
from development schemas 1 through 3. Initialization refuses to overwrite an
existing database. The current schema requires the settings table and its
integrity constraints. A settings request cannot recreate a missing table.

Schema 5 appends one immutable settings version per accepted save and commits
its audit event in the same transaction. A unique token identifies each recorded
version across controller databases and divergent restores. This decision
authorizes no data reset or live operation. Existing development data can be
preserved or used with the build that created it.

The controller, account store and protected agent journal keep separate owners.
The controller stores desired policy, exact native-source inputs, pinned reusable
objects, conversion evidence and operator audit. Current policy revisions are
immutable review and deployment records. The protected agent journal remains the
authority for host ownership, expected receipts and pending rollback. An
application database restore cannot establish any of those facts.

Use one supported policy representation at release. Consolidate development
formats where necessary and keep verified rule semantics, ordering, disabled rule
parameters and exact native source retention. Wire, policy and SQLite schema
identifiers belong to different contracts. Removing obsolete store migration code
does not establish compatibility for the current policy and agent formats.

The controller store shares parameterized domain operations across SQLite,
PostgreSQL, MariaDB, MySQL and SQL Server. Each server has its own current
schema with explicit constraints and triggers. It records a fingerprint of
the database catalog at initialization and checks the catalog before store
operations. A transaction-scoped lock on a singleton metadata row serializes
controller writes, including version allocation and stale-token checks.
Each server requires its own fresh-init, constraint, concurrency and native
backup/restore evidence. Retain schema identification and plan release-forward
migrations from the first supported baseline.
