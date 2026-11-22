# ADR 0039: Versioned controller object library

Status: Accepted for library management; policy references remain a separate milestone.

## Decision

Introduce framework-independent immutable IPv4, IPv6 and transport-port lists.
Each object has a stable controller UUID, unique lowercase identifier and fixed
type. Each edit appends an immutable version and attributed audit event in one
transaction. Require the editor's expected version so stale forms cannot overwrite
another administrator's change. Keep historical contents available by identity and
version. Names/types cannot change and objects cannot be deleted in this slice.

Validate numeric addresses/CIDRs and individual ports, reject mixed families,
scopes, mapped addresses, host bits, duplicates and unsupported ranges/flags.
Canonicalize spelling and ordering without merging or dropping entries. Bound
objects, versions, entries and request sizes. Display validation guidance and retain
invalid form values. Auditors may read; only Administrators with CSRF may write.
Store UTC instants and render them in the viewer's timezone.

Controller schema 3 adds protected object/version tables with immutable SQL triggers.
Extend the explicit offline upgrade for validated schemas 1 and 2; the web process
never migrates. Protect legacy sources/audits and reject colliding new tables.

Library edits confer no firewall authority. This slice does not translate lists to
native sets or attach them to policy rules. Do not flatten a reference into literals
and call that named-object support. Future policy integration must bind immutable
object identity/version/content into saved revisions, show impacted references and
require candidate review plus confirmed apply. Complete native observation and
packet/rollback conformance are required before native named sets are supported.

## Verification

Use real SQLite for reopen/history, stale edit and duplicate-name rejection,
role denial, atomic audit failure, capacity and trigger/digest corruption tests.
Verify explicit schema-2 upgrade preserves sources and revisions. Exercise HTTPS
read/write/CSRF/role boundaries, invalid and duplicate fields, escaped output and
restart persistence. Public screenshots contain synthetic objects only.
