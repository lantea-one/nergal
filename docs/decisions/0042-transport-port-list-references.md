# ADR 0042: Pinned port lists in postrouting and bridge rules

## Decision

Extend the existing immutable controller-reference contract to postrouting NAT and
bridge destination-port matching, including regular bridge chains. Canonical policy
intent retains identity, version, typed contents and digest. Never fetch "latest"
at compile/apply time. Controller preview/save verifies every reference against
immutable database history; agent compilation uses only the embedded snapshot.

A pure domain projection resolves a singleton to the scalar port matcher and a
larger list to the existing port-set matcher. Reject type mismatches and conflicting
literal ports, then run the complete native validation, including dormant rules.
Preserve family, protocol, NAT action/target, MAC/IP restrictions, jump/return,
priority, order, descriptions and enabled state. New JSON fields are strict:
older codecs must reject them rather than ignore a restriction.

Extend saved-usage enumeration to every supported scope. A dedicated UI selector
pins the displayed version; ordinary editing cannot discard it. Explicit removal
clears only the port matcher and warns that access can broaden. Draft editing,
revision save and confirmed apply remain separate. No SQL schema change is needed.

Native observations describe the projected kernel matchers, not controller identity.
Exact compiled artifacts, full owned-table receipts and independent timed rollback
remain authoritative for apply/confirm/recovery. Verify canonical round-trips,
invalid/forged references, preservation, real packets and receipt-bound rollback.

This does not add address-list matching to NAT/bridge, DNAT port translation lists,
native named sets/maps or dynamic objects. Those require their own complete typed
contracts, native observation and packet acceptance; no rule expansion or lossy
approximation is introduced here.
