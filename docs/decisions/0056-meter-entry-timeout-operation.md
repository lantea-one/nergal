# ADR 0056: Preserve meter timeout refresh operations

Status: Accepted; conformance requires native observation and packet checks.

## Evidence and decision

The kernel JSON for native `meter name { ip daddr timeout 60s limit ... }`
contains dynamic-set operation `update`. The existing compiler's `add @set`
contains operation `add`. These are different timeout-refresh semantics, even when
initial packet allowances are identical. Import must not silently translate them.

Add an explicit `RefreshEntryTimeout` flag to the immutable rate-limit contract,
default false. False preserves all existing serialized intent, candidates and state
projections. True emits `update @set` and is serialized explicitly. Source meters
map to true; explicit add/update syntax retains its operation. Require a distinct
semantic feature for refresh behavior. Unknown operations remain denied.

Native echo/list reconstruction must preserve the operation and bind it into state
digests; changing update to add is drift. Existing old artifacts and protected
receipts must remain byte-compatible. Controller and agent must be upgraded together
for new refresh intent; older codecs reject the new field without mutation.
Guided rule forms must preserve and expose this choice, including dormant rules.

Verify legacy artifacts, complete codec round trips, malformed input denial,
operation-only drift, complete native reconstruction and actual entry expiry under
continued traffic in disposable namespaces. No production firewall changes are
part of this work.
