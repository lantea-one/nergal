# ADR 0047: Generation-consistent native observations

- Status: accepted; implemented and verified in disposable namespaces
- Date: 2026-11-24

## Decision

Bracket each complete agent observation with the Linux nftables transaction
sequence (`NFT_MSG_GETGEN`, `NFTA_GEN_ID`). Accept the combined filter, NAT,
bridge and auxiliary snapshot only when both reads succeed and their generation
IDs match. Collection remains under the existing resource execution lock.
Unknown, malformed, denied or timed-out replies make observation unavailable;
there is no fallback to unchecked collection and no automatic retry that could
hide sustained concurrent modification.

The Linux helper sends one fixed read-only netfilter netlink query, with a private
unsubscribed socket, a bounded reply and deadline, cancellation, kernel-sender and
request-correlation checks. It accepts only the documented generation response.
It accepts no table names, policy bytes or mutation commands. Framework-independent
Core contracts and protected journal schemas stay unchanged.

This is a consistency check within one collection, not a persistent generation
receipt or a kernel compare-and-swap. Generation equality cannot close the race
between observation and a later transaction; competing privileged writers remain
unsupported. It also assumes fewer than 2^32 committed transactions during the
bounded collection. A transaction in any table in the current network namespace
can conservatively invalidate collection, including unrelated tables. Packet
counters and dynamic meter traffic do not constitute configuration transactions.

Native static named sets require complete element collection. Terse table listing
omits those elements as well as dynamic meter contents. This guard is a prerequisite
for safely combining future individual static-set listings with terse table/rule
snapshots; it does not add named-set support or weaken unknown-object rejection.

Implement independently against the public Linux netlink ABI:
[netlink.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netlink.h),
[nfnetlink.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nfnetlink.h),
and [nf_tables.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nf_tables.h).
No third-party implementation is copied.

Acceptance requires malformed/uncorrelated reply denial without host access,
real isolated generation reads across static set-element changes, read denial
without namespace capability, unchanged generation under actual meter traffic,
and existing receipt-bound apply/confirm/rollback conformance. All kernel checks
use disposable user/network namespaces and synthetic objects, never host rules.

## Acceptance results

The pure unit suite rejects malformed/unknown/uncorrelated wire replies, changed
and wrapped generations, failed initial/final queries, invalid collection and
cancellation. The real namespace fixture verifies stable reads, same-handle static
set-element mutation, dynamic meter packet traffic and capability denial. Existing
agent lifecycle/drift scenarios and the mapped-identity Unix/mTLS/web workflow pass
with the guard enabled, including explicit and independent timeout rollback.
No production kernel state was observed or modified. No new UI is introduced by this guard;
existing screenshots remain applicable.
