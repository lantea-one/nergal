# ADR 0001: native nftables as the first backend

- Status: accepted
- Date: November 18, 2026

## Decision

Implement a native nftables backend first. Do not implement a firewalld adapter
in the initial release and do not run a competing firewalld policy owner merely
to expose its D-Bus API. Keep policy concepts and capability validation separate
from the backend so that another implementation can be evaluated later without
reducing the core to a lowest-common-denominator ruleset.

## Evidence

An isolated firewalld 2.4.1 instance on Alpine 3.24 configured a custom zone,
a TCP service, a rich-rule rate limit and an IPv6 destination forward. Ordinary
reload preserved three foreign tables across inet, bridge and ip families.
This is a genuine strength and differs from the previously evaluated manager's
broad table reset behavior.

The generated rate limit was `limit rate 3/minute burst 5 packets`, a shared
rule bucket. It was not an independent nftables meter per source. The rich-rule
parser rejected the tested original-connection tuple, explicit SNAT address,
and per-source limit elements. These results establish limitations of the
supported rich-rule interface tested, not mathematical impossibility of building
similar behavior with every combination of policies or future firewalld releases.

The required semantics also include bridge policy, original-tuple-scoped NAT,
per-source state and atomic coordinated table changes. Adding a parallel native
rule system for these requirements would divide ownership and increase the
conformance and rollback burden. The deprecated direct interface is not an
acceptable foundation for that escape hatch.

The fixture and captured result are in tests/integration/firewalld. No production
firewall or host system bus was involved. This was a capability/reload test, not
a comprehensive packet-level migration rehearsal or performance benchmark.

## Consequences

Native nftables retains access to the required semantics and atomic transactions.
nergal must supply its own higher-level policy model, persistence, audit,
validation and confirmed-apply workflow. Use libnftables/structured input or
fixed-argument process execution without shell interpolation. Do not infer that
an atomic transaction also supplies connectivity rollback; the agent must do that.

Backend capabilities are explicit. Reject policies requiring missing semantics;
never substitute a global rate limit for a per-source limit or broaden a NAT rule.
Foreign tables and externally generated overlays need explicit ownership contracts.

## Sources

- https://firewalld.org/documentation/man-pages/firewalld.dbus.html
- https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html
- https://firewalld.org/documentation/man-pages/firewalld.policy.html
- https://firewalld.org/documentation/man-pages/firewalld.direct.html
- https://man.archlinux.org/man/libnftables-json.5.en
