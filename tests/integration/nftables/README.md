# Isolated native compiler conformance slice

Run from a Linux development machine after the pinned SDK Release build:

```sh
bash tests/integration/nftables/check.sh
```

Requires `dotnet`, `unshare`, `ip`, `nft`, `ping`, Python 3, nftables kernel support,
IPv6 and permission to create unprivileged user/network namespaces. No root,
Docker, daemon, host bus, network service or production firewall access is needed.
Missing tools/isolation fail the test; there is no privileged fallback. The script
creates fresh user and network namespaces together and verifies both differ from
the caller before any nft command. All namespace state disappears at process exit.
The C# fixture emits a policy through the actual compiler, not a hand-written
substitute. Compilation occurs outside the namespace and performs no host access.

The fixture uses synthetic `192.0.2.0/24` and `2001:db8::/32` addresses on its own
loopback device. Tests verify:

- Native `nft --check` accepts a candidate and changes no namespace state.
- Foreign sentinel tables in ip, ip6, inet and bridge remain unchanged.
- A preexisting reserved table causes both check and apply to fail without changes.
- A kernel-invalid command appended to a valid candidate rejects the entire batch.
- Repeated create-only provisioning fails without changing the installed policy.
- Real TCP connections and UDP datagrams succeed for permitted IPv4/IPv6 traffic.
- Earlier TCP drops override later permits; unmatched UDP receives default drop.
- Wrong source/destination traffic is denied in both families.
- ICMP and ICMPv6 echo packets reach the local namespace address.
- A 3-namespace routed topology (`client` <-> `router` <-> `server`) verifies schema-2
  `input`/`forward`/`output` drop defaults, interface matching (`iifname`/`oifname`),
  IPv6 Neighbor Discovery (`nd-neighbor-solicit`, `nd-neighbor-advert`) over
  drop-default chains, stateful return forwarding (`ct state established,related`),
  per-source dynamic rate limiting (`nergal_rl_*` isolation between distinct IPv4 and
  IPv6 client addresses), and deterministic `NftTableObservation` round-tripping across
  both populated full listings and `--terse` listings.
- A second 3-namespace NAT topology (`nat_check.py`) removes the server's default route
  and verifies dual-stack DNAT port forwarding, explicit SNAT source rewriting observed
  by the backend socket, `ct status dnat` filter discrimination, and live NAT/filter
  `NftNatTableObservation` / `NftTableObservation` round-tripping.

Denied packet assertions use bounded socket receive/connect timeouts. Listener
sockets exist before sending, so service startup timing does not determine results.
No production rules or topology are read or changed, and no host ruleset is flushed.

This suite covers schema-1/2 filtering, per-source rate limits, and dual-stack NAT;
bridge filtering, coordinated multi-table atomic transactions, remote agent control,
and web-driven confirmed apply belong to Phases 9–13.
This fixture is opt-in and not run by the default CI job.
