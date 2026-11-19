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

Denied packet assertions use bounded socket receive/connect timeouts. Listener
sockets exist before sending, so service startup timing does not determine results.
No production rules or topology are read or changed, and no host ruleset is flushed.

This verifies a local input-hook slice, not routing across interfaces, IPv6 neighbor
discovery/control completeness, NAT, fragmented traffic, rate limits, performance,
confirmed apply or rollback. The compiler is not connected to an agent or the web
host. A passing test does not make this a production firewall policy or apply path.
This fixture is opt-in and not run by the default CI job.
