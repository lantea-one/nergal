# Policy Reference

Policies are authored as versioned `FirewallPolicyBundle` JSON documents containing a required `filter` section and optional `nat` and `bridge` sections.

## Filter Policy (`inet nergal_filter`)

- **Schema 1**: Stateless `input` chain only (`inputDefaultVerdict`, scalar `source`, `destination`, `destinationPort`, `protocol`).
- **Schema 2**: Multi-chain (`input`, `forward`, `output`) with explicit per-chain default verdicts, interface matchers (`inputInterface`, `outputInterface`), conntrack state masks (`connectionStates`), `matchOriginalDestinationDnat` (`ct status dnat`), per-source dynamic rate limiting (`rateLimit`), allowlisted ICMP/ICMPv6 types (`icmpType`), and inline anonymous sets (`sourcePrefixes`, `destinationPrefixes`, `destinationPorts`).

### Inline Address & Port Sets (Schema 2)

- `sourcePrefixes` / `destinationPrefixes`: `2..64` distinct, disjoint, non-adjacent canonical CIDRs matching the rule's `family` (mutually exclusive with scalar `source`/`destination`).
- `destinationPorts`: `2..64` distinct TCP or UDP ports in `1..65535` (mutually exclusive with scalar `destinationPort`).
- Requiring at least two disjoint, non-adjacent prefixes ensures `nftables` preserves each element without folding singletons into scalars or merging adjacent prefixes into a `range`, guaranteeing deterministic compiler-to-observation round-trips.

### Allowlisted ICMP / ICMPv6 Types

| Protocol | Allowed `icmpType` values |
| --- | --- |
| `icmp` (IPv4) | `echo-request`, `echo-reply`, `destination-unreachable`, `time-exceeded`, `parameter-problem` |
| `icmpv6` (IPv6) | `echo-request`, `echo-reply`, `destination-unreachable`, `packet-too-big`, `time-exceeded`, `parameter-problem`, `nd-router-solicit`, `nd-router-advert`, `nd-neighbor-solicit`, `nd-neighbor-advert` |

## NAT (`inet nergal_nat`) & Bridge (`bridge nergal_bridge`)

- **NAT (`schemaVersion: 1`)**: Dual-stack prerouting `dnatRules` and ordered postrouting `snatRules`. Explicit SNAT remains the default; current router extensions add explicit `action: masquerade` and `action: return` choices.
- **Bridge (`schemaVersion: 1`)**: L2 forwarding chain (`defaultVerdict` + ordered `rules` matching `etherType`: `any`, `ipv4`, `ipv6`, `arp`, and optional `inputInterface`/`outputInterface`).

## Canonical Multi-Table Bundle Example

```json
{
  "schemaVersion": 1,
  "filter": {
    "schemaVersion": 2,
    "inputDefaultVerdict": "drop",
    "forwardDefaultVerdict": "drop",
    "outputDefaultVerdict": "accept",
    "rules": [
      {
        "family": "ipv4",
        "protocol": "tcp",
        "verdict": "accept",
        "chain": "input",
        "connectionStates": ["established", "related"]
      },
      {
        "family": "ipv4",
        "protocol": "tcp",
        "verdict": "accept",
        "chain": "input",
        "sourcePrefixes": ["192.0.2.0/24", "198.51.100.0/24"],
        "destinationPorts": [80, 443],
        "connectionStates": ["new"]
      },
      {
        "family": "ipv4",
        "protocol": "icmp",
        "verdict": "accept",
        "chain": "input",
        "icmpType": "parameter-problem"
      }
    ]
  },
  "nat": {
    "schemaVersion": 1,
    "dnatRules": [],
    "snatRules": [
      {
        "family": "ipv4",
        "source": "192.0.2.0/24",
        "translatedAddress": "198.51.100.2",
        "outputInterface": "wan0"
      }
    ]
  },
  "bridge": {
    "schemaVersion": 1,
    "defaultVerdict": "accept",
    "rules": [
      {
        "etherType": "ipv4",
        "verdict": "drop",
        "inputInterface": "br0"
      }
    ]
  }
}
```

## Unreleased router and settings work

See [Router Migration & Local Sandbox](router-migration-and-sandbox.md) for the
current support matrix, supported apply scope and recovery limits, saved-settings/runtime distinction,
private source inspection, container isolation, verification limits, and screenshots.
This local development work is not a published release.
