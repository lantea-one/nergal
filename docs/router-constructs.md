# Router constructs and migration status

The current development branch extends the existing typed policy contract. This
is local development work, not a published release or a claim that arbitrary
native configurations can be imported losslessly.

| Construct | Current support | Verification boundary |
| --- | --- | --- |
| Raw prerouting rpfilter, FIB unreachable lookup, UDP source ports | `filter.rpFilter` with ordered accept/drop rules | Native echo/list reconstruction; real IPv4 spoof denial and UDP 68 bypass |
| Forward TCP SYN MSS clamp | `filter.forwardTcpMssClamp`, 536–1460 | Captured forwarded IPv4 SYN contains MSS 1360 |
| Source MAC scalar/set/negation, ICMPx admin-prohibited reject | Filter-rule MAC fields and `verdict: reject` | Native syntax and echo/list reconstruction; MAC+IP mismatch packet denial |
| Destination-keyed meters | `rateLimit.keyKind: destinationAddress` | IPv4 and IPv6 packet tests share state across sources and separate destinations |
| Negated interface and IP matchers | Explicit `negate*` booleans | Compiler/codec validation, native reconstruction; dangling negation is rejected |
| Postrouting masquerade and return, ingress/protocol/port restrictions | `snatRules[].action` plus optional matchers | Real dual-stack translated source and unmodified return-exemption source |
| Independent early inet filtering and extended bridge jump/return | `auxiliaryFilter` and extended `bridge`, including priority -5 | Compiler preview and native syntax only; agent apply is denied |

The first six rows have compiler and observation support. This does not establish
web-driven watchdog rollback for every new combination. The last row is explicitly
**preview-only**: the controller, agent handler, and atomic replacement compiler
reject it with `policy.previewOnlyScope`. Complete independent auxiliary-table
ownership, drift observation, packet conformance, and timed rollback remain required.

## Authoring

Use **Advanced JSON & Revisions** in the policy builder for the new fields. The
existing simple structured forms do not yet expose every router field. They retain
advanced policy settings and existing matchers when changing other fields; invalid
cross-field edits are rejected. Always inspect the complete native candidate.

For example, these are optional schema-2 filter fields:

```json
{
  "forwardTcpMssClamp": 1360,
  "rpFilter": {
    "defaultVerdict": "accept",
    "rules": [
      { "verdict": "accept", "inputInterface": "lo" },
      { "verdict": "accept", "protocol": "udp", "sourcePort": 68 },
      { "verdict": "drop", "matchFibUnreachable": true }
    ]
  }
}
```

Bypasses are explicit ordered policy, never automatic compiler exemptions. Evaluate
IPv6 control traffic and the actual routing design before using a reverse-path
filter. The example is a contract illustration, not a deployable gateway policy.

A filter rule may pair `sourceMac: "02:00:00:00:00:01"` and
`source: "192.0.2.2/32"`; both restrictions are emitted. `negateSourceMac: true`
requires a MAC matcher. `reject` is an inet rule action, not a base-chain policy.
`rateLimit.keyKind` defaults to `sourceAddress`; unknown keys are rejected.

A postrouting rule chooses `action: "snat"`, `"masquerade"`, or `"return"`.
Explicit SNAT requires a source and translated address. Masquerade/return require
no translated address. They can restrict `inputInterface`, `outputInterface`,
`protocol`, `destinationPort` or `destinationPorts`, and source/destination prefixes.
Rule order is preserved so return exemptions precede later translation.

`auxiliaryFilter` contains a numeric `priority` and a schema-2 `filter` policy;
it compiles to reserved `inet nergal_aux`. Extended bridge policies retain reserved
`bridge nergal_bridge`, accept `priority`, and declare `subChains` containing
`name` and `rules`. Bridge rules support `bridgeName` (`meta ibrname`), source and
destination MACs with negation, optional family/prefix/transport/port matchers,
`jumpTarget`, and `return`. A jump/return uses `verdict: "drop"` as a neutral draft
value; conflicting actions, missing targets, cycles, and jump depth beyond eight
are rejected. Foreign table names are never adopted from imported text.

Existing filter observation fingerprints remain unchanged when new fields are
absent. Extended filter semantics use observation v7; extended NAT semantics use
NAT observation v2. Native test recordings contain only synthetic addresses and
locally administered MACs.

## Private source inspection

An operator can configure `NativeSources:Directory` on an authenticated controller.
Startup loads up to 32 non-linked `*.conf` files, each at most 512 KiB, from a trusted
operator-controlled directory. Administrators can inspect escaped exact snapshots
and SHA-256 content bindings at `/manage/sources`. Auditors are denied. There is no
request-controlled file path, source execution, or automatic policy conversion.
Keep the trusted directory and its parents protected against concurrent replacement.

The [local sandbox](local-sandbox.md) supplies a separate network-isolated native
check-only worker per private input. A successful `nft --check` establishes syntax
and kernel validation in that worker's namespace; it does not establish equivalence
to a managed policy, deployed topology, or packet correctness of a server export.
