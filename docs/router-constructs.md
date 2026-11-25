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
| Shared static IPv4/IPv6/port list references | Generated constant named sets, exact immutable versions in every declared reference scope | Complete contents/handles/lookups, IPv6 echo omissions, real packets and receipt-bound apply/rollback |
| Independent early inet filtering and extended bridge jump/return | `auxiliaryFilter` and extended `bridge`, including priority -5 | Real dual-stack bridge/early inet packets, complete receipts, confirmed apply and local rollback |

All rows have typed compiler and complete native observation support. Auxiliary
acceptance verifies dual-stack MAC+IP pinning and negation, bridge master matching,
local jump/return control flow, priority -5 before a later -4 hook, and early inet
restrictions without bypassing the primary filter. Real agent checks cover
confirmation, explicit/timeout rollback, controller loss, watchdog restart and
auxiliary removal/restoration. Separate-UID HTTPS/mTLS checks exercise all four
table types. This is bounded synthetic conformance, not arbitrary source import
or production deployment proof.

Rollback requires the protected baseline or recorded candidate native fingerprint.
Drift, copied-marker recreation, missing/unknown native state and ambiguous
unacknowledged replacement require manual recovery and are never silently adopted.

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
Postrouting also accepts `sourcePrefixes`/`destinationPrefixes` (2–64 disjoint,
non-adjacent same-family prefixes) or immutable `sourceObject`/`destinationObject`
references, exclusive with scalar restrictions. Complete observations retain every
set entry and use address-set fingerprint v3. Rule order is preserved so return
exemptions precede later translation. See [ADR 0043](decisions/0043-postrouting-address-sets-and-references.md).

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

## Operator staging and private source ingestion

An operator can configure `NativeSources:Directory` on an authenticated controller.
Startup loads up to 32 non-linked `*.conf` files, each at most 512 KiB, from a trusted
operator-controlled directory. Administrators can explicitly import these staging
snapshots into the database at `/manage/sources`, then inspect escaped exact content
and SHA-256 bindings. Auditors are denied. There is no request-controlled file path,
source execution, or automatic policy conversion.
Keep the trusted directory and its parents protected against concurrent replacement.

The [local sandbox](local-sandbox.md) supplies a separate network-isolated native
check-only worker per private input. A successful `nft --check` establishes syntax
and kernel validation in that worker's namespace; it does not establish equivalence
to a managed policy, deployed topology, or packet correctness of a server export.

## Source-bound migration reviews

The Native sources screen now inventories review keywords with one-based line
references and offers an administrator-only JSON report bound to the source
SHA-256. Reports separate typed mapping work, source resolution and known contract
gap signals such as maps, counters and `notrack`. The underlying library performs
bounded lexical scanning only: words may be identifiers, unknown syntax is not
validated, and the signal catalog is not exhaustive. Comments, quoted strings
and variable references do not create signals. Incomplete inventories have stable
diagnostics and never return partial findings.

Every report keeps `canConvert: false`. No source text is executed, no includes
are opened, and no managed candidate or revision is created. Table/chain counts
are recognized declarative headers, not proof of native syntax or complete scope.
Every declaration and ordered rule still requires explicit semantic mapping and
packet-level equivalence checks. Reports contain line references and topic codes,
not source literal values; source names and digests remain private. See
[ADR 0037](decisions/0037-private-native-migration-review.md).

The [native source library](native-source-library.md) now accepts authenticated
bounded UTF-8 uploads into immutable controller database records and downloads their
exact original bytes. Operator directory snapshots are optional staging inputs;
reports and selected detail use stored source identities. This is source ingestion,
distinct from semantic conversion and generated policy export. Initialize a fresh
store using the current controller schema.
