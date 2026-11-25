# ADR 0054: Complete-statement native rule expression slice

Status: Accepted for a bounded expression grammar. Later semantic conversion follows ADR 0055.

The inspection slice below remains unchanged. Source-bound semantic conversion
now extends this frontend under [ADR 0055](0055-source-bound-native-conversion-plans.md);
its separately saved plan determines revision readiness, not inventory counts.

## Decision

Parse every chain-local Rule statement from the shared declaration catalog once.
Keep source identity, exact nodes and ordered match predicates. A rule has either
one complete immutable typed result or one value-free positioned diagnostic; no
successful prefix survives an unresolved value, unknown expression or trailing
input. Other rule results remain inspectable, but no catalog is a policy candidate.

The initial grammar supports ordered IPv4/IPv6 source/destination literal matches,
source/destination MAC matches, exact iifname/oifname/ibrname/obrname matches with
optional meta, TCP/UDP source/destination numeric ports, implicit equality, == and
!=, and nonempty anonymous address/MAC/port sets. Terminal actions are accept,
drop, return and exactly reject with icmpx type admin-prohibited. Preserve repeated
predicates and their order; never overwrite them into one policy field. Do not
infer an IP family from a transport matcher or discard contradictory predicates.

Accept strict dotted IPv4 and numeric IPv6 with no scope/mapped form. A bare host
becomes /32 or /128; explicit CIDRs require zero host bits. Numeric ports include
0..65535 in the source model; policy compatibility is a later boundary. Reject
service/host names, ranges, escaping, wildcard interfaces, references and all other
expressions explicitly. Exact interface names are 1..15 ASCII letters/digits or
_, ., :, -; other characters and quote/backslash/wildcard syntax remain unsupported.
Quoted values are accepted only for those unescaped interface names. Bounds are 128 predicates and 64 elements per set;
exceeding a bound rejects the whole rule without truncation. The original remains
unchanged even when a literal is normalized in the private typed result.

Definitions, includes, chain metadata, family/hook compatibility, named objects,
control-flow resolution, counters, logging, NAT, FIB, MSS, meters and comments still
need dedicated semantic work. No rule result establishes whole-file support,
policy validity, packet equivalence, ownership or apply authority. No filesystem,
name/service resolver, shell, nft invocation, database migration or agent operation
is introduced. Database originals remain canonical; future mapping plans belong in
the database before reviewed revision creation.

The combined viewer/import analyzer owns this catalog over the same immutable
source. Reports use schema 3, retaining schema-2 structure and adding a value-free
ruleParsing summary: availability, total/parsed counts and diagnostic code/spans.
No private AST or literal values are serialized. Structural failure makes rule
parsing unavailable, with zero counts/diagnostics. Legacy report constructors keep
schemas 1/2. Show counts and bounded diagnostic details in the existing optional
source-structure disclosure. Every review still reports conversion blocked.

## Verification

Test full consumption, repeated/negated match order, typed literals, family
preservation, exact source provenance, immutable results, literal/grammar failures,
unknown suffixes after known verdicts, value-free positions, zero partial rules,
and inclusive resource bounds. Verify viewer/report agreement and exact original
bytes over real HTTPS with Administrator/Auditor boundaries. Use synthetic sources
for screenshots and public tests. These parser checks do not establish packet
semantics; round-trip and disposable namespace acceptance remain M4 requirements.

Reference: [Netfilter nft manual](https://netfilter.org/projects/nftables/manpage.html).
