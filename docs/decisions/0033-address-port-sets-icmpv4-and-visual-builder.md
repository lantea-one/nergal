# 0033: Inline Address/Port Sets, IPv4 ICMPv4 Types, and Structured Visual Rule Builder

- Status: Accepted
- Date: 2026-11-21

## Context

Schema-2 `FilterPolicy` rules previously matched only a single `Source` CIDR, a
single `Destination` CIDR, and a single `DestinationPort` integer, and the web
policy editor (`/manage/policies`) exposed only raw JSON authoring. Operators
managing dual-stack hosts commonly group multiple source/destination CIDRs or
service ports (`tcp dport { 80, 443 }`) in a single rule, need allowlisted IPv4
ICMP `parameter-problem` alongside `echo-request`, `echo-reply`,
`destination-unreachable`, and `time-exceeded`, and benefit from a structured
MVC + Blazor visual rule builder that produces canonical typed bundles without
hand-editing JSON.

## Decision

1. **Inline anonymous sets on schema-2 `FilterRule`**:
   - Add optional `SourcePrefixes`, `DestinationPrefixes`, and `DestinationPorts`
     properties to `FilterRule` (schema 2 only; rejected on schema 1 with
     `set.requiresSchema2`).
   - Each set property is mutually exclusive with its corresponding scalar
     property (`set.conflictsWithScalar`).
   - Sets require `2..64` distinct valid elements (`set.minElements`,
     `set.tooManyElements`, `set.duplicate`, `set.overlappingOrAdjacent`,
     `network.familyMismatch`, `port.outOfRange`, `port.requiresTransport`).
     Requiring at least two disjoint, non-adjacent elements guarantees nftables
     preserves each prefix in `nft --terse --json list table` without folding a
     singleton set into a scalar or merging adjacent prefixes into a `range`,
     preserving deterministic compiler/observation round-trips.
   - `NftFilterCompiler` emits canonical sorted anonymous sets (`ip/ip6 saddr { ... }`,
     `ip/ip6 daddr { ... }`, `tcp/udp dport { ... }`) and `NftTableObservation`
     reconstructs and canonically sorts them into `FilterRule` and `StateDigest`.
2. **Allowlisted IPv4 ICMPv4 types**:
   - Extend `FilterIcmpTypes.Ipv4Types` with `parameter-problem`, completing the
     allowlisted diagnostic set (`echo-request`, `echo-reply`,
     `destination-unreachable`, `time-exceeded`, `parameter-problem`).
3. **Structured visual rule builder and Blazor summary**:
   - Render a read-only `PolicyBundleSummary.razor` Blazor component inside
     `/manage/policies` displaying structured Filter, NAT, and Bridge rule tables.
   - Add CSRF-protected, Administrator-only MVC actions (`/manage/policies/rules/add`,
     `/manage/policies/rules/remove`, `/manage/policies/rules/move`) backed by
     pure POCO transformations in `PolicyAuthoringService` that produce canonical
     JSON drafts for live preview, diffing, and explicit revision save.
   - Auditors can inspect the visual summary and preview diffs, and receive `403`
     on all rule-builder mutation endpoints.

## Consequences

- Inline sets remain bounded (`<= 64` elements), canonical, and fully verifiable
  through `NftTableObservation` and `ApplyJournal` without new SQLite schema
  versions.
- The web controller never touches the kernel or spawns a shell during visual
  rule authoring; all edits remain draft transformations until explicitly saved
  and dispatched through two-phase confirmed apply.
