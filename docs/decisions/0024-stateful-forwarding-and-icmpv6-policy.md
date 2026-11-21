# ADR 0024 — Stateful forwarding, output filtering, interface matchers, and ICMPv6 policy

- Status: accepted
- Date: November 21, 2026

## Decision

1. **Preserve Schema 1 and introduce Policy Schema 2 (`Nergal.Core.Policy`)**:
   Keep `FilterPolicy` schema version `1` unchanged for input-only stateless policies and
   existing receipt compatibility. Introduce schema version `2` supporting explicit base
   chains (`FilterChainKind.Input`, `Forward`, `Output`) with per-chain default verdicts
   (`InputDefaultVerdict`, `ForwardDefaultVerdict`, `OutputDefaultVerdict`), validated
   interface names (`InputInterface`, `OutputInterface`), connection-tracking state masks
   (`ConnectionStateFlags`: `None`, `New`, `Established`, `Related`, `Invalid`), and
   validated ICMP/ICMPv6 type matchers (`IcmpType`).

2. **Fail-closed interface, chain-direction, state, and ICMP validation**:
   - Interface names accept only 1–15 ASCII characters (`[A-Za-z0-9._-]`, leading
     alphanumeric character), rejecting whitespace, slashes, quotes, wildcards, and
     native grammar delimiters (`interface.invalid`).
   - `InputInterface` is valid only on `Input` and `Forward` chains; `OutputInterface`
     is valid only on `Forward` and `Output` chains (`interface.chainMismatch`).
   - Schema 1 policies reject schema-2-only fields rather than silently ignoring them.
   - `ConnectionStates` rejects undefined flag bits (`connectionState.unknown`).
   - `IcmpType` requires `FilterProtocol.Icmp` or `FilterProtocol.IcmpV6`
     (`icmpType.requiresIcmp`) and restricts values to an explicit canonical allowlist
     for each family (`echo-request`, `echo-reply`, `destination-unreachable`,
     `time-exceeded` for IPv4; `echo-request`, `echo-reply`,
     `destination-unreachable`, `packet-too-big`, `time-exceeded`, `parameter-problem`,
     `nd-router-solicit`, `nd-router-advert`, `nd-neighbor-solicit`,
     `nd-neighbor-advert` for IPv6), rejecting unknown types (`icmpType.unsupported`).

3. **Deterministic compilation and full schema-2 observation (`Nergal.Nftables`)**:
   - `NftFilterCompiler` compiles schema-2 policies into create-only `inet nergal_filter`
     tables containing all three base chains (`input`, `forward`, `output`) in canonical
     order, with rules grouped in `(input, forward, output)` chain order while preserving
     relative rule order within each chain.
   - `NftTableObservation` reconstructs both single-chain schema-1 tables (retaining
     `nergal-observation-v1`/`v2`/`v3` digests) and three-chain schema-2 tables
     (`nergal-observation-v4` digest), failing closed on unknown chains, duplicate keys,
     non-canonical connection-state order, or unvalidated expressions.

## Remaining boundary

Per-source rate limiting (`PerSourceRateLimiting`), dual-stack DNAT/SNAT, bridge
filtering, multi-table atomic commits, and remote/controller transport remain for
Phases 7–13.
