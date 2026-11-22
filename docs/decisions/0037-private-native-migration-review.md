# ADR 0037: Private native migration review

Status: Accepted for read-only review; automatic conversion remains unimplemented.

## Decision

Keep exact private source snapshots and bind each migration review to its source
SHA-256. Add a bounded, deterministic lexical inventory in the unprivileged native
library and expose it to administrators alongside the source and as a downloadable
report. No source is compiled, executed, saved as a managed revision, or sent to
an agent by this workflow.

Inventory signals identify typed constructs requiring explicit mapping, known
contract gaps, and source resolution work. They are navigation aids, not a native
parser, capability proof, exhaustive gap analysis, or equivalence certification.
Quoted strings, comments and variable references cannot masquerade as keywords.
Malformed or oversized input yields an incomplete inventory and a stable diagnostic.
Every report remains blocked for conversion, including empty or unfamiliar input.

The private inputs contain more than the seven router constructs: named maps,
connection tracking bypass and counter statements require explicit preservation
work. Counting familiar keywords must never imply that the remaining rules are
safe to drop. Additional tables require ownership and hook/order mapping rather
than adopting their names. Source includes and definitions need explicit resolution.
Public tests use only synthetic snippets; private reviews and reports stay private.

## Next acceptance boundary

A converter must account for every declaration and rule, preserve ordering and
control flow, reject unsupported semantics without returning a partial candidate,
and produce a source-bound mapping report. Compare complete native observations
and real packet outcomes in disposable namespaces before describing a converted
server as equivalent. This inventory intentionally grants no conversion authority.
