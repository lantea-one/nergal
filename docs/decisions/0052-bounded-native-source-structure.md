# ADR 0052: Bounded native source structure

Status: Accepted for structural parsing. Later semantic conversion follows ADR 0055.

The inspection slice below remains unchanged. Source-bound semantic conversion
now extends this frontend under [ADR 0055](0055-source-bound-native-conversion-plans.md);
its separately saved plan determines revision readiness, not inventory counts.

## Decision

Extend the shared viewer/import analysis with one immutable delimiter tree over
the existing lossless token document. Group braces, brackets and parentheses;
retain every other token, including unknown input, comments, continuations and
physical line endings. Group spans include their opening and closing delimiters.
Token indexes refer to the same original document; do not re-lex or normalize it.
This is a structural frontend, not a complete nftables grammar or policy mapper.

Reject unexpected, mismatched and missing delimiters and nesting beyond 64 groups.
Return one stable, value-free diagnostic at the offending closer or unmatched
opener, never a partial tree or partial inventory. Preserve the existing
`source.unbalancedBraces` diagnostic for missing/unexpected braces; other delimiter
and depth failures have distinct codes. Lexical failures retain their original
code and position. Quoted/comment contents cannot open or close groups.

The common analyzer builds this structure once and derives the masked migration
inventory only from a complete structural result. Remove the inventory's separate
brace scan so viewing, report downloads and future semantic import cannot disagree
about source structure. The exact database original remains inspectable and
downloadable on any analysis failure. There is no include lookup, name resolution,
shell, nft invocation, policy candidate, agent operation or schema migration.

Expose a value-free structural summary and source positions in report schema 2,
alongside the existing source digest and masked review. Retain the legacy
three-argument report constructor/schema 1 for existing in-process callers; the UI
and download endpoint produce schema 2 from the shared analysis. Never serialize
the private tree/document into the downloadable report. Show diagnostic positions
with the existing source review, and keep structural counts in optional detail.

## Remaining M4 boundary

Semantic parsing must classify all declarations and ordered statements, resolve
definitions/includes explicitly, and account for unsupported input before returning
typed intent. A balanced tree does not establish native syntax validity, supported
semantics, equivalence or apply authority. Persist source-bound mapping/gap plans
before revision creation. Independent round-trip and real packet acceptance remain
required. All reviews still report conversion blocked, including empty input.

## Verification

Use synthetic source to verify exact ordered token coverage, nested spans,
opaque values, unknown input, immutable collections, inclusive depth bounds,
stable diagnostic positions and no partial tree/inventory on failure. Exercise
the real HTTPS upload/view/schema-2 report/original-download workflow and its
authorization boundaries. Compare exact originals and structural completion for
the private acceptance inputs without publishing their contents. These checks
establish structural contracts, not packet-level equivalence.
