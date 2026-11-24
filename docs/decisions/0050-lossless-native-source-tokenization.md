# ADR 0050: Lossless native source tokenization

Status: Accepted for a bounded lexical frontend; semantic conversion remains blocked.

## Decision

Add a pure, bounded source lexer in `Nergal.Nftables` before attempting semantic
import. Retain the immutable original string and a read-only sequence of typed
spans covering every UTF-16 code unit, including BOM, whitespace, comments, line
endings, continuations, quoted text and variable/set references. Each span carries
its physical one-based line/column. Tokenization never resolves a name, decodes a
quoted value, opens an include, invokes nft, or produces policy. Unknown bare
tokens and symbols remain visible to the future parser instead of disappearing.

Follow the public [Netfilter lexical conventions](https://netfilter.org/projects/nftables/manpage.html)
for comments, physical lines and non-quoted backslash continuations. Keep quoted
chunks opaque, distinguishing double and single quotes; accepting an opaque chunk
for inventory is not a claim that native nft syntax accepts it. Variable and set
references remain distinct from keywords. Preserve original bytes through the
existing UTF-8 source snapshot; span offsets refer to the .NET string, not byte
offsets. Do not normalize BOM, CRLF, lone CR, Unicode or escaping.

Limit input to 512 KiB of strict UTF-8, 65,536 significant tokens and 131,072 total
tokens including trivia. Reject invalid encoding, NUL/unsupported control
characters, unterminated quoted chunks and capacity exhaustion with stable codes
and positions, no partial document and no copied private values in diagnostics.
Do not include source text in token/document `ToString()` output.

The viewer and importer are one workflow backed by `NativeSourceAnalyzer.Analyze`.
It tokenizes once and derives the existing value-masked inventory from that exact
document. The web source snapshot holds one immutable analysis; viewing and review
downloads use it, and subsequent semantic import must consume the same document
and diagnostics. Do not add an independent viewer parser or a separate import UI
with divergent validation. Keep the original available in this combined workflow.
The web source snapshot is immutable rather than a positional record: a `with`
copy must not replace source text while retaining a cached analysis of older text.
Its string representation also omits private names and source values.

Reuse this frontend for the existing non-exhaustive migration inventory, which
still masks private values and always reports `CanConvert = false`. Physical line
references now handle CRLF/CR and continuations consistently. Existing brace
balance checks remain inventory checks, not native syntax validation. This adds
no database schema or conversion authority; immutable database source bytes remain
the rolling source of truth and review output remains derived.

## Next boundary

The semantic parser must consume and classify every significant token, retain
source provenance for each declaration/rule, account for unknowns explicitly and
resolve uploaded include dependencies with bounded, explicit mappings. No server
filesystem/include search, ambient name/service resolution or partial candidate
is authorized. Persist mappings and gaps before creating reviewed revisions;
independent round-trip and packet acceptance remains required by M4.

## Verification

Synthetic tests reconstruct exact source from all token spans, check physical
positions, comments/quotes/references/continuations, arbitrary unknown tokens,
immutable collections, stable value-free failures and independent byte/token
bounds. Reviewer regressions ensure masked values cannot become keywords, line
references remain accurate and every review remains blocked for conversion.
These tests establish lexical contracts only, not native syntax or packet behavior.

[ADR 0052](0052-bounded-native-source-structure.md) subsequently adds the shared
bounded delimiter tree and schema-2 structural summary, replacing the inventory's
separate brace scan. The lexer remains lossless and the conversion boundary remains
blocked pending semantic mapping.
