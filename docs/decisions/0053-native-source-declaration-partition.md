# ADR 0053: Native source declaration and statement partition

Status: Accepted for source-head classification. Later semantic conversion follows ADR 0055.

The inspection slice below remains unchanged. Source-bound semantic conversion
now extends this frontend under [ADR 0055](0055-source-bound-native-conversion-plans.md);
its separately saved plan determines revision readiness, not inventory counts.

## Decision

Partition the existing immutable structural tree into ordered source statements.
Retain all nodes, including separators and trivia, in exact source order. Recognize
block-header shapes for root tables and table-local chains, sets, maps, counters,
quotas and flowtables. Preserve explicit or omitted family/name token positions
without decoding names. Definitions, redefinitions, undefinitions, includes and
native commands retain their complete raw statement. Chain metadata and raw rule
statements retain order; their expressions are not yet semantically parsed.

Only table and chain bodies introduce recursively classified scopes. Other object
bodies remain intact structural groups for their own semantic parsers. Unknown
head shapes remain explicit unclassified statements with value-free positions.
Do not drop an unfamiliar declaration, rule, command or property. A recognized
head is not syntax validation or a claim that its semantics are supported.

Use newline/semicolon boundaries outside structural groups. A recognized block
header may continue across trivia/newlines immediately before its body. Recognized
block declarations terminate at that body's close, permitting adjacent blocks.
Anonymous sets/expressions in definitions or rules do not terminate statements.
Compute lookahead once per scope, preserving linear bounded work even with long
runs of trivia. Source bytes, token/depth limits and exact spans remain ADR 0050/52.

The common analyzer constructs this partition once. Derive displayed declarative
table/chain counts from contextual nodes instead of keyword scans anywhere in the
file. Add a masked `source.unclassifiedStatements` review signal at unknown heads.
Existing signal scanning remains explicitly non-exhaustive; every review still
reports conversion blocked. Keep report schema 2: its existing fields retain their
meaning, now with contextual header counts and an additional source-resolution
signal. Do not serialize the private declaration tree or unparsed names/values.

This adds no policy candidate, include/name resolution, privileged operation,
database schema or revision creation. The immutable database original stays
canonical. Future semantic parsing must consume every raw statement completely,
validate identifiers/types/expressions, preserve declaration scopes and control
flow, and persist mapping/gap plans before revision creation. Commands such as
whole-ruleset flush remain source data requiring explicit mapping, never execution.

## Verification

Test all recognized head categories and contexts, explicit/default families,
quoted names, named-object body retention, anonymous-set/rule boundaries, continued
headers, adjacent blocks, exact node coverage, immutable collections and value-free
unknown diagnostics. Verify misleading keyword sequences cannot become table/chain
counts outside their legal source contexts. Preserve structural failure handling
and blocked conversion. Use real HTTPS viewer/reports and private source-bound
acceptance without publishing values. These contracts do not establish complete
nft syntax, semantic equivalence or packet outcomes.
