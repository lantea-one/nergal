# ADR 0018 — Observe ordered family-wide input rules

Recognize the compiler's explicit IPv4/IPv6 family match followed by a terminal
accept/drop verdict. Require the whole rule object, the exact two expressions,
the expected table and chain, and a positive unique rule handle. A different
match, extra expression, comment, counter or unknown object invalidates the
whole observation. This slice requires no inference about implicit dependencies
that nft can elide when listing address, protocol or port expressions.

Preserve the original empty-chain digest byte for byte. For nonempty chains,
fingerprint every rule handle, family and verdict in evaluation order. Expose
the typed observed policy for exact compiler reconstruction during trusted receipt
binding. A matching fingerprint alone cannot bind a different protected baseline.
These changes provide read-only evidence. They add no enrollment authority or
kernel mutation to the controller or journal.
