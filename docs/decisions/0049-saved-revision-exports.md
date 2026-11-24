# ADR 0049: Saved revision exports

Status: Accepted for deterministic export; semantic native import remains M4 work.

## Decision

Export only explicitly selected immutable database revisions. Re-decode and compile
the complete saved bundle and require its exact candidate SHA-256 to match the
saved digest before returning either export. Reject missing, invalid, unsupported
or mismatched revisions without a partial attachment. This read-only workflow has
no agent, filesystem source, shell or kernel access and grants no apply authority.

Provide two distinct Administrator-only downloads in the policy UI:

- `nftables.conf`: exact UTF-8 bytes of the deterministic, untagged, create-only
  multi-table candidate. Its SHA-256 is the saved candidate digest. It contains
  active native semantics in reserved Nergal tables, without deletes, flushes,
  handles, host identity markers or current runtime state.
- `policy.json`: canonical complete typed intent, including disabled rules,
  descriptions, ordering and pinned reference snapshots/projection. Native text
  alone cannot retain all authored state. This is an intent snapshot, not a
  controller backup: library history, hosts, credentials, audits and receipts are
  excluded. A receiving controller must validate referenced library identities;
  a download does not authorize adopting foreign objects or ownership.

Both files derive from the saved database contents, never the current draft or
latest library version. Do not insert export-time timestamps, random identifiers,
ownership markers or provenance comments into the candidate. Repeated exports
remain byte-identical, and disabled intent can differ while the native digest is
unchanged. Neither file is evidence of applied or observed host state.

Retain separate exact original-source downloads under ADR 0038. No generated file
overwrites an original or becomes canonical database state. Arbitrary native source
conversion, include resolution, persisted mapping/gap reports and independent
semantic round trips remain explicit M4 gates. This decision introduces no import
format, SQL migration or privileged operation.

## Verification

Test all supported table scopes, static native and legacy literal references,
dormant state, exact digests, immutable revision selection and deterministic bytes.
Reject unknown/invalid policy, compilation failure, digest mismatch, invalid IDs,
missing revisions and unauthorized callers. Exercise actual HTTPS attachments and
the UI. Existing packet checks establish compiler behavior; download tests alone
cannot establish source conversion equivalence or firewall correctness.
