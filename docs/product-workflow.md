# UI-first product workflow

The product must support ordinary administration entirely through the UI, with
progressive detail for different experience levels. JSON remains an optional
expert representation, not a prerequisite for supported policy authoring.

## Implementation sequence

1. Completed: auxiliary/extended bridge ownership, complete observation, atomic
   confirmed apply and independent rollback under ADR 0036.
2. Completed: dedicated auxiliary packet/recovery acceptance and a working
   mapped-UID runner. Additional real-server combinations remain part of migration
   gap assessment; synthetic conformance is not production equivalence.
3. In progress: source-bound lexical reviews now expose migration topics and
   downloadable reports without executing sources or claiming conversion. Convert
   private source configurations explicitly, preserving all semantics;
   keep an auditable migration report and mark unsupported items clearly.
4. Complete structured authoring for every supported construct, with plain-language
   intent, contextual help, precise validation, complete review, and confirmed apply.
5. Improve navigation, dashboard charts, user profiles, and setup workflows with
   accessibility and light/dark consistency. Keep documentation and screenshots current.

## Interaction requirements

- Guided tasks explain source, destination, service, interfaces, identity restrictions,
  ordering, and expected effects without requiring nftables syntax knowledge.
- Expert controls expose the same full typed contract without a lossy alternate model.
- Editing JSON/code uses a real locally served code editor with highlighting,
  indentation, line numbers, keyboard support, and syntax diagnostics. Server-side
  typed validation remains authoritative. No CDN or telemetry is required.
- Charts use observed data and state their scope, collection time, and missing-data
  conditions. Do not invent traffic metrics from configuration counts or health probes.
- Profiles separate editable display/preferences from immutable identity and authorized
  role assignment. A user cannot promote their own role. Account changes need explicit
  authorization, CSRF, audit, session revocation, and last-administrator protection.
- Everyday operations stay in the UI. Initial privileged host trust/bootstrap remains
  an explicit local operator boundary, represented by a guided enrollment workflow;
  the browser never gains a shell or direct privileged host capability.

This is an active implementation plan, not a claim that all listed workflows exist.

## Code editor delivery

Policy JSON now uses a local CodeMirror 6 bundle with syntax highlighting, line
numbers, folding, undo/redo, search, bracket matching and JSON syntax diagnostics.
Theme colors follow the console live. Tab leaves the editor; **Indent lines**
uses parser-aware indentation without rewriting or dropping duplicate keys.
Invalid JSON remains visible after preview, with the server's validation result.
The strict server contract, role and CSRF checks remain authoritative.

See [asset maintenance](../tools/web-assets/README.md) for locked dependency and
reproducible bundle/license verification. JavaScript-disabled browsers retain the
textarea and the same server validation. Native candidate and source views are
read-only; no raw nft transaction can be submitted from this editor.

## Verification runner milestone

The separate mapped-UID fixture environment is now reproducible through
`tools/integration/check-mapped-identities.sh`. Its full isolation and status/
control/HTTPS suite passes using disposable container-local accounts and nested
namespaces. No host account/mapping changes or fixture guard relaxations are
required. The auxiliary/extended bridge packet and watchdog acceptance milestone now also
passes under ADR 0036. The next milestone is explicit private server conversion,
followed by complete structured authoring and the broader UX/profile/chart work.
