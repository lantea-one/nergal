# Agent instructions for nergal

Read README.md, docs/architecture.md, docs/testing.md and the decision records first.
Use .NET 10, ASP.NET Core MVC, Blazor and reusable POCOs. Keep domain types free
of ASP.NET, database and host dependencies. Prefer small, explicit components.

- Check git status before editing and preserve concurrent work.
- Keep application code, tests and documentation equally clear and maintainable.
  Document public contracts and the reason for security-sensitive behavior.
- Add meaningful unit tests with each behavior change; test failures and denied
  operations, not only successful cases. Do not replace packet-level checks with mocks.
- Run dotnet test and the relevant integration checks. Report unverified behavior.
- Native nftables on Linux is the sole firewall target. Do not add other firewall
  adapters or Windows-native deployment support. Never silently translate away unsupported semantics.
- Never modify production firewalls while developing or testing this repository.
  Integration fixtures use disposable network namespaces and synthetic addresses.
- Never flush a host ruleset or change foreign tables. Explicit ownership,
  atomic candidate validation and local timed rollback are design requirements.
- Never expose privileged host operations directly to the browser process or
  pass untrusted policy data through a shell. No production Docker socket mounts.
- Keep credentials, real topology, user data and host exports out of this public
  repository, logs and test fixtures. Do not copy FWCloud code or branding.
- Use temporary Git identity settings. Public publishing and live operations
  are separate actions and require the applicable authorization.
- CI jobs must use shared organization runners with dedicated labels ending in
  `-ci`, never private infrastructure runners or generic label fallbacks. Verify
  organization scope as well as the label. `vidar-ci` is for small, short-running
  tasks only; never use it for the full build, integration suite or packaging.

## Scope

These instructions apply repository-wide to all source, tests, documentation,
workflows and tooling. Keep this file tracked and ship it with the repository.

## Working sequence

1. Read this file, README.md, docs/architecture.md, docs/testing.md and the ADRs.
   Check for additional AGENTS.md files in the directories you will edit.
2. Inspect Git status and current main. Preserve concurrent changes and use a
   narrow `codex/` branch for new development. Do not claim local work is published.
3. State the behavior and security boundary being added. Keep changes reviewable;
   document design decisions before adding privileged behavior.
4. Use the SDK pinned in global.json. Restore with --locked-mode, build Release,
   verify formatting, run scripts/test-unit.sh and scripts/smoke-web.sh.
5. Update affected documentation and report actual checks, limitations and the
   next milestone. A passing unit suite is not proof of packet-level correctness.

## Product direction

The repository is currently an early foundation, not a working firewall manager.
Build a fully functioning, general-purpose FOSS application with optional multi-host
and OIDC support. The initial private deployment is an acceptance target, not the
product's scope: implement reusable contracts and test independent synthetic
network layouts. Keep all site-specific defaults and assumptions out of the core.
Use MVC, Blazor and framework-independent POCOs; keep browser, policy, compiler
and privileged-agent boundaries explicit. Do not require AD, Forgejo, WireGuard
or any particular network topology for a basic installation.

Provide UI workflows for reusable typed sets/IP lists and nftables.conf import/export.
Provide inline per-rule enable/disable controls that preserve rule settings/order,
and contextual accessible form hints. Rule state changes follow revision review
and confirmed apply. Preserve named-object references and immutable revision contents; report unsupported
import semantics explicitly. Source inspection alone is not full import/conversion.

Use the database as the rolling source of truth for application-managed state,
including reusable objects, imported content, settings and revision/audit history.
Store timestamps in UTC and display them in the viewer's local timezone, with an
explicit timezone indication. Do not use the server timezone for browser presentation.
Generated files are derived artifacts. Keep desired and observed/applied state
distinct, and preserve independently protected agent receipts/rollback decisions.
Defer migrations for additional SQL backends until the logical schema stabilizes;
then implement and verify versioned migrations on each supported engine.

Develop independently from public specifications. No FWCloud code or assets may
be copied. Do not advertise formal clean-room assurance without supporting evidence.
Production deployment, account/group changes, merges and firewall applies are
separate operations: verify current user authorization before carrying them out.

## Application source

Keep shared contracts small, explicit, typed and
independent of framework or host details. Document public APIs, invariants,
validation failures and security-sensitive choices with XML documentation.

- Core types must not depend on ASP.NET, a database, identity provider or shell.
- Validate unsupported and unknown input explicitly; never silently weaken policy.
- Keep MVC controllers and Blazor components thin. Put reusable behavior in
  appropriate services, with dependency injection at the application boundary.
- Never let request data become a shell command or an unrestricted nft transaction.
- Privileged operations require explicit resource ownership, authorization,
  complete candidate validation, atomicity and independent local timed rollback.
- OIDC must validate issuer, audience, redirect URIs and claims; application roles
  are configurable. Add durable protected Data Protection keys before real sessions.
- Avoid real host names, addresses, user data and credentials in defaults/examples.
- Add meaningful tests and update architecture/ADRs when introducing a boundary.

## Tests

Read docs/testing.md. Tests have the same requirements
for clarity, documentation, reuse and efficiency as application code.

- Unit tests are deterministic and independent of root, Docker, network access,
  live credentials and production services.
- Test observable contracts and failure/denial cases. Avoid assertions that merely
  mirror implementation, excessive mocks, timing sleeps and percentage-driven tests.
- Explain the safety property under test. Use reusable fixtures where they clarify
  intent; keep each test focused and failures diagnosable.
- Test caller mutation, invalid/unknown input and stable diagnostics for policy types.
- Kernel integration tests use disposable namespaces and synthetic addresses only.
  Never mount a production socket, host system bus or firewall configuration.
- Test real packet outcomes for dual-stack/NAT and rollback behavior; generated
  text alone cannot establish correct routing or access control.
- Run scripts/test-unit.sh after a Release build. Require usable coverage artifacts,
  but do not equate coverage with security or complete behavioral verification.

## Specialized sub-agents

Use the repository profiles in `.codex/agents/` for independent specialist work
when delegation improves the task. See `docs/agent-workflow.md` for roles/models.
Only the primary agent orchestrates. Keep at most four sub-agents open at once,
obey any stricter host limit, and close completed agents before filling a freed
slot. Sub-agents are leaves: never spawn other agents, tasks, chats, or parallel
Codex/CLI sessions, including as a workaround for the depth limit.

Before a fresh Codex runtime, run `python3 -B scripts/setup-agent-runtime.py`.
The trusted project config loads the private derived startup model catalog to
select V1, with a four-child concurrency ceiling and `max_depth = 1`.
The V2 feature flag alone cannot force V1 when model metadata selects V2. Do not switch to V2 without an equally enforced no-nesting
control: V2 ignores that depth setting. Existing sessions/daemons retain their loaded runtime settings; configuration
validation does not hot-reload this chat. Use a fresh local runtime (for example
`codex --no-daemon -C "$PWD"`) and verify the backend before relying on depth limits.

Select the named custom role with fresh/bounded context. If the available spawn
API has no custom-role selector, read its TOML and explicitly pass its model,
reasoning effort and leaf instructions in a fresh-context task. Supply the actual
assignment, file ownership, relevant decisions and required output; do not rely on
an inherited full-history fork to select a different specialist model.

The primary owns integration, the shared sandbox, commits/pushes/merges, issue
status and publication within the user's authorization. Assign disjoint files to
writers. Serialize restore/build/test/publish operations that share outputs, and
assign one verification owner for each suite. Reviews use a stable commit/diff;
a worker's self-review is not independent review. Every child reports concrete
changes/findings, actual checks, unverified behavior and risks. Never delegate
production firewall operations or expose private inputs in task prompts/results.
