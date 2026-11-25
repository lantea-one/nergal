# Repository specialist agents

This repository supplies nine reusable Codex roles. They are a catalog, not nine
simultaneous workers: only the primary orchestrator delegates, with at most **four
open sub-agents** and **no grandchildren**. Stricter host/service limits still win.

| Role | Model / reasoning | Assignment |
| --- | --- | --- |
| `code_explorer` | `gpt-6-luna` / medium | Read-only code/contract/ADR mapping and targeted evidence. |
| `dotnet_engineer` | `gpt-6.2-sol` / medium | .NET 10 services, MVC/Blazor and framework-independent contracts. |
| `nftables_engineer` | `gpt-6.2-astra` / high | Native policy/compiler/import, ownership, agent safety and packet semantics. |
| `identity_security` | `gpt-6.2-astra` / high | Identity/MFA/secrets/session work and independent security review. |
| `database_engineer` | `gpt-6.2-sol` / medium | Schema, transactional invariants, audit, timestamps and SQL backend work. |
| `ui_engineer` | `gpt-6.2-sol` / medium | Guided forms, accessibility, responsive themes and observation-backed charts. |
| `browser_qa` | `gpt-6.1-terra` / medium | Rendered browser workflows, keyboard checks and authentic synthetic screenshots. |
| `verification_engineer` | `gpt-6.2-sol` / medium | Deterministic tests, failure diagnosis and assigned isolated integration checks. |
| `docs_release` | `gpt-6-luna` / medium | Accurate docs/Pages, evidence summaries and release preparation; no publishing. |

Luna handles bounded scans and documentation work. Sol handles routine engineering
and verification. Astra handles deeper firewall/identity safety reasoning. Terra
handles visual browser verification. These are explicit repository choices, using
models present in the verified installed model catalog; contributors need an
account/client that supports them. Do not silently substitute a model. Report an
unavailable model to the primary, which can make an explicit appropriate selection.

Routine roles and the fallback use medium reasoning. The nftables and identity
security profiles use high for work across trust boundaries and failure modes.
For an unusually complex assignment in a medium role, select high explicitly
when the dispatch interface supports choosing the effort for that task. Named
profiles declare their own effort and can take precedence over spawn arguments.

## Runtime controls

Before opening this trusted project in Codex, run:

```sh
python3 -B scripts/setup-agent-runtime.py
```

The helper reads the installed binary's bundled model catalog outside the project,
changes only its multi-agent backend metadata to V1, and writes a private derived
catalog under ignored `artifacts/codex-agent-runtime/` with owner-only permissions.
It does not change model identifiers, model instructions, global configuration or
provider credentials. The project uses Codex's supported `model_catalog_json`
startup setting to load it. Regenerate after updating Codex, then start a fresh
runtime process. For a verified local launch, use `codex --no-daemon -C "$PWD"`
from this repository after setup. Do not commit the derived catalog; a fresh checkout requires this setup
step before Codex can load the catalog path.

`.codex/config.toml` sets `agents.max_concurrent_threads_per_session = 4`, excluding
the primary, and `agents.max_depth = 1` for direct children only. The private catalog
selects V1 for the modern role models. Setting `features.multi_agent_v2 = false`
alone is insufficient: shipped model metadata can otherwise select V2, which
ignores `max_depth`. Do not remove the catalog or enable V2 while claiming the same
no-nesting guarantee. The installed Codex model catalog output confirmed V1 for
all role models, and its model-visible runtime preview exposed `multi_agent_v1`
rather than V2 collaboration. The read-only app-server `config/read` also confirmed
the trusted project layer, role registrations, four-child cap and depth-one limit.

Custom role files contain model, reasoning and instructions. Current Codex applies
bounded role overrides: putting `agents.enabled` or `agents.max_depth` in a child
file does not disable its tools. The root V1 depth cap provides runtime nesting
enforcement; all role instructions additionally forbid indirect delegation through
CLI sessions or new tasks/chats. No per-role sandbox or approval override is claimed:
children inherit parent permissions and managed requirements.

Project settings require a trusted checkout and apply when a session loads them.
They do not retroactively reconfigure an already running chat or model manager.
A new thread in an existing daemon does not prove that a startup-only catalog was
reloaded. Restart Desktop and verify its effective backend before relying on the
limit there; the dedicated local launch above was verified. Higher-priority
managed/session settings and host concurrency limits take precedence. Verify the
effective configuration rather than assuming the file alone establishes enforcement.

## Dispatch and ownership

The primary assigns one concrete task, role, acceptance criteria, relevant decisions,
file ownership and expected report. Choose a fresh/bounded-context named role;
full-history forks inherit parent role/model behavior and are unsuitable for selecting
a different specialist. When a session's spawn API lacks a custom-role selector,
the primary loads the role TOML and explicitly supplies its model, effort and leaf
instructions with the task, while retaining that session's enforced limits.

Use disjoint files for concurrent writers. A useful grouping is implementation,
independent security review, focused verification and documentation, but start only
workers that can make independent progress. Serialize commands that share .NET
build output or the sandbox. One worker owns each verification suite; do not waste
slots rerunning the same checks concurrently. A reviewer examines a stable diff or
commit and does not count its own implementation review as independent evidence.

Children cannot commit, push, merge, publish, deploy, manage PR/issue status, restart
the shared sandbox or change live accounts/provider trust. The primary handles
those actions under existing user authorization and the repository's safety rules.
No child may create another agent/task/chat/CLI agent to bypass the limits. Return
requests for additional help to the primary.

Every report identifies changed/reviewed files, observable findings, actual commands
and results, unverified behavior and material risks. Keep credentials, topology,
private host exports and user data out of prompts, logs, public fixtures and captures.
A generated nft candidate is not packet evidence, and a missing browser tool is not
successful visual QA. All roles retain AGENTS.md and applicable ADR requirements.

## Verification

Run:

```sh
python3 -B scripts/verify-agent-config.py
python3 -B scripts/test-agent-config.py
codex app-server --strict-config --print-startup-config
```

The deterministic validator checks role registration, unique names, explicit model
choices, required instructions, the four-child ceiling, V1 catalog selection and depth-one cap.
Its tests reject unsafe limits, backend changes, missing/unknown roles, unsupported
role settings and accidental permission/approval overrides. This validates repository
configuration contracts, not a live model's decisions or a future client's behavior.
The private startup catalog is verified separately against the installed runtime.
The CLI command also checks compatibility with the installed Codex version.

Sources: [OpenAI subagent documentation](https://learn.chatgpt.com/docs/agent-configuration/subagents),
[configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference),
and [official configuration schema](https://github.com/openai/codex/blob/main/codex-rs/core/config.schema.json).
