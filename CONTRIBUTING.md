# Contributing

Use the .NET 10 SDK. Keep changes focused, preserve nullable annotations and
build without warnings. Public APIs need XML documentation explaining contracts,
side effects and failure behavior. Comments should explain intent rather than
repeat an implementation statement. Prefer explicit, reusable POCOs and immutable
snapshots at validation boundaries.

Add deterministic unit tests alongside every meaningful behavior change. Use
clear scenario names and arrange/act/assert structure. Test denied behavior,
unknown values and mutation boundaries. Do not add tests solely to inflate coverage.

Design for independent installations. Private deployment requirements can motivate
features, but implementations must use reusable contracts and synthetic public
examples rather than hardcoded hosts, ports, identity groups or topology. Cover
relevant independent host/gateway/dual-stack/bridge scenarios, document unsupported
semantics, and keep basic installation independent of optional site integrations.
See [product scope](docs/product-workflow.md).

Before proposing a change:

```sh
dotnet restore Nergal.slnx
dotnet format Nergal.slnx --verify-no-changes --no-restore
dotnet test Nergal.slnx --configuration Release --no-restore
```

Privileged tests are opt-in and run only in disposable namespaces. Document the
capabilities and resources they need. Never point them at a production agent.
See docs/testing.md for the distinction between unit and integration tests.

Use `Nergal.slnx`. Keep application projects at the solution root and all unit/test
fixture projects in the `Tests` solution folder; source directories retain their
existing paths.

Repository-specific Codex roles and enforced delegation limits are documented in
[the agent workflow](docs/agent-workflow.md). Run `python3 -B scripts/test-agent-config.py`
and `python3 -B scripts/verify-agent-config.py` after changing those profiles.

Before first opening this checkout in Codex (and after updating Codex), run
`python3 -B scripts/setup-agent-runtime.py`, then start a fresh runtime process (for example `codex --no-daemon -C "$PWD"`).
An existing daemon/chat does not reload startup model metadata. This creates
the ignored private startup catalog needed for enforceable direct-child-only agents;
it keeps the selected model identities and instructions unchanged.
