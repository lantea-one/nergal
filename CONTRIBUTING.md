# Contributing

Use the .NET 10 SDK. Keep changes focused, preserve nullable annotations and
build without warnings. Public APIs need XML documentation explaining contracts,
side effects and failure behavior. Comments should explain intent rather than
repeat an implementation statement. Prefer explicit, reusable POCOs and immutable
snapshots at validation boundaries.

Add deterministic unit tests alongside every meaningful behavior change. Use
clear scenario names and arrange/act/assert structure. Test denied behavior,
unknown values and mutation boundaries. Do not add tests solely to inflate coverage.

Before proposing a change:

```sh
dotnet restore Nergal.sln
dotnet format Nergal.sln --verify-no-changes --no-restore
dotnet test Nergal.sln --configuration Release --no-restore
```

Privileged tests are opt-in and run only in disposable namespaces. Document the
capabilities and resources they need. Never point them at a production agent.
See docs/testing.md for the distinction between unit and integration tests.
