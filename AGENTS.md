# Agent instructions

Read README.md, docs/architecture.md, docs/testing.md and the decision records first.
Use .NET 10, ASP.NET Core MVC, Blazor and reusable POCOs. Keep domain types free
of ASP.NET, database and host dependencies. Prefer small, explicit components.

- Check git status before editing and preserve concurrent work.
- Keep application code, tests and documentation equally clear and maintainable.
  Document public contracts and the reason for security-sensitive behavior.
- Add meaningful unit tests with each behavior change; test failures and denied
  operations, not only successful cases. Do not replace packet-level checks with mocks.
- Run dotnet test and the relevant integration checks. Report unverified behavior.
- Native nftables is the first backend. Do not add a partial firewalld adapter or
  silently translate away unsupported semantics.
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
