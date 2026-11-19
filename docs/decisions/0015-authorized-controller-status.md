# ADR 0015 — Authorized read-only controller status

Expose a single opt-in GET endpoint for a configured local resource. Require a
valid local administrator application session over direct HTTPS. Authorize the
request before opening any socket. Accept no request-supplied path, identity,
target or command. Keep health independent of the agent.

Use the existing peer-authenticated Unix status client. The controller uses an
unprivileged UID distinct from the configured server UID and traverses a shared
socket directory using an explicitly provisioned group. Startup requires the
configuration but may proceed when the agent is down. Queries use the client's
bounded two-second exchange, a fresh connection and no retries.

Return schema-1 matched, drift or unbound replies with the exact decimal revision.
For unavailable, denied, invalid or incomplete replies return HTTP 503 with no
metadata. A transport failure grants no authority to inspect the journal or retry
through another backend. Never expose raw diagnostics, policy or endpoint paths.
No service is installed, enrolled or started by the web controller.
