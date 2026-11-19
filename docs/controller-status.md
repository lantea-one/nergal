# Read-only controller status

A local administrator can follow **View agent status** from the session page when
both local sessions and the agent status route are enabled. GET `/agent/status`
queries one explicitly configured local Unix socket. The web process receives a
classification and last-confirmed revision. It never opens the privileged journal.

| Setting | Meaning |
| --- | --- |
| `LocalSessions:Enabled` | Requires a provisioned [local HTTPS session host](local-sessions.md) |
| `AgentStatus:Enabled` | Opts into the route and session-page link |
| `AgentStatus:SocketPath` | Absolute Unix socket path, within the transport's 107-byte limit |
| `AgentStatus:ServerUserId` | Explicit expected kernel UID of the server |
| `AgentStatus:SocketGroupId` | Explicitly provisioned group granting the controller socket access |

Use a non-root controller UID distinct from the server UID. Provision the shared
directory and socket according to [the transport contract](local-status-protocol.md).
The web process authenticates the server using socket metadata and kernel peer
credentials. The listener independently authorizes the controller UID. The endpoint
accepts no client-specified target, query parameters, command or body. It permits
four concurrent queries with no queue, and each exchange has a two-second deadline.

A successful response contains schema version 1, `matched`, `drift` or `unbound`,
and the exact revision as a decimal string. HTTP 401 indicates a missing or invalid
local session. HTTP 503 with an empty body indicates that the controller could
not establish resource status, including when the agent refuses the controller.
The route never exposes local paths, raw policy text, journal fields or diagnostics.
The HTTP response is not cached. Health checks make no agent query. The agent
may be offline while the controller starts or an administrator signs in.

Tests use a disposable agent fixture and mapped service identities. No installed
agent, production observation, OIDC authorization or mutation endpoint is provided.
