# ADR 0066 — Containerized native host agent

Status: accepted

## Decision

Ship separate Linux controller and agent images. The controller remains a
zero-capability process and reaches host agents over the pinned mutual TLS
protocol in [ADR 0028](0028-authenticated-agent-control-protocol.md). An agent
container on a managed Linux host joins that host's network namespace so the
existing native ownership, validation and receipt contracts apply to the
host's nftables tables.

The agent image starts through a fixed launcher. The launcher switches to
UID/GID 1654, clears supplementary groups and drops all bootstrap capabilities
except `CAP_NET_ADMIN` before starting application code. The container uses a
read-only root and distinct journal and TLS mounts. The operator invokes local
enrollment and boot reconciliation explicitly. The same journal must stay with
the same managed host across container replacements.

A native watchdog is a separate process. A container PID namespace ends when
its PID 1 exits, so the image uses a small supervisor to keep the namespace
alive until the listener and any watchdog descendants have exited. During
graceful shutdown the supervisor signals the listener and lets the watchdog
reach its result. The Compose configuration allows the maximum confirmation
window plus rollback time. Forced container termination can interrupt the
watchdog and requires the existing agent recovery procedure.

The agent receives access to its host network namespace and its own protected
directories. The CI build uses the separate rootless organization engine.
See the [operator instructions](../deployment.md#containerized-agent) for both
installation roles and the release workflow.
