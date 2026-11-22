# ADR 0028 — Authenticated agent control protocol and TLS 1.3 pinned mTLS transport

- Status: accepted
- Date: November 21, 2026

## Decision

1. **Typed agent control contracts (`Nergal.Core.Agent`)**:
   Preserve the read-only status-only protocol (`AgentStatusCodec`, `UnixStatusServer`)
   unchanged and add a separate bounded, versioned control protocol (`AgentControlCommand`:
   `Status`, `PrepareApply`, `Confirm`, `Rollback`; `AgentControlFrame` capped at 262,144 bytes;
   `AgentControlCodec` rejecting duplicate keys, deep nesting, unknown fields, and
   non-canonical values). `PrepareApply` carries typed schema-1 or schema-2 `FilterPolicy`
   definitions; no shell text or raw nft commands cross the transport boundary.

2. **Authenticated local and remote transports (`Nergal.LocalTransport`, `Nergal.RemoteTransport`)**:
   - Extend `Nergal.LocalTransport` with `UnixControlServer` and `UnixControlClient`,
     enforcing `SO_PEERCRED` peer-UID authorization in both directions, overflow-UID
     rejection, protected parent/socket checks, and explicit inode-preserving cleanup.
   - Add `Nergal.RemoteTransport` providing `TlsControlServer` and `TlsControlClient`
     over TLS 1.3 only (`SslProtocols.Tls13`), requiring mutual client certificates and
     validating both endpoints against explicit certificate validity windows and
     constant-time SHA-256 thumbprint pins rather than ambient system trust stores.

3. **Agent execution, locking, and independent watchdog spawning (`Nergal.Agent`)**:
   Add `control-serve` (Unix peer-UID) and `tls-serve` (TLS 1.3 mTLS) commands to
   `nergal-agent`. All operations acquire `ResourceExecutionLock` around journal and
   kernel state transitions. Before mutating the kernel on `PrepareApply`, the server
   spawns an independent `nergal-agent watch` child process, awaits its durable
   `WATCHING` readiness signal (`RollbackArmed`), and then applies the validated candidate
   via `ReplaceAndVerifyAsync` so controller disconnect or crash still triggers
   autonomous timed packet rollback.

## Remaining boundary

Controller-side SQLite persistence (`Nergal.ControllerState`), configurable
`Administrator`/`Auditor` RBAC roles, append-only audit logs, and MVC/Blazor policy and
confirmed-apply workflows remain for Phases 11–13.
