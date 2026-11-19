# ADR 0010: authenticate the local read-only status server

- Status: accepted
- Date: November 19, 2026

The listener's client-UID authorization is only half of the local channel. Add an
unprivileged status client that explicitly configures the expected server UID,
pathname and optional provisioned socket group. No implicit root/default authority,
automatic discovery, stale-path repair, retry or mutating command is added.

Before connecting, validate the service-owned directory/socket policy and reject
symlinks, unknown node types, shared socket links, unsafe modes and unavailable
metadata. After connection, obtain kernel SO_PEERCRED and verify the expected UID
before sending even the fixed status request. Recheck overflow identity and the
path's inode/device/owner snapshot before dispatch. Path checks are not a race-proof
sandbox against the trusted server account/root or hostile ancestor mutation;
SO_PEERCRED captures the connection creator, not future descriptor recipients.

Send the existing fixed version-1 frame and half-close writes. Bound connection,
framing, exact reply extent/EOF and JSON parsing by a single deadline. Only a full,
valid typed reply is returned. Truncation, trailing data, unknown fields/outcomes,
malformed revisions, deadline expiry and unavailable peer/path metadata fail with
stable local diagnostics and no partial resource state. Cancellation from the caller
remains cancellation. No raw remote text appears in errors.

Conformance must use actual separate mapped UIDs and independent Python servers:
prove a wrong-UID server sees no request bytes; reject hostile frames and blocked
exchanges; exercise fragmented and exact UInt64 replies; verify cancellation and
round-trip with the existing journal/native status fixture. No daemon install,
controller/browser integration or live firewall changes are part of this boundary.
