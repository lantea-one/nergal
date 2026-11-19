# ADR 0017 — Offline local account provisioning

Expose separate initialize and provision commands in a standalone executable
that depends only on the existing Identity infrastructure. Ownership of the
explicit private directory bounds local access. The web process has no anonymous
bootstrap endpoint. Provisioning uses the same serialized singleton constraints
and password validation as the library and creates no Linux users or groups.

Use a terminal prompt with confirmation or an explicitly selected redirected
UTF-8 input stream. Arguments and environment variables never carry passwords.
The terminal must have echo disabled before the prompt becomes visible. Reading
directly from the file descriptor avoids the console reader's separate interactive
echo/editing behavior. A pseudo-terminal test checks the externally visible
result, including on interruption. No reset, replacement, migration or production
deployment is part of this command.
