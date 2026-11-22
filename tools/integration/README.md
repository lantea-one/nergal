# Disposable mapped-identity integration runner

After the pinned SDK Release build, run:

```sh
bash tools/integration/check-mapped-identities.sh
```

This runs the existing, unmodified separate-UID isolation and local-status/control/
HTTPS apply fixtures. It creates subordinate-ID ranges only inside a disposable
container image. Host accounts, groups, subordinate-ID files and security settings
are not changed. Each fixture additionally creates fresh user/network namespaces
and verifies their identities before any native work.

The container has no external network, published ports, writable host mount, real
server export, host bus or Docker socket. It reads only public source/test build
outputs and the pinned SDK; its writable temporary data is discarded. `SYS_ADMIN`
and a container-only relaxed seccomp profile are required for nested namespaces.
This is privileged test tooling, never a production controller configuration.
The ordinary development web stack remains unprivileged and is unaffected.

The base image/packages are development tooling dependencies; the Docker build
requires package network access. Execution itself uses `--network none`. Keep
these tests separate from deterministic unit tests and report actual outcomes.
