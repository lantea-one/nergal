# Deployment & Packaging

nergal is designed for Linux hosts running `systemd` and `nftables` with strict privilege separation between `nergal-agent` and `nergal-web`.

## Systemd Units & Provisioning

Repository artifacts under `deploy/systemd/`:
- `nergal-agent.service`: Runs `/opt/nergal/agent/nergal-agent.dll` under `User=nergal-agent` with `CAP_NET_ADMIN` only (no full root shell, private tmp, strict filesystem protections).
- `nergal-web.service`: Runs `/opt/nergal/web/Nergal.Web.dll` as unprivileged user `nergal-web` with zero capabilities (`CapabilityBoundingSet=`).
- `nergal.sysusers` & `nergal.tmpfiles`: Declaratively create the `nergal-web`, `nergal-agent`, and `nergal-ctl` accounts/groups plus private `0700` state directories (`/var/lib/nergal/agent`, `/var/lib/nergal/web`) and `/run/nergal` (`2710`).

## Initial Host Setup

1. **Initialize offline local administrator & controller state**:
   ```bash
   nergal-admin account init /var/lib/nergal/web/accounts
   nergal-admin account provision /var/lib/nergal/web/accounts admin --role administrator
   nergal-admin controller init /var/lib/nergal/web/state
   ```
2. **Enroll the host agent** (creates owned `inet nergal_filter` and binds `journal.db`):
   ```bash
   nergal-agent enroll /var/lib/nergal/agent
   ```
3. **Configure TLS certificates**:
   - Kestrel HTTPS certificate/key for `Nergal.Web`
   - Pinned TLS 1.3 mTLS server/client certificates (`0600` private keys) for remote `nergal-agent tls-serve` hosts, or Unix `control-serve` for co-located hosts.

## Release Packages

Release builds produce reproducible Linux `x64` artifacts via `scripts/package-release.sh`:
- `nergal_<version>_linux-x64.tar.gz`: Self-contained layout installing binaries under `/opt/nergal/{agent,web,admin}`, CLI wrappers in `/usr/local/sbin/`, and systemd/sysusers/tmpfiles definitions.
- `nergal_<version>_amd64.deb`: Debian/Ubuntu package built with `dpkg-deb --root-owner-group` installing `/opt/nergal/`, `/usr/local/sbin/` wrappers, and `systemd`/`sysusers.d`/`tmpfiles.d` units.
- `SHA256SUMS`: Cryptographic checksums for all release archives.

## Unreleased router and settings work

See [Router Migration & Local Sandbox](router-migration-and-sandbox.md) for the
current support matrix, supported apply scope and recovery limits, saved-settings/runtime distinction,
private source inspection, container isolation, verification limits, and screenshots.
This local development work is not a published release.

## Shared organization CI runners

Build verification and Pages publication use the shared organization CI pool,
currently pinned to `asgard-ci`. `heimdall-ci` is also an approved shared runner.
Labels must end in `-ci`, and registration must be organization-owned without a
repository binding. A suffix alone does not prove shared scope. Private
infrastructure runners and generic label fallbacks are prohibited.

`vidar-ci` may run small, short tasks such as documentation validation/publication
when available in the shared organization pool. Never assign it the full .NET
build, integration suite or release packaging. The offline runner-policy check
guards reviewed labels and prevents that heavy-workflow assignment; operators
must verify registration scope separately when maintaining the pool.

Forks must select their own verified shared organization CI runners and update the
reviewed workflow policy. Changes to labels require review; arbitrary repository
variable values cannot redirect these workflows to infrastructure. The existing
Pages token and publication destination are unchanged. Previously queued runs
retain their original selections and must be cancelled if disallowed.
