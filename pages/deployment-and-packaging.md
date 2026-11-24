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

## Documentation publishing runner

The Pages workflow uses repository variable `PAGES_RUNNER_LABEL` when set,
otherwise `CI_RUNNER_LABEL` (the normal verification runner setting), otherwise
`ubuntu-latest`. Configure an available, trusted runner with network access to the
publication service. A separate Pages runner is optional; no site-specific runner
label is required by the repository. Workflow validation and the existing Pages
token/publication destination are unchanged. A previously queued run retains its
original runner selection; new runs use the updated workflow after merge.
