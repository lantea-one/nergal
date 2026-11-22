# Deployment & Packaging

nergal is designed for Linux hosts running `systemd` and `nftables` with strict privilege separation between `nergal-agent` and `nergal-web`.

## Systemd Units & Provisioning

Repository artifacts under `deploy/systemd/`:
- `nergal-agent.service`: Runs `/usr/libexec/nergal/agent/nergal-agent` with `CAP_NET_ADMIN` only (no full root shell, private tmp, strict filesystem protections).
- `nergal-web.service`: Runs `/usr/libexec/nergal/web/Nergal.Web` as unprivileged user `nergal-web` with zero capabilities (`CapabilityBoundingSet=`).
- `nergal.sysusers` & `nergal.tmpfiles`: Declaratively create the `nergal-web` / `nergal-agent` service accounts, socket group, and `0700` state directories (`/var/lib/nergal/agent`, `/var/lib/nergal/web`, `/run/nergal`).

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
- `nergal_<version>_linux-x64.tar.gz`: Self-contained layout with `nergal-agent`, `nergal-web`, `nergal-admin`, and `deploy/systemd/` units.
- `nergal_<version>_amd64.deb`: Debian/Ubuntu package built with `dpkg-deb --root-owner-group` installing binaries to `/usr/libexec/nergal/`, wrapper scripts in `/usr/sbin/`, and systemd/sysusers/tmpfiles definitions.
- `SHA256SUMS`: Cryptographic checksums for all release archives.
