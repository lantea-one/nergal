# Deploying nergal

This guide covers single-host and controller-plus-agent production layouts using the
hardened systemd service templates under `deploy/systemd/`.

## Privilege and trust boundaries

- **`nergal-agent`** owns `/var/lib/nergal/agent` (`0700`, `nergal-agent:nergal-agent`),
  its `nft` netlink privilege (`CAP_NET_ADMIN` only, non-root `User=nergal-agent`), and
  its watchdog/journal state. It never runs an HTTP server, browser session, or database
  for web users.
- **`nergal-web`** runs unprivileged (`User=nergal-web`) with **no** `CAP_NET_ADMIN`,
  **no** `AF_NETLINK`, and **no** Docker socket access. When co-located with the agent, it
  communicates exclusively over `/run/nergal/control.sock` via `SupplementaryGroups=nergal-ctl`,
  verified on every connection via Linux `SO_PEERCRED` (`ALLOWED_PEER_UID`). Remote hosts
  use pinned TLS 1.3 mutual authentication (`tls-serve`) with owner-only `0600` private keys.
- **No external infrastructure required**: basic installations use local account SQLite
  credentials (`LocalSessions`) and do not require Active Directory, OIDC, Forgejo, or WireGuard.

## Dedicated accounts and directories

Create dedicated service identities and mode-checked private directories before initializing state:

```sh
sudo groupadd --system nergal-ctl
sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin --gid nergal-ctl nergal-agent
sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin nergal-web
sudo usermod --append --groups nergal-ctl nergal-web

sudo install -d -o nergal-agent -g nergal-agent -m 0700 /var/lib/nergal/agent
sudo install -d -o nergal-agent -g nergal-ctl -m 2710 /run/nergal
sudo install -d -o nergal-web -g nergal-web -m 0700 \
  /var/lib/nergal/web /var/lib/nergal/web/accounts /var/lib/nergal/web/controller /var/lib/nergal/web/keys
sudo install -d -o root -g root -m 0755 /etc/nergal/agent /etc/nergal/web /opt/nergal/agent /opt/nergal/web /opt/nergal/admin
```

For `/run/nergal` across reboots, install the repository's declarative `sysusers.d`
and `tmpfiles.d` templates (`deploy/systemd/nergal.sysusers` and
`deploy/systemd/nergal.tmpfiles`):

```sh
sudo install -m 0644 deploy/systemd/nergal.sysusers /usr/lib/sysusers.d/nergal.conf
sudo install -m 0644 deploy/systemd/nergal.tmpfiles /usr/lib/tmpfiles.d/nergal.conf
sudo systemd-sysusers /usr/lib/sysusers.d/nergal.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/nergal.conf
```

## Release packages

Reproducible Linux release archives (`.tar.gz`, `.deb` when `dpkg-deb` is available,
and `SHA256SUMS`) can be built and verified from source with:

```sh
bash scripts/package-release.sh --verify
```

## Offline initialization

Publish the release binaries cleanly for the host runtime (`.NET 10`):

```sh
dotnet publish src/Nergal.Agent/Nergal.Agent.csproj -c Release -o /opt/nergal/agent
dotnet publish src/Nergal.Admin/Nergal.Admin.csproj -c Release -o /opt/nergal/admin
dotnet publish src/Nergal.Web/Nergal.Web.csproj -c Release -o /opt/nergal/web
```

1. **Enroll the host agent** (backs up/binds an empty `inet nergal_filter` baseline without modifying unrelated tables):

   ```sh
   sudo -u nergal-agent dotnet /opt/nergal/agent/nergal-agent.dll enroll /var/lib/nergal/agent
   ```

2. **Initialize controller state and local administrator account** (interactive password prompt without terminal echo):

   ```sh
   sudo -u nergal-web dotnet /opt/nergal/admin/nergal-admin.dll account init /var/lib/nergal/web/accounts
   sudo -u nergal-web dotnet /opt/nergal/admin/nergal-admin.dll account provision /var/lib/nergal/web/accounts admin
   sudo -u nergal-web dotnet /opt/nergal/admin/nergal-admin.dll controller init /var/lib/nergal/web/controller
   ```

   Create an owner-only (`0600`) wrapping PKCS#12 file `/etc/nergal/web/wrapping.pfx` for persistent Data Protection keys and Kestrel TLS certificates owned by `nergal-web`.

3. **Configure `/etc/nergal/web/env`** (`0600`, owned by `nergal-web`):

   ```ini
   ASPNETCORE_URLS=https://127.0.0.1:8443
   Kestrel__Certificates__Default__Path=/etc/nergal/web/web.crt
   Kestrel__Certificates__Default__KeyPath=/etc/nergal/web/web.key
   LocalSessions__Enabled=true
   LocalSessions__AccountDirectory=/var/lib/nergal/web/accounts
   LocalSessions__KeyDirectory=/var/lib/nergal/web/keys
   LocalSessions__CertificateFile=/etc/nergal/web/wrapping.pfx
   ControllerState__Enabled=true
   ControllerState__Directory=/var/lib/nergal/web/controller
   ```

   Add `ControllerState__TlsClientCertificatePath` and `ControllerState__TlsClientKeyPath` (`0600`, owned by `nergal-web`) when managing remote `tls-serve` agents, and `Oidc__*` variables when using federated group RBAC (`Oidc:AdministratorGroups`, `Oidc:AuditorGroups`).

## Remote TLS 1.3 mutual-authentication agents (`tls-serve`)

On remote managed hosts:

1. Generate dedicated leaf ECDSA P-256 or RSA server and controller client certificates with explicit EKUs (`serverAuth` on the agent server cert, `clientAuth` on the controller cert, `CA:FALSE`) and `0600` private keys.
2. Compute each certificate's lowercase SHA-256 DER thumbprint (`openssl x509 -in cert.crt -outform DER | sha256sum`).
3. Configure the remote agent unit `ExecStart`:

   ```sh
   ExecStart=/usr/bin/dotnet /opt/nergal/agent/nergal-agent.dll tls-serve /var/lib/nergal/agent 192.0.2.10:9443 /etc/nergal/agent/server.crt /etc/nergal/agent/server.key <CLIENT_SHA256>
   ```

4. Register the remote host in `/manage` using its `<ip>:<port>` and pinned server SHA-256 thumbprint.

## Installing the systemd units

1. Substitute `WEB_UID` (`id -u nergal-web`) and `SOCKET_GROUP_GID` (`getent group nergal-ctl | cut -d: -f3`) in `/etc/systemd/system/nergal-agent.service`.
2. Copy `deploy/systemd/nergal-web.service` to `/etc/systemd/system/nergal-web.service`.
3. Reload and start:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now nergal-agent.service nergal-web.service
   ```

## Operational boundaries in release 2026.11.21

- Native `nftables` on Linux is the sole firewall target. Other firewall adapters
  and Windows-native service deployments are outside scope (ADR 0051).
- Two-phase agent control (`prepare-apply`, `confirm`, `rollback`) supports the owned filter, NAT, bridge and early inet bundle slice under [ADR 0036](decisions/0036-complete-bundle-observation-and-rollback.md), with complete native receipt verification and coordinated rollback. Unsupported native semantics still fail closed; imported source text is not an agent payload.
- Run `nergal-agent reconcile /var/lib/nergal/agent` manually or from a pre-start dependency after host reboots when explicit new-boot reconciliation of owned tables is required.

## Unreleased controller schema 4

The source, typed object and conversion-plan libraries require controller schema 4. Existing
schema-1/2/3 controllers need an explicit offline `nergal-admin controller upgrade`
after a verified backup and stopping writers. New stores initialize at schema 4.
This upgrade does not change account or agent journal schemas. See
[the source library upgrade procedure](native-source-library.md).
