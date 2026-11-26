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

## Install a release package

The **Build Linux release packages** workflow runs for version tags, packaging
pull requests, and on demand.
It builds AMD64 packages with native tools on the shared organization CI runner.
Each run publishes the files and their SHA-256 manifest as CI artifacts.

| Distribution | Package | Install |
| --- | --- | --- |
| Debian and Ubuntu | `.deb` | `sudo apt install ./nergal_VERSION_amd64.deb` |
| Fedora | `.rpm` | `sudo dnf install ./nergal-VERSION-1.x86_64.rpm` |
| Arch Linux | `.pkg.tar.zst` | `sudo pacman -U ./nergal-VERSION-1-x86_64.pkg.tar.zst` |

Each package requires its distribution's .NET 10 runtime, ASP.NET Core 10
runtime, systemd and nftables. On Debian 13, configure the [Microsoft APT
feed](https://learn.microsoft.com/en-us/dotnet/core/install/linux-debian#debian-13)
before installation. Ubuntu 26.04, Fedora and Arch use their distribution feeds.
Check the included file with `sha256sum -c SHA256SUMS` in the artifact directory.

To build locally after locked restore, select `--format deb`, `rpm`, or
`arch`. Use `--format all` on a build machine with all three tools.
Set `SOURCE_DATE_EPOCH` to the source revision's Unix timestamp for a release
build. Each format also produces a Linux tar archive from the same staged layout.

```sh
dotnet restore Nergal.slnx --locked-mode
bash scripts/package-release.sh --format deb --verify
```

The packages install vendor units, CLI launchers and systemd account and
directory definitions. They leave service activation, credentials and firewall
enrollment to the operator.
The [Debian QEMU fixture](../tests/integration/installed-system/README.md)
checks the installed services and agent rollback in an isolated guest.

## Offline package upgrades

Stage the newer package and its verified SHA-256 manifest on each controller
and agent host using the site's offline transfer process. Stage any required
distribution runtime packages before disconnecting the host. Verify the package
checksum, then upgrade with the local package manager. On Debian, use
`sudo apt install ./nergal_VERSION_amd64.deb`. Use a package whose version is
newer than the installed one and whose schemas match the existing stores.
Keep application services stopped during a planned maintenance window, install
the package, inspect package-manager and service logs, and start the services
explicitly after checking their private configuration and state ownership.
Confirm authenticated status and the expected revision before enabling normal
controller dispatch. Package installation does not enroll an agent, reconcile
its firewall, or authorize an apply.

## Rotate remote agent trust

Remote TLS control uses explicit SHA-256 DER leaf pins on both sides (ADR 0028).
For an agent server-certificate rotation, provision the replacement certificate
and key privately, calculate its lowercase SHA-256 DER fingerprint, and
register the replacement endpoint with that new server pin in the controller.
Switch the agent listener to the new certificate during the maintenance window.
Verify authenticated status and the expected revision through the replacement
registration before retiring the old registration. The replacement has its
own registration ID. Both registration changes remain in the controller audit.

For controller client-certificate rotation, configure the agent's client pin
allowlist to accept both the old and replacement client fingerprints. Install
the replacement private key only in the controller service's protected
directory, configure the controller to use it, and verify authenticated agent
status. Then remove the old fingerprint from the agent allowlist and verify
that the old client credential is denied while the replacement still succeeds.
Keep the active keys and certificate trust configuration in access-controlled
backups. Retire old private keys according to the site's credential procedure.

## Full controller and agent recovery

Back up the controller and each agent independently. Finish or roll back pending
operations and quiesce the corresponding service so each set is internally
consistent. Preserve the controller's
account and identity stores, application database files and SQLite WAL/SHM as a
consistent set, Data Protection key ring, wrapping certificate/private key and
wrapping-key history, HTTPS certificate/key, OIDC issuer and TLS trust
configuration, and service configuration. Use the database's native consistent
backup procedure; for SQLite use the backup API described in
[controller SQLite backup](controller-sqlite-backup.md), rather than copying
only a live main database file.

For each agent, preserve its protected journal and related state together with
its boot and resource ownership records, TLS listener configuration and
site-specific systemd drop-ins. On the recovery host, verify the original
service UID and group and preserve the original directory and key-file modes.
The controller database and the agent journal have independent trust roots.

Restore controller and agents onto separate, clean installations, keeping the
old hosts powered off and offline to prevent duplicate identities or competing
firewall managers. Check the restored data and trust configuration before
starting services. On an agent with a new boot identity, explicitly run the
agent's boot reconciliation procedure and verify authenticated status and real
policy behavior before restoring controller dispatch. Reconciliation can
recreate only the journal's last confirmed owned state; inspect collisions or
ownership failures instead of adopting existing tables. Keep pending rollback
and controller/agent observations under operator review. M6 server-database
backup and restore procedures are separate and documented in
[controller server databases](controller-server-databases.md).

## Initialize a new single host

1. Create the private web state subdirectories and initialize the offline stores.

   ```sh
   sudo install -d -o nergal-web -g nergal-web -m 0700 \
     /var/lib/nergal/web/accounts /var/lib/nergal/web/controller /var/lib/nergal/web/keys
   sudo -u nergal-web nergal-admin account init /var/lib/nergal/web/accounts
   sudo -u nergal-web nergal-admin account provision /var/lib/nergal/web/accounts admin
   sudo -u nergal-web nergal-admin controller init /var/lib/nergal/web/controller
   ```

2. Install the HTTPS certificate and key plus an independent wrapping PKCS#12
   certificate with a private key. Place them under `/etc/nergal/web/` using
   owner-only permissions for private key files. Create the wrapping certificate
   directory with `sudo install -d -o nergal-web -g nergal-web -m 0700 /etc/nergal/web/private`.
   Install `wrapping.pfx` there with owner `nergal-web` and mode `0600`.

3. Set these values in the private service environment file
   `/etc/nergal/web/env`. Choose a browser-trusted HTTPS certificate for the
   host name and the appropriate listening address.

   ```ini
   ASPNETCORE_URLS=https://127.0.0.1:8443
   Kestrel__Certificates__Default__Path=/etc/nergal/web/web.crt
   Kestrel__Certificates__Default__KeyPath=/etc/nergal/web/web.key
   LocalSessions__Enabled=true
   LocalSessions__AccountDirectory=/var/lib/nergal/web/accounts
   LocalSessions__KeyDirectory=/var/lib/nergal/web/keys
   LocalSessions__CertificateFile=/etc/nergal/web/private/wrapping.pfx
   ControllerState__Enabled=true
   ControllerState__Directory=/var/lib/nergal/web/controller
   ```

4. Enroll the host explicitly. This creates the owned `inet nergal_filter`
   baseline. The enrollment unit runs with `CAP_NET_ADMIN` under the same
   dedicated account that owns the protected agent journal.

   ```sh
   sudo systemctl start nergal-agent-enroll.service
   sudo systemctl enable --now nergal-agent.service nergal-web.service
   ```

5. Sign in at `/manage`. Open **Hosts** and register a local Unix connection
   at `/run/nergal/control.sock` using the UID from `id -u nergal-agent`.
   Use the `nergal-ctl` group ID when pinning the socket group. Check the
   authenticated status before reviewing a candidate change.

For a source or archive installation, install the same vendor units and
`/usr/lib/nergal/nergal-local-agent` launcher, run the account and directory
setup above, and reload systemd before starting services.

## Reconcile a managed host after reboot

Run `sudo systemctl start nergal-agent-reconcile.service` on an enrolled host
after a reboot, and then recheck the authenticated agent status. The unit runs
the journaled recovery command under `nergal-agent` with `CAP_NET_ADMIN`. It
recreates the last confirmed policy, verifies its native receipt, and marks any
unfinished operation from the previous boot interrupted. Repeating the unit
on the same boot returns `reconcile.sameBoot`. If another ruleset already uses
the enrolled table names, inspect the conflict before continuing.

The package leaves this unit inactive. An installation can order an explicit
start before the agent listener once its boot-time firewall ownership and
ordering have been established.

## Remote TLS 1.3 mutual-authentication agents (`tls-serve`)

1. Generate a dedicated ECDSA P-256 or RSA leaf certificate for each agent and
   another for the controller. Set `CA:FALSE`, with EKU `serverAuth` on the
   remote leaf and `clientAuth` on the controller leaf. Keep each private key
   with its own service account in a service-owned directory with mode `0700`,
   and set the key file to mode `0600`.
2. Compute each certificate's lowercase SHA-256 DER thumbprint with
   `openssl x509 -in cert.crt -outform DER | sha256sum`. Give the agent the
   controller fingerprint and the controller the agent fingerprint.
3. On the remote host, run `sudo systemctl start nergal-agent-enroll.service`
   once. Use `sudo systemctl edit nergal-agent.service` to configure the listener.

   ```ini
   [Service]
   ExecStart=
   ExecStart=/usr/bin/nergal-agent tls-serve /var/lib/nergal/agent 192.0.2.10:9443 /etc/nergal/agent/private/server.crt /etc/nergal/agent/private/server.key <CLIENT_SHA256>
   ```

   Replace the example endpoint with the agent's management address. Then run
   `sudo systemctl enable --now nergal-agent.service` for the new listener.
4. In the controller service environment, set
   `ControllerState__TlsClientCertificatePath` and
   `ControllerState__TlsClientKeyPath` to its client certificate and key paths.
   Restart the controller and register the remote endpoint and pinned server
   fingerprint in **Hosts**. Check the authenticated status and revision before
   reviewing or applying a candidate.

## Containerized controller

Build the unprivileged controller image from this checkout and initialize its
private named volumes with the offline administrator service.

```sh
sh deploy/container/build.sh
docker compose -f deploy/container/compose.yaml run --rm admin account init /var/lib/nergal/state/accounts
docker compose -f deploy/container/compose.yaml run --rm admin account provision /var/lib/nergal/state/accounts admin
docker compose -f deploy/container/compose.yaml run --rm admin controller init /var/lib/nergal/state/controller
```

Set `NERGAL_CREDENTIALS_DIR` to a directory containing `https.crt`,
`https.key`, and `wrapping.pfx`. Give the directory mode `0700` and the private
files mode `0600`. Both must be owned by UID/GID 1654 as seen from the container.
The mount is read-only.
Use `NERGAL_SETTINGS_FILE` for private deployment overrides. The example
publishes the HTTPS port on IPv4 loopback. For remote browser access, configure
the intended HTTPS entry point and hostname.

```sh
docker compose -f deploy/container/compose.yaml up -d --no-build controller
```

The controller has no Linux capabilities and uses separate volumes for
application state and the encrypted session key ring. Preserve both volumes
and the wrapping certificate when replacing the container. Run the privileged
agent as its own service on each managed Linux host and connect over pinned
mutual TLS. Configure the controller's client certificate and private key as
read-only files in the credentials directory using
`ControllerState__TlsClientCertificatePath` and
`ControllerState__TlsClientKeyPath`.

## Operational boundaries

- Native `nftables` on Linux is the sole firewall target. Other firewall adapters
  and Windows-native service deployments are outside scope (ADR 0051).
- Two-phase agent control (`prepare-apply`, `confirm`, `rollback`) supports the owned filter, NAT, bridge and early inet bundle slice under [ADR 0036](decisions/0036-complete-bundle-observation-and-rollback.md), with complete native receipt verification and coordinated rollback. Unsupported native semantics still fail closed; imported source text is not an agent payload.

## Unreleased controller schema 6

Controller schema 6 includes immutable settings versions and their audit bindings,
plus the latest authenticated usable observation for each registered host.
Initialize a fresh directory with `nergal-admin controller init`. Startup rejects
older development schemas and initialization refuses to replace an existing
store. Handle retained development data separately. The account store and
protected agent journal have their own initialization and ownership boundaries.
See [controller backup and restore](controller-sqlite-backup.md) and the
[fresh-schema decision](decisions/0065-fresh-prerelease-database-schemas.md).
For PostgreSQL, MariaDB, MySQL and SQL Server, see [controller server databases](controller-server-databases.md).
