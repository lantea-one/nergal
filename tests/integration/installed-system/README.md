# Installed Debian single-host check

This opt-in test starts with a fresh Debian 13 amd64 netinst disk and installs an
already-built Nergal Debian package. It boots real systemd in QEMU with no network
interface or host mounts. All firewall mutations and packet probes run in a
dedicated network namespace inside the guest. Guest application passwords and
certificates are generated in that guest.

Use Bash, QEMU, qemu-img, isoinfo, cpio, gzip, OpenSSL, xorriso, dpkg-deb, and a
local Debian 13 amd64 netinst ISO. The fixture was prepared with Debian 13.8.
Build or obtain the Nergal Debian package separately. Collect the amd64 packages
`aspnetcore-runtime-10.0`, `dotnet-runtime-10.0`, `dotnet-hostfxr-10.0`,
`dotnet-host`, and `dotnet-runtime-deps-10.0` from Microsoft's Debian 13 feed
into a dedicated directory. Use compatible versions and verify them against the
vendor package feed. See [Microsoft's Debian installation instructions](https://learn.microsoft.com/en-us/dotnet/core/install/linux-debian).

```sh
bash tests/integration/installed-system/check.sh prepare /path/to/debian-13.8.0-amd64-netinst.iso
bash tests/integration/installed-system/check.sh check \
    /tmp/nergal-installed-base.XXXXXXXX/debian.qcow2 \
    /path/to/nergal_amd64.deb /path/to/dotnet-runtime-debs
```

The first command prints the installed base disk path. The second boots a fresh
copy-on-write overlay twice so the base can serve multiple runs. Add
`NERGAL_QEMU_ACCELERATOR=kvm` to both commands if QEMU can open `/dev/kvm`.
The default is TCG. Both commands print their serial log paths under `/tmp`.
The fixture retains the disks, attached media, and logs there for inspection.

The check requires package installation to leave both services stopped and the
agent journal absent. It uses the package's explicit enrollment unit, checks
repeat-enrollment denial without changing the owned table, and provisions a
synthetic local administrator using the installed command. It verifies the Web
and agent service capabilities, certificate-verified HTTPS login, the packaged
stylesheet, and matched versus denied Unix control responses from different UIDs.
An installed agent CLI operation denies IPv4 and IPv6 loopback ICMP packets. An
independent watchdog restores both packet flows and the last confirmed revision.
The fixture then puts the controller and enrolled agent in two guest namespaces
joined by a private veth pair. It registers and queries the remote service over
pinned mutual TLS and verifies that a wrong server fingerprint yields no revision.
It powers off while a second candidate is applied and unconfirmed. On the next
boot it starts the packaged reconcile unit, verifies the previous revision and
both IPv4 and IPv6 packet flows, and checks that the interrupted operation cannot
be confirmed and reconciliation cannot run twice in the same boot.
Routed forwarding, NAT, and web-initiated apply have separate acceptance boundaries.

## Installed multi-host upgrade, trust rotation, and restore

The opt-in multi-host fixture starts with two independently prepared Debian 13
QEMU base disks: one controller and one agent. It installs a baseline Nergal
package, exercises the installation, and upgrades both guests with a newer
package built from the same application code at an incremented package version.
The current schema stays unchanged across that package upgrade. A private
Unix-backed QEMU layer-2 link connects the guests; they have no external network
or host mounts. A synthetic managed HTTPS OIDC issuer runs inside the controller
guest. Two private offline raw disks hold the controller and agent backups.
After backup and shutdown, the fixture creates two fresh guest overlays and
swaps which base disk supplies each role. It verifies new machine and boot IDs,
attaches the backup disks read-only, restores each role independently and
reconciles the agent on its new boot.

Prepare both Debian 13 guest disks and stage the runtime dependency packages as
described above. To build a fixture upgrade before the first release, use a
disposable checkout, increment `Version` and `InformationalVersion` in
`Directory.Build.props`, then build a second `.deb` with the same schemas.
Run the fixture with both package files.

```sh
python3 -B tests/integration/installed-system/check-multihost.py \
    --accelerator kvm \
    CONTROLLER_BASE_QCOW2 AGENT_BASE_QCOW2 BASELINE_DEB UPGRADE_DEB RUNTIME_DIR
```

Use `--accelerator tcg` (the default) where KVM is unavailable. The fixture
rejects a shared controller/agent base disk or non-increasing package versions.
It checks authenticated controller status against the actual server
fingerprints, replacement registration and retirement, overlapping then
retired client-certificate pins and denial of the old credential. After restore
it checks the saved controller settings, reviewed policy digest, registration,
audit and last authenticated observation, plus fresh OIDC and local logins.
The agent checks exercise real packets, timed rollback, and authenticated drift
detection and recovery in a disposable network namespace. The command prints
`PASS` after all phases complete. Logs, overlays, ISOs and synthetic backup
disks stay in a private temporary directory under `/tmp` for inspection.

The installed fixture uses the SQLite controller, identity and agent stores.
Server-database restore has its own [M6 fixtures](../controller-sql/README.md).
