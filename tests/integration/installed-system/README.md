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

The first command prints the installed base disk path. The second uses a fresh
copy-on-write overlay so the base can serve multiple runs. Add
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
This exercises package bootstrap and basic installed native behavior. Routed
forwarding, NAT, web-initiated policy apply, and reconciliation after guest
reboot have separate acceptance boundaries.
