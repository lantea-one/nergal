#!/bin/bash
set -eu

virtualization=$(systemd-detect-virt --vm)
if [[ -z ${INVOCATION_ID:-} || $(hostname) != nergal-installed-test ||
      ! $virtualization =~ ^(kvm|qemu)$ || $(ls -1 /sys/class/net) != lo ]]; then
    printf 'Refusing to run outside the isolated fixture guest\n' >&2
    exit 1
fi

# The hypervisor supplies a read-only ISO. The VM has no network interface.
directory=/mnt/nergal-fixture
trap 'systemctl --no-block poweroff' EXIT
: > /run/nergal-installed-fixture
mkdir -p "$directory"
mount -t iso9660 -o ro,nodev,nosuid,noexec LABEL=NERGAL_TEST "$directory"
set +e
bash "$directory/check-guest.sh" "$directory"
result=$?
set -e
printf 'NERGAL_INSTALLED_RESULT=%d\n' "$result"
exit "$result"
