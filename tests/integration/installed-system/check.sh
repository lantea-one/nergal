#!/bin/bash
# Boot a dedicated disk with no NIC, host filesystems, management sockets or host capabilities.
set -euo pipefail
umask 077

fixture=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
accelerator=${NERGAL_QEMU_ACCELERATOR:-tcg}
case "$accelerator" in
    tcg) cpu=max ;;
    kvm) cpu=host ;;
    *) printf 'Unsupported NERGAL_QEMU_ACCELERATOR\n' >&2; exit 2 ;;
esac
qemu=(qemu-system-x86_64 -machine "accel=$accelerator" -cpu "$cpu" -smp 2 -m 2048
    -nodefaults -no-user-config -display none -monitor none -serial stdio -nic none -no-reboot)

prepare() {
    local installer=$1 work=$2
    isoinfo -R -i "$installer" -x /install.amd/vmlinuz > "$work/vmlinuz"
    isoinfo -R -i "$installer" -x /install.amd/initrd.gz > "$work/initrd.gz"
    test -s "$work/vmlinuz" && test -s "$work/initrd.gz" || return 1
    mkdir "$work/initrd-input"
    cp "$fixture"/{debian.preseed,fixture-start.sh,fixture-start.service} "$work/initrd-input/"
    # Debian requires a valid crypt hash when no regular user is created. The late
    # command locks root, and the random plaintext never leaves this pipe.
    {
        printf 'd-i passwd/root-password-crypted password '
        openssl rand -hex 32 | openssl passwd -6 -stdin
    } >> "$work/initrd-input/debian.preseed"
    (
        cd "$work/initrd-input"
        printf '%s\n' debian.preseed fixture-start.sh fixture-start.service |
            cpio --quiet -o -H newc | gzip -n
    ) >> "$work/initrd.gz"
    qemu-img create -f qcow2 "$work/debian.qcow2" 8G
    timeout --kill-after=10s 30m "${qemu[@]}" \
        -drive "if=virtio,format=qcow2,file=$work/debian.qcow2" -cdrom "$installer" \
        -kernel "$work/vmlinuz" -initrd "$work/initrd.gz" \
        -append 'auto=true priority=critical preseed/file=/debian.preseed console=ttyS0,115200n8 TERM=vt102 DEBIAN_FRONTEND=text --- console=ttyS0,115200n8' \
        > "$work/install.log" 2>&1
    grep -q NERGAL_DEBIAN_INSTALLED "$work/install.log"
    printf 'Debian installer completed. Base disk %s/debian.qcow2\n' "$work"
}

check() {
    local base=$1 package=$2 runtimes=$3 work=$4
    test "$(dpkg-deb -f "$package" Package)" = nergal
    local runtime_debs=("$runtimes"/*.deb)
    test -f "${runtime_debs[0]}"
    mkdir -p "$work/media/runtime-debs"
    install -m 0644 "$package" "$work/media/nergal.deb"
    install -m 0644 "${runtime_debs[@]}" "$work/media/runtime-debs/"
    install -m 0644 "$fixture"/{check-guest.sh,check-protocol.py} "$work/media/"
    xorriso -as mkisofs -quiet -R -V NERGAL_TEST -o "$work/check.iso" "$work/media"
    sha256sum "$package"
    qemu-img create -f qcow2 -F qcow2 -b "$base" "$work/debian-test.qcow2"
    timeout --kill-after=10s 8m "${qemu[@]}" \
        -drive "if=virtio,format=qcow2,file=$work/debian-test.qcow2" -cdrom "$work/check.iso" \
        > "$work/check.log" 2>&1
    if ! grep -q 'NERGAL_INSTALLED_RESULT=0' "$work/check.log"; then
        printf 'Installed-system check failed. Serial log %s/check.log\n' "$work" >&2
        return 1
    fi
    printf 'Installed-system check passed. Serial log %s/check.log\n' "$work"
}

case "${1:-}" in
    prepare)
        test "$#" -eq 2
        installer=$(realpath -e "$2")
        work=$(mktemp -d /tmp/nergal-installed-base.XXXXXXXX)
        printf 'Installer log %s/install.log\n' "$work"
        prepare "$installer" "$work"
        ;;
    check)
        test "$#" -eq 4
        base=$(realpath -e "$2")
        package=$(realpath -e "$3")
        runtimes=$(realpath -e "$4")
        work=$(mktemp -d /tmp/nergal-installed-check.XXXXXXXX)
        printf 'Guest log %s/check.log\n' "$work"
        check "$base" "$package" "$runtimes" "$work"
        ;;
    *)
        printf 'Usage: %s prepare DEBIAN_NETINST_ISO\n       %s check BASE_QCOW2 NERGAL_DEB DOTNET_DEB_DIRECTORY\n' "$0" "$0" >&2
        exit 2
        ;;
esac
