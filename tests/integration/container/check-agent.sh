#!/bin/bash
# Stage a local image and boot the installed-system fixture without a NIC or host mounts.
set -euo pipefail
umask 077

if (( $# < 4 || $# > 5 )); then
    printf 'Usage: %s BASE_QCOW2 AGENT_IMAGE DOCKER_STATIC_AMD64_TGZ DOCKER_SHA256 [STATIC_COMPOSE_AMD64]\n' "$0" >&2
    exit 2
fi

base=$(realpath -e -- "$1")
image=$2
engine=$(realpath -e -- "$3")
digest=${4,,}
accelerator=${NERGAL_QEMU_ACCELERATOR:-tcg}
case "$accelerator" in
    tcg) cpu=max ;;
    kvm) cpu=host ;;
    *) printf 'Unsupported NERGAL_QEMU_ACCELERATOR\n' >&2; exit 2 ;;
esac
if [[ ! -f $base || ! -f $engine || ! $digest =~ ^[0-9a-f]{64}$ ||
      ! $image =~ ^[a-zA-Z0-9][a-zA-Z0-9._/:-]*:[a-zA-Z0-9_][a-zA-Z0-9_.-]*$ ]]; then
    printf 'Expected a prepared qcow2, a tagged local agent image, and a Docker archive with its upstream SHA-256\n' >&2
    exit 2
fi

fixture=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d /tmp/nergal-agent-container.XXXXXXXX)
printf 'Guest serial log %s/check.log\n' "$work"
mkdir "$work/media"
install -m 0644 -- "$engine" "$work/media/docker.tgz"
(
    cd "$work/media"
    printf '%s  docker.tgz\n' "$digest" | sha256sum --check --strict
)
if (( $# == 5 )); then
    compose=$(realpath -e -- "$5")
    install -m 0644 -- "$compose" "$work/media/docker-compose"
    install -m 0644 "$fixture/../../../deploy/container/docker-compose.agent.yml" "$work/media/agent.yml"
fi

install -m 0644 "$fixture/check-agent-guest.sh" "$work/media/check-guest.sh"
printf '%s\n' "$image" > "$work/media/image-name"
docker image save --platform linux/amd64 --output "$work/media/agent.tar" -- "$image"
sha256sum "$work/media/agent.tar"
xorriso -as mkisofs -quiet -R -V NERGAL_TEST -o "$work/check.iso" "$work/media"
qemu-img create -f qcow2 -F qcow2 -b "$base" "$work/debian-test.qcow2"

if ! timeout --kill-after=10s 10m qemu-system-x86_64 \
    -machine "accel=$accelerator" -cpu "$cpu" -smp 2 -m 3072 \
    -nodefaults -no-user-config -display none -monitor none -serial stdio -nic none -no-reboot \
    -drive "if=virtio,format=qcow2,file=$work/debian-test.qcow2" -cdrom "$work/check.iso" \
    > "$work/check.log" 2>&1 ||
    ! grep -Eq 'NERGAL_AGENT_CONTAINER_PASS[[:space:]]*$' "$work/check.log" ||
    ! grep -Eq 'NERGAL_INSTALLED_RESULT=0[[:space:]]*$' "$work/check.log"; then
    printf 'Agent container check failed. Serial log %s/check.log\n' "$work" >&2
    exit 1
fi
printf 'Agent container check passed under QEMU %s. Serial log %s/check.log\n' "$accelerator" "$work"
