#!/bin/bash
# Driven only by the private QEMU virtio-serial port. Application traffic uses the separate guest NIC.
set -euo pipefail
umask 077

media=$1
runtime=/run/nergal-ops
role=$(cat "$media/role")
case "$role" in
    controller) address=192.0.2.1; mac=52:54:00:4d:37:01 ;;
    agent) address=192.0.2.2; mac=52:54:00:4d:37:02 ;;
    *) exit 2 ;;
esac
virtualization=$(systemd-detect-virt --vm)
if [[ $EUID != 0 || $(hostname) != nergal-installed-test || ! $virtualization =~ ^(kvm|qemu)$ ||
      ! -f /run/nergal-installed-fixture ]]; then
    echo 'Refusing execution outside the dedicated fixture guest' >&2
    exit 1
fi

if (($# == 1)); then
    test "$(ls -1 /sys/class/net)" = lo
    test -c /dev/virtio-ports/nergal.fixture
    install -d -m 0700 "$runtime"
    if [[ $role == controller ]]; then
        install -m 0600 "$media/password" "$runtime/password"
    fi
    exec 3<> /dev/virtio-ports/nergal.fixture
    printf 'READY\n' >&3
    while IFS=' ' read -r -a command <&3; do
        if [[ ${command[*]} == shutdown ]]; then
            printf 'OK\n' >&3
            exit 0
        fi
        result=0
        bash "$media/check-guest.sh" "$media" "${command[@]}" > "$runtime/phase.log" 2>&1 3>&- || result=$?
        cat "$runtime/phase.log"
        sed 's/^/LOG /' "$runtime/phase.log" >&3
        if ((result != 0)); then
            printf 'ERROR %d\n' "$result" >&3
            exit "$result"
        fi
        printf 'OK\n' >&3
    done
    exit 1
fi

phase=$2
shift 2
if [[ $phase == network ]]; then
    deadline=$((SECONDS + 15))
    until [[ $(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '.' | wc -c) == 2 ]]; do
        ((SECONDS < deadline)) || exit 1
        sleep .1
    done
    for nic in /sys/class/net/*; do
        [[ $nic == */lo ]] && continue
        test "$(cat "$nic/address")" = "$mac"
        ip addr add "$address/30" dev "${nic##*/}"
        ip link set "${nic##*/}" up
    done
    ip link set lo up
fi
network=()
if [[ $role == agent && -e /run/netns/nergal-multihost-agent ]]; then
    test "$(ls -1 /sys/class/net)" = lo
    network=(netns exec nergal-multihost-agent ip)
fi
links=$(ip "${network[@]}" -o link show)
test "$(wc -l <<< "$links")" = 2
grep -Fq "$mac" <<< "$links"
test -z "$(ip "${network[@]}" route show default)$(ip "${network[@]}" -6 route show default)"
addresses=$(ip "${network[@]}" -brief -4 address)
grep -Fq "$address/30" <<< "$addresses"
case "$phase" in
    network)
        sed 's/^/BOOT_ID=/' /proc/sys/kernel/random/boot_id
        sed 's/^/MACHINE_ID=/' /etc/machine-id
        ;;
    package)
        ! command -v dotnet || exit 1
        if dpkg-query -W nergal 2>/dev/null; then exit 1; fi
        case "$1" in
            baseline) package=nergal.deb ;;
            upgrade) package=nergal-upgrade.deb ;;
            *) exit 2 ;;
        esac
        dpkg -i "$media"/runtime-debs/*.deb "$media/$package"
        test "$(dpkg-query -W -f='${Version}' nergal)" = "$(dpkg-deb -f "$media/$package" Version)"
        if systemctl is-active --quiet nergal-agent.service || systemctl is-active --quiet nergal-web.service; then
            exit 1
        fi
        test ! -e /var/lib/nergal/agent/journal.db
        test ! -e /var/lib/nergal/web/controller/controller.db
        ;;
    backup|restore|upgrade)
        export backup_disk=/dev/disk/by-id/virtio-NERGAL_BACKUP
        # shellcheck source=/dev/null
        source "$media/multihost-backup.sh"
        case "$phase" in
            backup) backup_state ;;
            restore) restore_state ;;
            upgrade) upgrade_package ;;
        esac
        ;;
    agent-*)
        [[ $role == agent ]]
        # shellcheck source=/dev/null
        source "$media/multihost-agent.sh"
        case "$phase" in
            agent-init) agent_init "$@" ;;
            agent-commit) agent_commit_policy ;;
            agent-rotate) agent_rotate "$@" ;;
            agent-trust) agent_trust "$@" ;;
            agent-start) agent_restart ;;
            agent-reconcile) agent_restore ;;
            agent-drift) agent_inject_drift ;;
            agent-repair) agent_repair_drift ;;
            *) exit 2 ;;
        esac
        ;;
    controller-*)
        [[ $role == controller ]]
        bash "$media/multihost-controller.sh" "$media" "${phase#controller-}" "$@"
        ;;
    oidc-configure|oidc-trust|oidc-verify)
        [[ $role == controller ]]
        python3 -B "$media/multihost-oidc.py" "${phase#oidc-}"
        ;;
    *) exit 2 ;;
esac
