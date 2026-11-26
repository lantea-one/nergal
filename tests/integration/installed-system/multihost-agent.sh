#!/bin/bash
# Sourced by multihost-guest.sh after its QEMU, role, NIC and offline-media checks.
# Each phase runs in its own errexit shell. Only the certificate pin leaves the guest.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then exit 2; fi

ma_namespace=nergal-multihost-agent
ma_config=/etc/nergal/agent
ma_state=/var/lib/nergal/agent

_ma_pins() {
    local LC_ALL=C pin
    if (( $# < 1 || $# > 2 )); then return 2; fi
    for pin in "$@"; do
        if [[ ! $pin =~ ^[0-9A-Fa-f]{64}$ ]]; then
            echo 'Expected a 64-digit SHA-256 client certificate pin' >&2
            return 2
        fi
    done
    local IFS=,
    printf '%s\n' "${*,,}"
}

_ma_setup_namespace() {
    local nic
    if [[ ! -e /run/netns/$ma_namespace ]]; then
        # The orchestrator assigned this one fixture NIC before invoking the phase.
        nic=$(ip -o -4 addr show | awk '$4 == "192.0.2.2/30" {print $2}')
        [[ -n $nic && $(cat "/sys/class/net/$nic/address") == 52:54:00:4d:37:02 ]]
        ip netns add "$ma_namespace"
        ip link set dev "$nic" netns "$ma_namespace"
        ip -n "$ma_namespace" link set lo up
        ip -n "$ma_namespace" link set dev "$nic" up
        ip -n "$ma_namespace" addr replace 192.0.2.2/30 dev "$nic"
    fi
    [[ $(stat -Lc %i "/run/netns/$ma_namespace") != "$(stat -Lc %i /proc/1/ns/net)" ]]
    ip -n "$ma_namespace" -o -4 addr show | awk '$4 == "192.0.2.2/30" {found=1} END {exit !found}'
}

# Drop-ins are boot-local. A restored guest reconstructs them from the package
# and the backed-up role configuration before running the explicit reconcile unit.
_ma_units() {
    local unit dir
    for unit in nergal-agent-enroll nergal-agent-reconcile nergal-agent; do
        dir=/run/systemd/system/$unit.service.d
        install -d "$dir"
        printf '[Service]\nNetworkNamespacePath=/run/netns/%s\n' "$ma_namespace" > "$dir/fixture.conf"
    done
    cat >> /run/systemd/system/nergal-agent.service.d/fixture.conf <<'UNIT'
EnvironmentFile=/etc/nergal/agent/client-pins.env
ExecStart=
ExecStart=/usr/bin/nergal-agent tls-serve /var/lib/nergal/agent 192.0.2.2:9443 /etc/nergal/agent/private/server.crt /etc/nergal/agent/private/server.key ${CLIENT_PINS}
UNIT
    systemctl daemon-reload
}

_ma_set_pins() {
    local tmp
    tmp=$(mktemp "$ma_config/.client-pins.XXXXXXXX")
    printf 'CLIENT_PINS=%s\n' "$1" > "$tmp"
    mv -T "$tmp" "$ma_config/client-pins.env"
}

_ma_identity() (
    set -e
    umask 077
    local tmp
    tmp=$(mktemp -d "$ma_config/.new-server.XXXXXXXX")
    trap 'rm -f "$tmp/server.key" "$tmp/server.crt"; rmdir "$tmp"' EXIT
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 7 \
        -subj '/CN=nergal-agent-fixture.invalid' -addext 'subjectAltName=IP:192.0.2.2' \
        -addext 'basicConstraints=critical,CA:FALSE' -addext 'keyUsage=critical,digitalSignature' \
        -addext 'extendedKeyUsage=serverAuth' -keyout "$tmp/server.key" -out "$tmp/server.crt"
    chown nergal-agent:nergal-agent "$tmp"/server.{crt,key}
    install -d -m 0700 -o nergal-agent -g nergal-agent "$ma_config/private"
    mv -T "$tmp/server.key" "$ma_config/private/server.key"
    mv -T "$tmp/server.crt" "$ma_config/private/server.crt"
)

_ma_server_pin() {
    openssl x509 -in "$ma_config/private/server.crt" -outform DER | sha256sum | cut -d ' ' -f 1
}

_ma_start_listener() {
    local pid sockets deadline=$((SECONDS + 60))
    systemctl start nergal-agent.service
    while (( SECONDS < deadline )); do
        pid=$(systemctl show -p MainPID --value nergal-agent.service)
        sockets=$(ip netns exec "$ma_namespace" ss -4Hlnpt 'sport = :9443')
        if [[ $pid != 0 && $sockets == *'192.0.2.2:9443 '* && $sockets == *"pid=$pid,"* ]]; then
            return 0
        fi
        sleep .2
    done
    echo 'Packaged nergal-agent did not bind 192.0.2.2:9443 in the fixture namespace' >&2
    return 1
}

agent_init() {
    local pins pin
    pins=$(_ma_pins "$@") || return 2
    [[ $# == 1 && ! -e $ma_state/journal.db && ! -e $ma_config/private/server.key ]] || return 1
    _ma_setup_namespace
    _ma_identity
    _ma_set_pins "$pins"
    _ma_units
    systemctl start nergal-agent-enroll.service
    _ma_start_listener
    pin=$(_ma_server_pin)
    printf 'SERVER_PIN=%s\n' "$pin"
}

_ma_as_agent() {
    ip netns exec "$ma_namespace" setpriv --reuid=nergal-agent --regid=nergal-agent --init-groups \
        --inh-caps=-all,+net_admin --ambient-caps=-all,+net_admin --bounding-set=-all,+net_admin \
        --no-new-privs "$@"
}

_ma_cli() {
    _ma_as_agent /usr/bin/nergal-agent "$1" "$ma_state" "${@:2}"
}

_ma_packets() {
    local expected=$1 result=0
    ip netns exec "$ma_namespace" ping -4 -qn -c 1 -W 1 127.0.0.1 >/dev/null || return 1
    ip netns exec "$ma_namespace" ping -6 -qn -c 1 -W 1 ::1 >/dev/null || result=$?
    if (( result != expected )); then
        printf 'IPv6 loopback ping returned %d, expected %d\n' "$result" "$expected" >&2
        return 1
    fi
}

_ma_apply_policy() {
    local terminal=$1 timeout=$2 operation watchdog watcher ready_by log
    operation=$(cat /proc/sys/kernel/random/uuid)
    watchdog=$(cat /proc/sys/kernel/random/uuid)
    log=$(mktemp /run/nergal-ops/agent-watch.XXXXXXXX)
    _ma_cli prepare "$operation" "$timeout" accept ipv6:drop
    # Separate CLI worker. The listener can stop and no client needs to stay connected.
    _ma_cli watch "$operation" "$watchdog" </dev/null >"$log" 2>&1 &
    watcher=$!
    ready_by=$((SECONDS + 45))
    until grep -qx WATCHING "$log"; do
        if ! kill -0 "$watcher" 2>/dev/null || (( SECONDS >= ready_by )); then
            echo 'Independent rollback watchdog did not arm' >&2
            return 1
        fi
        sleep .1
    done
    _ma_cli apply "$operation" "$watchdog"
    _ma_packets 1
    if [[ $terminal == Confirmed ]]; then
        _ma_cli confirm "$operation" "$watchdog"
    else
        systemctl stop nergal-agent.service
    fi
    wait "$watcher"
    grep -qx "$terminal" "$log"
}

agent_commit_policy() {
    _ma_packets 0
    _ma_apply_policy RolledBack 35
    _ma_packets 0
    _ma_start_listener
    _ma_apply_policy Confirmed 120
    _ma_packets 1
}

agent_rotate() {
    local pins old_pin pin
    pins=$(_ma_pins "$@") || return 2
    old_pin=$(_ma_server_pin)
    systemctl stop nergal-agent.service
    _ma_identity
    _ma_set_pins "$pins"
    _ma_start_listener
    pin=$(_ma_server_pin)
    [[ $pin != "$old_pin" ]]
    printf 'SERVER_PIN=%s\n' "$pin"
}

agent_trust() {
    local pins
    pins=$(_ma_pins "$@") || return 2
    _ma_set_pins "$pins"
    systemctl stop nergal-agent.service
    _ma_start_listener
}

agent_restart() {
    _ma_units
    _ma_start_listener
}

agent_restore() {
    _ma_setup_namespace
    _ma_units
    _ma_packets 0
    # The packaged CLI verifies the different kernel boot and refuses a table collision.
    systemctl start nergal-agent-reconcile.service
    _ma_start_listener
    _ma_packets 1
}

# Only the guarded guest orchestrator writes policy during this check. Hold the
# packaged agent's POSIX byte-range lock across each observation and mutation.
_ma_native_drift() {
    [[ -e /run/netns/$ma_namespace &&
       $(stat -Lc %i "/run/netns/$ma_namespace") != "$(stat -Lc %i /proc/1/ns/net)" ]] || return 1
    _ma_as_agent timeout 20s python3 -B - "$1" "${2:-}" <<'PY'
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from uuid import UUID

action, saved = sys.argv[1:]
state = Path("/var/lib/nergal/agent")
scope = ["inet", "nergal_filter", "input"]

def require(condition, message):
    if not condition:
        sys.exit(message)

def nft(*args):
    return subprocess.check_output(["/usr/sbin/nft", "-ja", *args], timeout=5)

def listing():
    entries = json.loads(nft("list", "table", *scope[:2]))["nftables"]
    return [item for item in entries if "metainfo" not in item]

def rule_handle(item, left, right):
    rule = item["rule"]
    handle = rule["handle"]
    require(type(handle) is int and 0 < handle <= 2**64 - 1, "Invalid native rule handle")
    expected = {"family": scope[0], "table": scope[1], "chain": scope[2], "handle": handle,
                "expr": [{"match": {"op": "==", "left": left, "right": right}}, {"drop": None}]}
    require(rule == expected, "Unexpected native rule in fixture input chain")
    return handle

# A rule comment is outside the observable schema. This exact address match
# on TEST-NET-2 distinguishes the fixture rule and leaves controller traffic usable.
marker = {"payload": {"protocol": "ip", "field": "saddr"}}
address = "198.51.100.77"
with (state / "resource.lock").open("r+b") as lock:
    fcntl.lockf(lock, fcntl.LOCK_EX, 1)
    with sqlite3.connect((state / "journal.db").as_uri() + "?mode=ro", uri=True) as db:
        receipt = db.execute("""
            SELECT r.owner, r.resource, r.handle FROM enrollment e JOIN resource_receipt r USING(singleton)
            WHERE e.singleton=1 AND e.active IS NULL AND e.resource_bound=1 AND e.owner=r.owner
              AND e.revision='2' AND r.revision=e.revision AND e.boot=r.boot AND r.boot=? AND r.namespace=?
        """, (Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
              str(os.stat("/proc/self/ns/net").st_ino))).fetchone()
    require(receipt is not None, "Expected idle revision-2 enrollment in this boot and namespace")
    owner, resource, table_handle = receipt
    before = listing()
    expected_marker = f"nergal:v1:{UUID(owner).hex}:{UUID(resource).hex}"
    table = before[0]["table"]
    require(table == {"family": scope[0], "name": scope[1], "handle": int(table_handle),
                      "comment": expected_marker}, "Native table differs from protected receipt")
    chain = before[1]["chain"]
    require(chain == {"family": scope[0], "table": scope[1], "name": scope[2], "handle": chain["handle"],
                      "type": "filter", "hook": "input", "prio": 0, "policy": "accept"},
            "Unexpected fixture input chain")
    rule_handle(before[2], {"meta": {"key": "nfproto"}}, "ipv6")
    if action == "inject":
        require(len(before) == 3, "Expected exactly the enrolled IPv6 drop rule before injection")
        nft("add", "rule", *scope, "ip", "saddr", address, "drop")
        after = listing()
        require(len(after) == 4 and after[:-1] == before, "Unexpected table change during injection")
        print(rule_handle(after[-1], marker, address))
    elif action == "repair":
        require(len(before) == 4, "Expected exactly one extra fixture rule")
        handle = rule_handle(before[-1], marker, address)
        require(str(handle) == saved, "Saved fixture handle differs from live marker rule")
        nft("delete", "rule", *scope, "handle", str(handle))
        require(listing() == before[:-1], "Unexpected table change during fixture repair")
    else:
        sys.exit("Unknown drift fixture operation")
PY
}

agent_inject_drift() (
    # The root-only record cannot overwrite an earlier injection's evidence.
    set -C
    _ma_native_drift inject > /run/nergal-ops/drift-rule.handle
)

agent_repair_drift() {
    local record=/run/nergal-ops/drift-rule.handle handle
    IFS= read -r handle < "$record" || return 1
    [[ $handle =~ ^[1-9][0-9]{0,19}$ ]] || return 1
    _ma_native_drift repair "$handle" || return 1
    _ma_packets 1 || return 1
    rm -- "$record"
}
