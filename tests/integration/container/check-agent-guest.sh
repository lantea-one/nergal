#!/bin/bash
# Invoked by the installed-system hook from an offline, read-only fixture ISO.
set -Eeuo pipefail
umask 077
trap 'printf "Agent container check failed at guest script line %s\n" "$LINENO" >&2' ERR

media=${1:-}
virtualization=$(systemd-detect-virt --vm || true)
if [[ $(id -u) != 0 || $(hostname) != nergal-installed-test || ! $virtualization =~ ^(kvm|qemu)$ ||
      $(ls -1 /sys/class/net) != lo || ! -f /run/nergal-installed-fixture ||
      $media != /mnt/nergal-fixture || $(findmnt -n -o FSTYPE --mountpoint "$media") != iso9660 ]]; then
    printf 'Refusing agent container check outside the isolated fixture guest\n' >&2
    exit 1
fi

work=$(mktemp -d /var/tmp/nergal-agent-container.XXXXXXXX)
namespace=nergal-container-test
namespace_created=false
container=nergal-agent-fixture
state=/var/lib/nergal/agent
tls=/etc/nergal/agent/private
image=$(cat "$media/image-name")
readlink /proc/self/ns/net > "$work/initial-netns"
/usr/sbin/nft -aj list ruleset > "$work/initial-ruleset"

namespace_exec() {
    nsenter --net="/run/netns/$namespace" -- "$@"
}

docker() {
    namespace_exec "$work/docker/docker" --host "unix://$work/docker.sock" "$@"
}

compose() {
    docker compose --file "$media/agent.yml" --project-name nergal-agent-fixture "$@"
}

finish() {
    local code=$?
    if (( code != 0 )); then
        docker logs "$container" 2>&1 || true
        tail -n 50 "$work/dockerd.log" || true
    fi
    if [[ -n ${daemon_pid:-} ]]; then
        docker rm -f "$container" >/dev/null 2>&1 || true
        kill "$daemon_pid" 2>/dev/null || true
        wait "$daemon_pid" || true
    fi
    if [[ $namespace_created == true ]]; then
        ip netns del "$namespace" 2>/dev/null || true
    fi
}
trap finish EXIT

ip netns add "$namespace"
namespace_created=true
ip -n "$namespace" link set lo up
namespace_exec readlink /proc/self/ns/net > "$work/fixture-netns"
test "$(cat "$work/initial-netns")" != "$(cat "$work/fixture-netns")"
test "$(ip -n "$namespace" -o link show | awk -F ': ' '{print $2}')" = lo
namespace_exec /usr/sbin/nft -aj list ruleset > "$work/empty-ruleset"
test -z "$(namespace_exec /usr/sbin/nft list tables)"

tar --extract --gzip --file "$media/docker.tgz" --directory "$work" --no-same-owner \
    docker/{containerd,containerd-shim-runc-v2,docker,docker-init,docker-proxy,dockerd,runc}
export PATH="$work/docker:$PATH"
export DOCKER_CONFIG="$work/docker-config"
unset DOCKER_CONTEXT DOCKER_HOST
mkdir -p "$DOCKER_CONFIG/cli-plugins"
if [[ -f $media/docker-compose ]]; then
    install -m 0755 "$media/docker-compose" "$DOCKER_CONFIG/cli-plugins/docker-compose"
fi
printf '{}\n' > "$work/daemon.json"
# Join only the network namespace so dockerd retains the guest's cgroup mounts.
nsenter --net="/run/netns/$namespace" -- "$work/docker/dockerd" --config-file "$work/daemon.json" \
    --host "unix://$work/docker.sock" --pidfile "$work/dockerd.pid" \
    --data-root "$work/data" --exec-root "$work/exec" --bridge=none \
    --iptables=false --ip6tables=false --userland-proxy=false \
    > "$work/dockerd.log" 2>&1 &
daemon_pid=$!
ready_by=$((SECONDS + 60))
until docker version --format '{{.Server.Version}}' 2>/dev/null; do
    kill -0 "$daemon_pid"
    (( SECONDS < ready_by ))
    sleep .2
done
readlink "/proc/$daemon_pid/ns/net" | cmp "$work/fixture-netns" -
docker image load --input "$media/agent.tar"

install -d -m 0700 -o 1654 -g 1654 "$work"/{state,denied-state,tls}
export NERGAL_AGENT_IMAGE="$image" NERGAL_AGENT_STATE_DIR="$work/state" NERGAL_AGENT_TLS_DIR="$work/tls"
docker_flags=(--pull never --user 0:0 --network host --read-only --cap-drop ALL
    --cap-add SETUID --cap-add SETGID --cap-add SETPCAP --security-opt no-new-privileges:true
    --tmpfs '/tmp:rw,noexec,nosuid,nodev,mode=0700,uid=1654,gid=1654,size=64m'
    --mount "type=bind,src=$work/tls,dst=$tls,readonly")

agent() {
    if [[ -f $media/agent.yml ]]; then
        compose run --no-deps --pull never --rm agent "$@"
    else
        docker run --rm "${docker_flags[@]}" --cap-add NET_ADMIN \
            --mount "type=bind,src=$work/state,dst=$state" "$image" "$@"
    fi
}

snapshot_rules() {
    namespace_exec /usr/sbin/nft -aj list ruleset
}

expect_denied() {
    local expected=$1 diagnostic=$2 result=0
    shift 2
    "$@" > "$work/denial.log" 2>&1 || result=$?
    cat "$work/denial.log"
    test "$result" -eq "$expected"
    grep -Fxq "$diagnostic" "$work/denial.log"
}

snapshot_rules | cmp "$work/empty-ruleset" -
docker run --rm "${docker_flags[@]}" --cap-add NET_ADMIN \
    --mount "type=bind,src=$work/state,dst=$state" "$image" > "$work/default.log"
grep -Fxq 'Usage:' "$work/default.log"
test -z "$(find "$work/state" -mindepth 1 -print -quit)"
snapshot_rules | cmp "$work/empty-ruleset" -
expect_denied 127 'setpriv: apply capabilities: Operation not permitted' \
    docker run --rm "${docker_flags[@]}" \
    --mount "type=bind,src=$work/denied-state,dst=$state" "$image" enroll "$state"
test -z "$(find "$work/denied-state" -mindepth 1 -print -quit)"
snapshot_rules | cmp "$work/empty-ruleset" -
printf 'Omitting NET_ADMIN denied enrollment before any kernel or journal write\n'

agent enroll "$state"
test "$(stat -c '%u:%g:%a' "$work/state/journal.db")" = 1654:1654:600
test "$(namespace_exec /usr/sbin/nft list tables)" = 'table inet nergal_filter'
snapshot_rules > "$work/enrolled-ruleset"
sha256sum "$work/state/journal.db" > "$work/enrolled-journal.sha256"
expect_denied 1 journal.exists agent enroll "$state"
expect_denied 1 reconcile.sameBoot agent reconcile "$state"
snapshot_rules | cmp "$work/enrolled-ruleset" -
sha256sum --check --status "$work/enrolled-journal.sha256"
/usr/sbin/nft -aj list ruleset | cmp "$work/initial-ruleset" -
printf 'Explicit enrollment created only inet nergal_filter inside the nested namespace. Repeated enroll and same-boot reconcile preserved the table and journal\n'

certificate() {
    local name=$1 usage=$2
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
        -subj "/CN=$name.nergal-fixture.invalid" -addext 'subjectAltName=IP:127.0.0.1' \
        -addext 'basicConstraints=critical,CA:FALSE' -addext 'keyUsage=critical,digitalSignature' \
        -addext "extendedKeyUsage=$usage" -keyout "$work/$name.key" -out "$work/$name.crt" \
        > /dev/null 2>&1
}
certificate server serverAuth
certificate client clientAuth
certificate unpinned clientAuth
install -o 1654 -g 1654 -m 0600 "$work"/server.{crt,key} "$work/tls/"
client_pin=$(openssl x509 -in "$work/client.crt" -outform DER | sha256sum | cut -d ' ' -f 1)
port=19443
serve=(tls-serve "$state" "127.0.0.1:$port" "$tls/server.crt" "$tls/server.key" "$client_pin")
if [[ -f $media/agent.yml ]]; then
    export NERGAL_AGENT_LISTEN="127.0.0.1:$port" NERGAL_AGENT_CLIENT_SHA256="$client_pin"
    compose run --no-deps --pull never --detach --name "$container" agent
    printf 'Started TLS using the deploy/container production agent Compose service\n'
else
    docker run --detach --name "$container" "${docker_flags[@]}" --cap-add NET_ADMIN \
        --mount "type=bind,src=$work/state,dst=$state" "$image" "${serve[@]}"
    printf 'Started TLS using the equivalent Docker run flags\n'
fi

listening() {
    test -n "$(namespace_exec ss -4Hln 'sport = :19443')"
}

wait_for_listener() {
    local ready_by=$((SECONDS + 45))
    until listening; do
        test "$(docker inspect --format '{{.State.Running}}' "$container")" = true
        (( SECONDS < ready_by ))
        sleep .2
    done
}

wait_for_listener
docker inspect --format '{{json .}}' "$container" > "$work/container.json"
python3 -B - "$work/container.json" "$work" "$state" "$tls" <<'PY'
import json
from pathlib import Path
import sys

path, work, state, tls = sys.argv[1:]
container = json.loads(Path(path).read_text())
host = container['HostConfig']
assert host['NetworkMode'] == 'host' and host['ReadonlyRootfs'] and not host['Privileged'], host
assert not host['PortBindings'] and not host['PidMode'], host
assert set(host['CapDrop']) == {'ALL'}
assert {cap.removeprefix('CAP_') for cap in host['CapAdd']} == {'NET_ADMIN', 'SETUID', 'SETGID', 'SETPCAP'}
assert {option.replace('=', ':', 1) for option in host['SecurityOpt']} == {'no-new-privileges:true'}
binds = {(mount['Source'], mount['Destination'], mount['RW'])
         for mount in container['Mounts'] if mount['Type'] == 'bind'}
assert binds == {(f'{work}/state', state, True), (f'{work}/tls', tls, False)}, binds
assert all(mount['Type'] in ('bind', 'tmpfs') for mount in container['Mounts'])
PY
pid=$(docker inspect --format '{{.State.Pid}}' "$container")
python3 -B - "$pid" "$work/fixture-netns" <<'PY'
import os
from pathlib import Path
import sys

supervisor, fixture_namespace = sys.argv[1:]
children = Path(f'/proc/{supervisor}/task/{supervisor}/children').read_text().split()
assert len(children) == 1, f'Expected one agent child, got {children}'
agent, = children
assert b'tls-serve' in Path(f'/proc/{agent}/cmdline').read_bytes().split(b'\0')
for pid in (supervisor, agent):
    assert os.readlink(f'/proc/{pid}/ns/net') == Path(fixture_namespace).read_text().strip()
    status = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines())
    for field in ('Uid', 'Gid'):
        assert status[field].split() == ['1654'] * 4, (pid, field, status[field])
    assert not status['Groups'].strip(), (pid, status['Groups'])
    for field in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
        assert int(status[field], 16) == 1 << 12, (pid, field, status[field])  # CAP_NET_ADMIN
    assert status['NoNewPrivs'].strip() == '1', (pid, status['NoNewPrivs'])
PY
printf 'Supervisor and TLS listener run as UID/GID 1654 with only CAP_NET_ADMIN and no-new-privileges\n'

tls_request() {
    namespace_exec python3 -B - "$work" "$port" "$1" <<'PY'
import json
from pathlib import Path
import socket
import ssl
import struct
import sys

directory, port, action = sys.argv[1:]
root = Path(directory)
client = 'unpinned' if action == 'denied' else 'client'
context = ssl.create_default_context(cafile=root / 'server.crt')
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(root / f'{client}.crt', root / f'{client}.key')
request = {'schemaVersion': 1, 'command': 'status'}
operation = '20000000-0000-0000-0000-000000000001'
if action == 'prepare':
    request.update(command='prepare-apply', operationId=operation, confirmationTimeoutSeconds=15,
                   policy={'schemaVersion': 1, 'inputDefaultVerdict': 'accept',
                           'forwardDefaultVerdict': 'drop', 'outputDefaultVerdict': 'drop',
                           'rules': [{'family': 'ipv6', 'protocol': 'any', 'verdict': 'drop',
                                      'chain': 'input', 'connectionStates': 0}]})
body = json.dumps(request).encode()
with socket.create_connection(('127.0.0.1', int(port)), timeout=8) as tcp:
    try:
        with context.wrap_socket(tcp, server_hostname='127.0.0.1') as conn:
            conn.sendall(struct.pack('>I', len(body)) + body)
            with conn.makefile('rb') as stream:
                header = stream.read(4)
                if not header and action == 'denied':
                    sys.exit(0)
                size, = struct.unpack('>I', header)
                assert 1 <= size <= 262_144, size
                data = stream.read(size)
                assert len(data) == size
                reply = json.loads(data)
    except (ConnectionResetError, ssl.SSLEOFError, ssl.SSLError) as error:
        if action != 'denied' or isinstance(error, ssl.SSLCertVerificationError):
            raise
        sys.exit(0)
if action == 'prepare':
    assert reply['outcome'] == 'appliedPendingConfirmation' and reply['operationId'] == operation, reply
else:
    assert action == 'status' and reply == {'schemaVersion': 1, 'outcome': 'matched', 'revision': '1'}, reply
PY
}

probe() {
    namespace_exec ping -q -c 1 -W 1 "$1" > /dev/null
}

deny_ipv6() {
    local result=0
    probe ::1 || result=$?
    test "$result" -eq 1
}

tls_request status
tls_request denied
probe 127.0.0.1
probe ::1
tls_request prepare
probe 127.0.0.1
deny_ipv6
docker stop --time 40 "$container" > "$work/stop.log" &
stop_pid=$!
closed_by=$((SECONDS + 8))
while listening; do
    kill -0 "$stop_pid"
    (( SECONDS < closed_by ))
    sleep .1
done
# The listener must be gone while the watchdog still protects a live candidate.
kill -0 "$stop_pid"
deny_ipv6
wait "$stop_pid"
test "$(docker inspect --format '{{.State.ExitCode}}' "$container")" -eq 0
probe 127.0.0.1
probe ::1
docker start "$container"
wait_for_listener
tls_request status
/usr/sbin/nft -aj list ruleset | cmp "$work/initial-ruleset" -
printf 'Pinned mTLS applied a synthetic IPv6 drop. Graceful Docker stop closed the listener before the watchdog restored packets and revision 1\n'
printf 'NERGAL_AGENT_CONTAINER_PASS\n'
