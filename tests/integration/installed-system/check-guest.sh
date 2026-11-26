#!/bin/bash
set -Eeuo pipefail
umask 077

trap 'printf "Installed-system check failed at guest script line %s\n" "$LINENO" >&2' ERR
virtualization=$(systemd-detect-virt --vm)
if [[ $(hostname) != nergal-installed-test || ! $virtualization =~ ^(kvm|qemu)$ ||
      $(ls -1 /sys/class/net) != lo || ! -f /run/nergal-installed-fixture ]]; then
    printf 'Guest isolation check failed (hostname=%s vm=%s interfaces=%s)\n' \
        "$(hostname)" "$virtualization" "$(ls -1 /sys/class/net)" >&2
    exit 1
fi
media=$1
agent_state=/var/lib/nergal/agent
web_state=/var/lib/nergal/web
config=/etc/nergal/web
namespace=nergal-installed-test

diagnose() {
    result=$?
    if (( result != 0 )); then
        systemctl list-jobs --no-pager
        journalctl --no-pager -n 45 -u nergal-agent-enroll.service \
            -u nergal-agent.service -u nergal-web.service
    fi
}
trap diagnose EXIT

# shellcheck disable=SC1091
. /etc/os-release
printf 'Guest %s, kernel %s\n' "$PRETTY_NAME" "$(uname -r)"
[[ $ID == debian && $VERSION_ID == 13 ]]
test "$(passwd -S root | cut -d' ' -f2)" = L
test -x /usr/sbin/nft
/usr/sbin/nft --version
if command -v dotnet; then exit 1; fi
if dpkg-query -W nergal 2>/dev/null; then exit 1; fi
dpkg -i "$media"/runtime-debs/*.deb
/usr/bin/dotnet --list-runtimes
dpkg -i "$media/nergal.deb"
dpkg-query -W -f='${Package} ${Version} ${Status}\n' nergal
test "$(dpkg-query -W -f='${Status}' nergal)" = 'install ok installed'
test "$(stat -c '%a %U:%G' "$agent_state")" = '700 nergal-agent:nergal-agent'
test "$(stat -c '%a %U:%G' "$web_state")" = '700 nergal-web:nergal-web'
test "$(stat -c '%a %U:%G' /run/nergal)" = '2710 nergal-agent:nergal-ctl'
if systemctl is-active --quiet nergal-agent.service; then exit 1; fi
if systemctl is-active --quiet nergal-web.service; then exit 1; fi
test ! -e "$agent_state/journal.db"
printf 'Package installed with private service identities and no automatic service start or enrollment\n'

# All packet traffic and agent mutations use a separate network namespace inside the air-gapped VM.
ip netns add "$namespace"
test "$(stat -Lc %i /run/netns/"$namespace")" != "$(stat -Lc %i /proc/self/ns/net)"
ip -n "$namespace" link set lo up
test -z "$(ip netns exec "$namespace" /usr/sbin/nft list tables)"
for unit in nergal-agent-enroll nergal-agent nergal-web; do
    dropin=/run/systemd/system/$unit.service.d/fixture.conf
    install -d "${dropin%/*}"
    printf '[Service]\nNetworkNamespacePath=/run/netns/%s\n' "$namespace" > "$dropin"
done

web_uid=$(id -u nergal-web)
agent_uid=$(id -u nergal-agent)
if (( web_uid == 0 || agent_uid == 0 || web_uid == agent_uid )); then
    printf 'Package did not provision separate non-root UIDs\n' >&2
    exit 1
fi
systemctl daemon-reload
systemctl start nergal-agent-enroll.service
ip netns exec "$namespace" /usr/sbin/nft -aj list table inet nergal_filter > /run/enrolled-table.json
if systemctl start nergal-agent-enroll.service; then
    printf 'Unexpected success enrolling into an existing journal\n' >&2
    exit 1
fi
journalctl -u nergal-agent-enroll.service -o cat --no-pager > /run/enrollment-log
grep -qx journal.exists /run/enrollment-log
ip netns exec "$namespace" /usr/sbin/nft -aj list table inet nergal_filter > /run/replayed-table.json
cmp /run/enrolled-table.json /run/replayed-table.json
printf 'Repeated enrollment was denied with journal.exists and native state stayed unchanged\n'
if /usr/sbin/nft list table inet nergal_filter >/dev/null 2>&1; then
    printf 'GUARD: enrollment unexpectedly touched the guest initial namespace\n' >&2
    exit 1
fi

install -d -o nergal-web -g nergal-web -m 0700 "$web_state"/{accounts,controller,keys}
runuser -u nergal-web -- nergal-admin account init "$web_state/accounts"
runuser -u nergal-web -- nergal-admin controller init "$web_state/controller"
openssl rand -base64 32 > /run/nergal-fixture-password
runuser -u nergal-web -- nergal-admin account provision "$web_state/accounts" fixture-admin --password-stdin \
    < /run/nergal-fixture-password
for name in tls wrapping; do
    timeout 20s openssl req -x509 -newkey rsa:3072 -nodes -days 1 -subj '/CN=nergal-installed-test.invalid' \
        -addext 'subjectAltName=IP:127.0.0.1' -keyout "$config/$name.key" \
        -out "$config/$name.crt" 2>/dev/null
done
install -d -o nergal-web -g nergal-web -m 0700 "$config/private"
timeout 20s openssl pkcs12 -export -inkey "$config/wrapping.key" -in "$config/wrapping.crt" \
    -out "$config/private/wrapping.pfx" -passout pass:
rm "$config"/wrapping.{key,crt}
chown nergal-web:nergal-web "$config"/{tls.key,tls.crt,private/wrapping.pfx}
chmod 0600 "$config"/{tls.key,tls.crt,private/wrapping.pfx}
cat > "$config/env" <<EOF_ENV
ASPNETCORE_URLS=https://127.0.0.1:8443
Kestrel__Certificates__Default__Path=$config/tls.crt
Kestrel__Certificates__Default__KeyPath=$config/tls.key
LocalSessions__Enabled=true
LocalSessions__AccountDirectory=$web_state/accounts
LocalSessions__KeyDirectory=$web_state/keys
LocalSessions__CertificateFile=$config/private/wrapping.pfx
ControllerState__Enabled=true
ControllerState__Directory=$web_state/controller
EOF_ENV

printf 'Starting packaged systemd services\n'
timeout 20s systemctl enable nergal-agent.service nergal-web.service
systemctl start --no-block nergal-agent.service nergal-web.service
ip netns exec "$namespace" python3 -B "$media/check-protocol.py" https
rm /run/nergal-fixture-password
systemctl is-active --quiet nergal-agent.service
systemctl is-active --quiet nergal-web.service
agent_pid=$(systemctl show -p MainPID --value nergal-agent.service)
web_pid=$(systemctl show -p MainPID --value nergal-web.service)
test "$(awk '/^CapEff:/ {print $2}' "/proc/$agent_pid/status")" = '0000000000001000'
test "$(awk '/^CapEff:/ {print $2}' "/proc/$web_pid/status")" = '0000000000000000'
test "$(stat -c '%a %U:%G' /run/nergal/control.sock)" = '660 nergal-agent:nergal-ctl'
runuser -u nergal-web -- python3 -B - matched "$agent_uid" < "$media/check-protocol.py"
python3 -B "$media/check-protocol.py" denied "$agent_uid"
printf 'Packaged services started, HTTPS login succeeded, and Unix status enforced peer UID\n'

# Exercise a real packet denial followed by watchdog rollback with the installed agent.
agent() {
    ip netns exec "$namespace" setpriv --reuid=nergal-agent --regid=nergal-agent --init-groups \
        --inh-caps=-all,+net_admin --ambient-caps=-all,+net_admin --bounding-set=-all,+net_admin \
        --no-new-privs /usr/bin/nergal-agent "$1" "$agent_state" "${@:2}"
}
probe() {
    ip netns exec "$namespace" ping -q -c 1 -W 1 "$1" >/dev/null
}
probe 127.0.0.1
probe ::1
operation=$(cat /proc/sys/kernel/random/uuid)
watchdog=$(cat /proc/sys/kernel/random/uuid)
agent prepare "$operation" 25 drop
agent watch "$operation" "$watchdog" > /run/nergal-fixture-watch.log 2>&1 &
watch_process=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    if grep -qx WATCHING /run/nergal-fixture-watch.log; then
        break
    fi
    kill -0 "$watch_process"
    sleep .1
done
grep -qx WATCHING /run/nergal-fixture-watch.log
agent apply "$operation" "$watchdog"
for address in 127.0.0.1 ::1; do
    probe_result=0
    probe "$address" || probe_result=$?
    if (( probe_result != 1 )); then
        printf 'Expected packet timeout for %s, received ping status %s\n' "$address" "$probe_result" >&2
        exit 1
    fi
done
wait "$watch_process"
grep -qx RolledBack /run/nergal-fixture-watch.log
probe 127.0.0.1
probe ::1
runuser -u nergal-web -- python3 -B - matched "$agent_uid" < "$media/check-protocol.py"
printf 'Packaged agent blocked IPv4 and IPv6 loopback packets and the independent watchdog restored them\n'
ip netns exec "$namespace" python3 -B "$media/check-protocol.py" assets
