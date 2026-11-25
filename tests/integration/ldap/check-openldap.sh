#!/usr/bin/env bash
# A fresh synthetic directory and CA for each opt-in Release test run.
set -euo pipefail
fixture=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$fixture/../../.."
mode=${1:-all}
if [[ $# -gt 1 || ( $mode != all && $mode != --check-directory && $mode != --check-web ) ]]; then
    echo "Usage: $0 [--check-directory|--check-web]" >&2
    exit 2
fi
for tool in docker openssl python3 timeout; do
    command -v "$tool" >/dev/null || { echo "Missing fixture prerequisite: $tool" >&2; exit 2; }
done
if [[ $mode != --check-directory ]]; then
    command -v dotnet >/dev/null || { echo 'Missing fixture prerequisite: dotnet' >&2; exit 2; }
fi

umask 077
work=$(mktemp -d /tmp/nergal-ldap.XXXXXXXX)
container="${work##*/}"
cleanup() {
    local result=$?
    if (( result != 0 )); then
        timeout 5s docker logs "$container" 2>/dev/null || true
    fi
    timeout 10s docker rm -f "$container" >/dev/null 2>&1 || true
    rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

port=$(python3 - <<'PY'
import socket

with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PY
)
mkdir "$work/keys" "$work/empty-certs" "$work/runtime"
for ca in ca unrelated; do
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
        -subj "/CN=Nergal Synthetic LDAP $ca" \
        -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
        -keyout "$work/$ca.key" -out "$work/keys/$ca.pem" 2>"$work/openssl.log" || { cat "$work/openssl.log" >&2; exit 1; }
done
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=directory.example.test' \
    -keyout "$work/keys/peer.key" -out "$work/peer.csr" 2>"$work/openssl.log" || { cat "$work/openssl.log" >&2; exit 1; }
cat > "$work/peer.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:directory.example.test,IP:127.0.0.1
EOF
openssl x509 -req -in "$work/peer.csr" -CA "$work/keys/ca.pem" -CAkey "$work/ca.key" \
    -CAcreateserial -days 1 -sha256 -extfile "$work/peer.ext" -out "$work/keys/peer.pem"

BUILDX_CONFIG="$work/buildx" timeout --kill-after=10s 300s \
    docker build --iidfile "$work/image-id" "$fixture"
# Docker host networking adds no published ports or firewall rules. The sole server
# listener is loopback, the config is synthetic, and the database lives in tmpfs.
timeout --kill-after=5s 30s docker run --detach --name "$container" --network host \
    --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --read-only \
    --tmpfs /directory:rw,noexec,nosuid,nodev,mode=1777 \
    --mount "type=bind,source=$work/keys,target=/fixture,readonly" \
    "$(cat "$work/image-id")" "$port" >/dev/null

ready=0
for _ in {1..30}; do
    if timeout 2s openssl s_client -connect "127.0.0.1:$port" -servername directory.example.test \
        -verify_hostname directory.example.test -verify_return_error -CAfile "$work/keys/ca.pem" \
        -brief </dev/null >"$work/tls.log" 2>&1; then
        ready=1
        break
    fi
    sleep 0.2
done
if (( ready == 0 )); then
    cat "$work/tls.log" >&2
    echo 'The synthetic LDAPS listener failed its TLS readiness check.' >&2
    exit 1
fi

search() {
    timeout --kill-after=2s 8s docker exec --env LDAPTLS_CACERT=/fixture/ca.pem \
        --env LDAPTLS_REQCERT=demand "$container" ldapsearch -LLL -x -o ldif-wrap=no \
        -H "ldaps://127.0.0.1:$port" "$@"
}
base=dc=example,dc=test
administrator="cn=Fixture Administrator,ou=people,$base"
search -D "$administrator" -w fixture-user-password -b "$administrator" -s base \
    '(objectClass=*)' entryUUID > "$work/self.ldif"
grep -Fx 'entryUUID: 26fccabb-d580-4e59-b2ce-4a6aa8eb4a5b' "$work/self.ldif"
search -D "cn=reader,$base" -w fixture-reader-password -b "$base" \
    '(uid=administrator)' entryUUID > "$work/referral.ldif"
grep -Fx "dn: $administrator" "$work/referral.ldif"
grep -F "ldaps://127.0.0.1:$port/ou=people,$base" "$work/referral.ldif" || {
    echo 'The broad LDAP search did not return the seeded search reference.' >&2
    cat "$work/referral.ldif" >&2
    exit 1
}
referral_status=0
search -D "cn=reader,$base" -w fixture-reader-password -b "ou=referral,$base" \
    '(uid=administrator)' entryUUID > "$work/direct-referral.log" 2>&1 || referral_status=$?
if (( referral_status != 10 )); then
    cat "$work/direct-referral.log" >&2
    echo "Expected LDAP referral result (10), got $referral_status." >&2
    exit 1
fi
echo 'Synthetic LDAPS bind, self UUID lookup, referral result and search reference verified.'
if [[ $mode == --check-directory ]]; then
    exit 0
fi

export NERGAL_LDAP_FIXTURE_PORT=$port
export SSL_CERT_DIR="$work/empty-certs" XDG_RUNTIME_DIR="$work/runtime"
check_web() {
    SSL_CERT_FILE="$work/keys/ca.pem" timeout --kill-after=10s 180s python3 -B "$fixture/check-web.py"
}
if [[ $mode == --check-web ]]; then
    check_web
    exit 0
fi

run_tests() {
    timeout --kill-after=10s 120s dotnet test tests/Nergal.Web.Tests/Nergal.Web.Tests.csproj \
        --configuration Release --no-build --no-restore --filter "$1" \
        --results-directory "$work/results" --logger "trx;LogFileName=$2.trx"
    python3 - "$work/results/$2.trx" <<'PY'
import sys
import xml.etree.ElementTree as ET

counters = ET.parse(sys.argv[1]).find(".//{*}Counters")
if counters is None or not (0 < int(counters.attrib["total"]) == int(counters.attrib["passed"])):
    sys.exit("The opt-in LDAPS filter did not run and pass its selected tests.")
PY
}
suite='FullyQualifiedName~Nergal.Web.Tests.LdapDirectoryIntegrationTests'
SSL_CERT_FILE="$work/keys/ca.pem" \
    NERGAL_LDAP_FIXTURE_TLS_CERTIFICATE="$work/keys/peer.pem" \
    NERGAL_LDAP_FIXTURE_TLS_KEY="$work/keys/peer.key" \
    run_tests "($suite&FullyQualifiedName!~DeniesUntrustedPeer)|FullyQualifiedName~LdapWireLoopbackTests|FullyQualifiedName~RecoveryLdapDirectoryIntegrationTests" trusted
# X509 chain trust can be cached by the runtime, so use a second test host.
SSL_CERT_FILE="$work/keys/unrelated.pem" run_tests "$suite&FullyQualifiedName~DeniesUntrustedPeer" untrusted

check_web
