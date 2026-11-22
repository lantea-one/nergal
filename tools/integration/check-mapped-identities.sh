#!/usr/bin/env bash
# Container-local subordinate IDs and nested disposable namespaces; no host identities or firewall mounts.
set -euo pipefail
cd "$(dirname "$0")/../.."
root=$PWD
sdk=$(dirname "$(readlink -f "$(command -v dotnet)")")
[[ $(dotnet --version) == 10.0.404 ]] || { printf 'Use the SDK pinned in global.json.\n' >&2; exit 1; }
[[ -f tests/integration/local-status/bin/Release/net10.0/Nergal.LocalStatus.Fixture.dll ]] || {
    printf 'Build the Release solution first.\n' >&2; exit 1;
}
export BUILDX_CONFIG="$root/artifacts/integration-buildx"
mkdir -p "$BUILDX_CONFIG"
docker build -f tools/integration/Dockerfile -t nergal-integration:local tools/integration
# SYS_ADMIN + the relaxed container seccomp profile permit nested user/network namespaces.
# No writable host mounts, published ports, production exports, bus, or Docker socket.
docker run --rm --network none --read-only --user 1000:1000 --pids-limit 512 --memory 2g \
    --cap-add SYS_ADMIN --security-opt seccomp=unconfined \
    --tmpfs /tmp:rw,exec,nosuid,mode=1777,size=2g \
    --mount "type=bind,src=$root/src,dst=/workspace/src,readonly" \
    --mount "type=bind,src=$root/tests,dst=/workspace/tests,readonly" \
    --mount "type=bind,src=$sdk,dst=/opt/dotnet,readonly" \
    nergal-integration:local bash -euc '
        bash tests/integration/isolation/check.sh
        bash tests/integration/local-status/check.sh
    '
