#!/usr/bin/env bash
# Existing subordinate identities in fresh user/network namespaces; no host accounts/groups or buses.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
for tool in dotnet unshare newuidmap newgidmap nft ip openssl python3; do
    command -v "$tool" >/dev/null || { printf 'Required tool missing: %s\n' "$tool" >&2; exit 1; }
done
fixture="$PWD/tests/integration/local-status/bin/Release/net10.0/Nergal.LocalStatus.Fixture.dll"
enrollment="$PWD/tests/integration/enrollment/bin/Release/net10.0/Nergal.Enrollment.Fixture.dll"
agent="$PWD/src/Nergal.Agent/bin/Release/net10.0/nergal-agent.dll"
[[ -f "$fixture" && -f "$enrollment" && -f "$agent" ]] || { printf '%s\n' 'Build the Release solution first.' >&2; exit 1; }
unshare --user --map-auto --map-root-user --net python3 -B tests/integration/local-status/check.py \
    "$fixture" "$enrollment" "$(readlink /proc/self/ns/user)" "$(readlink /proc/self/ns/net)"
unshare --user --map-auto --map-root-user --net python3 -B tests/integration/local-status/client-check.py \
    "$fixture" "$(readlink /proc/self/ns/user)" "$(readlink /proc/self/ns/net)"
unshare --user --map-auto --map-root-user --net python3 -B tests/integration/local-status/control-check.py \
    "$agent" "$(readlink /proc/self/ns/user)" "$(readlink /proc/self/ns/net)"
