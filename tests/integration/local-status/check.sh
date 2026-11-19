#!/usr/bin/env bash
# Existing subordinate identities in fresh user/network namespaces; no host accounts/groups or buses.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
for tool in dotnet unshare newuidmap newgidmap nft python3; do
    command -v "$tool" >/dev/null || { printf 'Required tool missing: %s\n' "$tool" >&2; exit 1; }
done
fixture="$PWD/tests/integration/local-status/bin/Release/net10.0/Nergal.LocalStatus.Fixture.dll"
enrollment="$PWD/tests/integration/enrollment/bin/Release/net10.0/Nergal.Enrollment.Fixture.dll"
[[ -f "$fixture" && -f "$enrollment" ]] || { printf '%s\n' 'Build the Release solution first.' >&2; exit 1; }
unshare --user --map-auto --map-root-user --net python3 tests/integration/local-status/check.py \
    "$fixture" "$enrollment" "$(readlink /proc/self/ns/user)" "$(readlink /proc/self/ns/net)"
