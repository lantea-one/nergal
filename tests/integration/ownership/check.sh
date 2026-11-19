#!/usr/bin/env bash
# All native observations and mutations occur in fresh disposable namespaces.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
for tool in dotnet unshare nft python3; do
    command -v "$tool" >/dev/null || { printf 'Required tool missing: %s\n' "$tool" >&2; exit 1; }
done
fixture="$PWD/tests/integration/ownership/bin/Release/net10.0/Nergal.Ownership.Fixture.dll"
[[ -f "$fixture" ]] || { printf '%s\n' 'Build the Release solution first.' >&2; exit 1; }
unshare --user --map-root-user --net python3 tests/integration/ownership/check.py \
    "$fixture" "$(readlink /proc/self/ns/user)" "$(readlink /proc/self/ns/net)"
