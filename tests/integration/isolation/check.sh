#!/usr/bin/env bash
# Existing subordinate-ID mappings only. Never create/change host accounts or groups.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
for tool in dotnet unshare newuidmap newgidmap python3; do
    command -v "$tool" >/dev/null || { printf 'Required tool missing: %s\n' "$tool" >&2; exit 1; }
done
fixture="$PWD/tests/integration/isolation/bin/Release/net10.0/Nergal.Isolation.Fixture.dll"
[[ -f "$fixture" ]] || { printf '%s\n' 'Build the Release solution first.' >&2; exit 1; }
unshare --user --map-auto --map-root-user --net \
    python3 tests/integration/isolation/check.py "$fixture" \
    "$(readlink /proc/self/ns/user)" "$(readlink /proc/self/ns/net)"
