#!/usr/bin/env bash
# Fresh namespaces and synthetic protected intents only; no host enrollment or apply API.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
for tool in dotnet unshare nft ip python3; do
    command -v "$tool" >/dev/null || { printf 'Required tool missing: %s\n' "$tool" >&2; exit 1; }
done
fixture="$PWD/tests/integration/enrollment/bin/Release/net10.0/Nergal.Enrollment.Fixture.dll"
[[ -f "$fixture" ]] || { printf '%s\n' 'Build the Release solution first.' >&2; exit 1; }
for scenario in collision bound family schema1 cli cli-collision; do
    unshare --user --map-root-user --net python3 tests/integration/enrollment/check.py \
        "$fixture" "$scenario" "$(readlink /proc/self/ns/user)" "$(readlink /proc/self/ns/net)"
done
