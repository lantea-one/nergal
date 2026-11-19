#!/usr/bin/env bash
# Fresh user AND network namespaces are mandatory; no root/host fallback exists.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
for tool in dotnet unshare ip nft python3; do
    command -v "$tool" >/dev/null || { printf 'Required tool missing: %s\n' "$tool" >&2; exit 1; }
done
fixture="$PWD/tests/integration/watchdog/bin/Release/net10.0/Nergal.Watchdog.Fixture.dll"
[[ -f "$fixture" ]] || { printf '%s\n' 'Build the Release solution first.' >&2; exit 1; }
guard_directory=$(mktemp -d)
trap 'rm -rf "$guard_directory"' EXIT
# This read-only status invocation must fail at the guard before opening state.
if dotnet "$fixture" status "$guard_directory" "$(readlink /proc/self/ns/net)" \
    "$(readlink /proc/self/ns/user)" 00000000-0000-0000-0000-000000000001 3000 \
    >"$guard_directory/out" 2>"$guard_directory/error"; then
    printf '%s\n' 'Ordinary-host namespace guard unexpectedly accepted execution.' >&2
    exit 1
fi
grep -q 'fixture.namespaceNotIsolated' "$guard_directory/error"
printf '%s\n' 'PASS: ordinary-host execution refused before opening state'
# Each scenario receives its own user/network namespace and private temporary journal.
for scenario in before_apply after_apply watchdog_restart restore_ack confirmation foreign_state corrupt_journal missing_journal; do
    unshare --user --map-root-user --net \
        python3 tests/integration/watchdog/check.py "$fixture" "$scenario" \
        "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)"
done
