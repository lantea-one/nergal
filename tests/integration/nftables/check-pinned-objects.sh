#!/usr/bin/env bash
# No host namespace fallback or production state; synthetic pinned snapshots only.
set -euo pipefail
cd "$(dirname "$0")/../../.."
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
dotnet tests/integration/nftables/bin/Release/net10.0/Nergal.Nftables.Fixture.dll pinned > "$fixture/policy.nft"
unshare --user --map-root-user --net python3 tests/integration/nftables/pinned_check.py \
  "$fixture/policy.nft" "$fixture/echo.json" "$fixture/list.json" \
  "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)"
dotnet tests/integration/nftables/bin/Release/net10.0/Nergal.Nftables.Fixture.dll verify-pinned "$fixture/echo.json" "$fixture/list.json"
