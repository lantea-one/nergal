#!/usr/bin/env bash
# No host namespace fallback, production data or foreign mutations.
set -euo pipefail
cd "$(dirname "$0")/../../.."
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
for mode in state-accept-on state-accept-off state-drop-on state-drop-off; do
  dotnet tests/integration/nftables/bin/Release/net10.0/Nergal.Nftables.Fixture.dll "$mode" > "$fixture/$mode.nft"
done
unshare --user --map-root-user --net python3 tests/integration/nftables/rule_state_check.py \
  "$fixture" "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)"
