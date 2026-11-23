#!/usr/bin/env bash
# Disposable namespaces only; no host firewall fallback.
set -euo pipefail
cd "$(dirname "$0")/../../.."
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
runner=(dotnet tests/integration/nftables/bin/Release/net10.0/Nergal.Nftables.Fixture.dll)
for mode in router-packets router-packet-nat router-packet-nat-disabled-return router-packet-nat-source-miss router-packet-nat-destination-miss router-packet-nat-negated router-constructs router-nat router-bridge router-auxiliary; do
    "${runner[@]}" "$mode" > "$fixture/$mode.nft"
done
unshare --user --map-root-user --net python3 tests/integration/nftables/router_constructs_check.py \
    "$fixture/router-packets.nft" "$fixture/router-packet-nat.nft" \
    "$fixture/router-constructs.nft" "$fixture/router-nat.nft" "$fixture" \
    "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)"
"${runner[@]}" verify-constructs "$fixture/filter-echo.json" "$fixture/filter-list.json" "$fixture/nat-echo.json" "$fixture/nat-list.json"
"${runner[@]}" verify-postrouting-sets "$fixture/packet-nat-echo.json" "$fixture/packet-nat-list.json"
# Dedicated packet/agent acceptance runs through enrollment/check-auxiliary-apply.sh.
unshare --user --map-root-user --net nft --check -f "$fixture/router-bridge.nft"
unshare --user --map-root-user --net nft --check -f "$fixture/router-auxiliary.nft"
printf 'PASS: native echo/list reconstruction and bridge/auxiliary syntax\n'
