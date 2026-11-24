#!/usr/bin/env bash
# Synthetic objects in fresh namespaces only. No host fallback or configuration inputs.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
dll=$(realpath tests/integration/nftables/bin/Release/net10.0/Nergal.Nftables.Fixture.dll)
dotnet "$dll" native-static-sets > "$fixture/candidate.nft"
unshare --user --map-root-user --net python3 -B tests/integration/nftables/native_static_sets_check.py \
    "$fixture" "$(readlink /proc/self/ns/user)" "$(readlink /proc/self/ns/net)"
dotnet "$dll" verify-native-static-sets "$fixture/echo.json" "$fixture/filter.json" "$fixture/nat.json" "$fixture/bridge.json" "$fixture/aux.json"
printf 'PASS: native static set definitions, contents, handles and lookup references round-trip in all four owned tables\n'
# Reuse the actual routed dual-stack DNAT/SNAT packet fixture with native address/port references.
dotnet "$dll" named-nat-filter > "$fixture/nat-filter.nft"
dotnet "$dll" named-nat > "$fixture/nat.nft"
dotnet "$dll" named-nat-negated > "$fixture/nat-negated.nft"
unshare --user --map-root-user --net python3 -B tests/integration/nftables/nat_check.py \
    "$fixture/nat-filter.nft" "$fixture/nat.nft" \
    "$fixture/nat-filter-echo.json" "$fixture/nat-filter-list.json" "$fixture/nat-echo.json" "$fixture/nat-list.json" \
    "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)" "$fixture/nat-negated.nft"
dotnet "$dll" named-verify-nat "$fixture/nat-filter-echo.json" "$fixture/nat-filter-list.json" "$fixture/nat-echo.json" "$fixture/nat-list.json"
dotnet "$dll" named-verify-nat-negated "$fixture/nat-echo.json.negated" "$fixture/nat-list.json.negated"
dotnet "$dll" named-pinned > "$fixture/pinned.nft"
unshare --user --map-root-user --net python3 -B tests/integration/nftables/pinned_check.py \
    "$fixture/pinned.nft" "$fixture/pinned-echo.json" "$fixture/pinned-list.json" \
    "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)"
dotnet "$dll" named-verify-pinned "$fixture/pinned-echo.json" "$fixture/pinned-list.json"
dotnet "$dll" named-router > "$fixture/router.nft"
unshare --user --map-root-user --net python3 -B tests/integration/nftables/router_check.py \
    "$fixture/router.nft" "$fixture/router-echo.json" "$fixture/router-list.json" "$fixture/router-terse.json" \
    "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)"
dotnet "$dll" named-verify-router "$fixture/router-echo.json" "$fixture/router-list.json" "$fixture/router-terse.json"
for kind in singleton prefix; do
    dotnet "$dll" native-low-ipv6 "$kind" > "$fixture/low-$kind.nft"
    unshare --user --map-root-user --net python3 -B tests/integration/nftables/native_low_ipv6_check.py \
        "$fixture/low-$kind.nft" "$fixture/low-$kind-echo.json" "$fixture/low-$kind-list.json" \
        "$(readlink /proc/self/ns/user)" "$(readlink /proc/self/ns/net)"
    dotnet "$dll" verify-native-low-ipv6 "$fixture/low-$kind-echo.json" "$fixture/low-$kind-list.json" "$kind"
done
