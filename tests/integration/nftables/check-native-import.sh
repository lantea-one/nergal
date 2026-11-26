#!/usr/bin/env bash
# Compare independently authored native inputs and imported intent using real packets in disposable namespaces.
set -euo pipefail
cd "$(dirname "$0")/../../.."
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
runner=(dotnet tests/integration/nftables/bin/Release/net10.0/Nergal.Nftables.Fixture.dll)
filter_binding='Filter=inet/nergal_filter'
bindings="$filter_binding;Nat=inet/nergal_nat"
{
    printf '%s\n' 'destroy table inet nergal_filter' 'destroy table inet nergal_nat'
    cat tests/integration/nftables/import-router-filter.nft tests/integration/nftables/import-router-nat.nft
} > "$fixture/independent-source.nft"
"${runner[@]}" import-native "$fixture/independent-source.nft" filter "$bindings" --restrict-cleanup > "$fixture/imported-filter.nft"
"${runner[@]}" import-native "$fixture/independent-source.nft" nat "$bindings" --restrict-cleanup > "$fixture/imported-nat.nft"
# Additional variants exercise existing independent negation/return packet assertions after native re-import.
for mode in router-packet-nat-disabled-return router-packet-nat-source-miss router-packet-nat-destination-miss router-packet-nat-negated router-nat; do
    "${runner[@]}" "$mode" > "$fixture/original-$mode.nft"
    cat tests/integration/nftables/import-router-filter.nft "$fixture/original-$mode.nft" > "$fixture/combined.nft"
    "${runner[@]}" import-native "$fixture/combined.nft" nat "$bindings" > "$fixture/$mode.nft"
done
"${runner[@]}" router-constructs > "$fixture/original-filter.nft"
"${runner[@]}" import-native "$fixture/original-filter.nft" filter "$filter_binding" > "$fixture/roundtrip-filter.nft"
for variant in independent imported; do
    if [[ "$variant" == independent ]]; then
        filter=tests/integration/nftables/import-router-filter.nft
        nat=tests/integration/nftables/import-router-nat.nft
    else
        filter="$fixture/imported-filter.nft"
        nat="$fixture/imported-nat.nft"
    fi
    unshare --user --map-root-user --net python3 -B tests/integration/nftables/router_constructs_check.py \
        "$filter" "$nat" "$fixture/roundtrip-filter.nft" "$fixture/router-nat.nft" "$fixture" \
        "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)"
done
printf 'PASS: independent native/imported dual-stack packets, MAC+IP pinning, raw/FIB/DHCP, SYN MSS, destination meters and ordered NAT exemptions\n'
"${runner[@]}" import-native tests/integration/nftables/import-meter-expiry.nft filter 'Filter=inet/expiry_source' > "$fixture/imported-expiry.nft"
for source in tests/integration/nftables/import-meter-expiry.nft "$fixture/imported-expiry.nft"; do
    unshare --user --map-root-user --net python3 -B tests/integration/nftables/meter_expiry_check.py \
        "$source" "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)"
done
