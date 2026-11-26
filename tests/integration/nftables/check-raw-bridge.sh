#!/usr/bin/env bash
# Exercise a complete independent source and its converted bundle in fresh namespaces.
set -euo pipefail
cd "$(dirname "$0")/../../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
runner=(dotnet tests/integration/nftables/bin/Release/net10.0/Nergal.Nftables.Fixture.dll)
source=tests/integration/nftables/import-raw-bridge.nft
"${runner[@]}" import-native "$source" bundle 'Filter=inet/nergal_filter;Bridge=bridge/nergal_bridge' > "$work/candidate.nft"
for policy in "$source" "$work/candidate.nft"; do
    unshare --user --map-root-user --net python3 -B tests/integration/nftables/raw_bridge_check.py \
        "$policy" "$work" "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)"
done
"${runner[@]}" verify-raw-bridge "$work/candidate.nft" "$work/echo.json" "$work/filter.json" "$work/bridge.json"
printf '%s\n' 'PASS: raw and bridge packet outcomes, counter placement, interface rename and complete native receipts'
