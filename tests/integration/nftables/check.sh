#!/usr/bin/env bash
# There is deliberately no privileged or host-namespace fallback.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
for tool in dotnet unshare ip nft python3 ping; do
    command -v "$tool" >/dev/null || { printf 'Required tool missing: %s\n' "$tool" >&2; exit 1; }
done
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
dotnet run --project tests/integration/nftables/Nergal.Nftables.Fixture.csproj \
    --configuration Release --no-build --no-restore -- schema1 > "$fixture/candidate.nft"
unshare --user --map-root-user --net \
    python3 tests/integration/nftables/check.py "$fixture/candidate.nft" \
    "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)"
dotnet run --project tests/integration/nftables/Nergal.Nftables.Fixture.csproj \
    --configuration Release --no-build --no-restore -- router > "$fixture/router.nft"
unshare --user --map-root-user --net \
    python3 tests/integration/nftables/router_check.py "$fixture/router.nft" \
    "$fixture/router-echo.json" "$fixture/router-list.json" "$fixture/router-terse.json" \
    "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)"
dotnet run --project tests/integration/nftables/Nergal.Nftables.Fixture.csproj \
    --configuration Release --no-build --no-restore -- verify-router \
    "$fixture/router-echo.json" "$fixture/router-list.json" "$fixture/router-terse.json"
dotnet run --project tests/integration/nftables/Nergal.Nftables.Fixture.csproj \
    --configuration Release --no-build --no-restore -- nat-filter > "$fixture/nat-filter.nft"
dotnet run --project tests/integration/nftables/Nergal.Nftables.Fixture.csproj \
    --configuration Release --no-build --no-restore -- nat > "$fixture/nat.nft"
unshare --user --map-root-user --net \
    python3 tests/integration/nftables/nat_check.py \
    "$fixture/nat-filter.nft" "$fixture/nat.nft" \
    "$fixture/nat-filter-echo.json" "$fixture/nat-filter-list.json" \
    "$fixture/nat-echo.json" "$fixture/nat-list.json" \
    "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)"
dotnet run --project tests/integration/nftables/Nergal.Nftables.Fixture.csproj \
    --configuration Release --no-build --no-restore -- verify-nat \
    "$fixture/nat-filter-echo.json" "$fixture/nat-filter-list.json" \
    "$fixture/nat-echo.json" "$fixture/nat-list.json"
dotnet run --project tests/integration/nftables/Nergal.Nftables.Fixture.csproj \
    --configuration Release --no-build --no-restore -- bundle-create > "$fixture/bundle-v1.nft"
dotnet run --project tests/integration/nftables/Nergal.Nftables.Fixture.csproj \
    --configuration Release --no-build --no-restore -- bundle-replace > "$fixture/bundle-v2.nft"
unshare --user --map-root-user --net \
    python3 tests/integration/nftables/bundle_check.py \
    "$fixture/bundle-v1.nft" "$fixture/bundle-v2.nft" \
    "$fixture/bundle-filter-list.json" "$fixture/bundle-bridge-list.json" \
    "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)"
dotnet run --project tests/integration/nftables/Nergal.Nftables.Fixture.csproj \
    --configuration Release --no-build --no-restore -- verify-bundle \
    "$fixture/bundle-filter-list.json" "$fixture/bundle-bridge-list.json"
