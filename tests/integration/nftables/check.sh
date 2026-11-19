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
    --configuration Release --no-build --no-restore > "$fixture/candidate.nft"
unshare --user --map-root-user --net \
    python3 tests/integration/nftables/check.py "$fixture/candidate.nft" \
    "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)"
