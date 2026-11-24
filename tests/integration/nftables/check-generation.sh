#!/usr/bin/env bash
# This fixture has no host-namespace fallback and no production inputs.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
for tool in dotnet unshare nft ip ping python3 capsh; do
    command -v "$tool" >/dev/null || { printf 'Required tool missing: %s\n' "$tool" >&2; exit 1; }
done
unshare --user --map-root-user --net python3 -B tests/integration/nftables/generation_check.py \
    "$(realpath tests/integration/nftables/bin/Release/net10.0/Nergal.Nftables.Fixture.dll)" \
    "$(readlink /proc/self/ns/user)" "$(readlink /proc/self/ns/net)"
