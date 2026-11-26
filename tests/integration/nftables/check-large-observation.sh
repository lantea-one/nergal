#!/usr/bin/env bash
# Large native evidence is collected only from an isolated synthetic ruleset.
set -euo pipefail
cd "$(dirname "$0")/../../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
runner=(dotnet tests/integration/nftables/bin/Release/net10.0/Nergal.Nftables.Fixture.dll)
"${runner[@]}" large-observation > "$work/candidate.nft"
unshare --user --map-root-user --net bash -euc '
    [[ "$(readlink /proc/self/ns/net)" != "$2" && "$(readlink /proc/self/ns/user)" != "$3" ]]
    ip link set lo up
    nft --check --file "$1/candidate.nft"
    nft --echo --handle --json --file "$1/candidate.nft" > "$1/echo.json"
    nft --terse --json list table inet nergal_filter > "$1/filter.json"
    nft --terse --json list table inet nergal_nat > "$1/nat.json"
    python3 - <<PY
import socket
for port, allowed in ((20289, True), (20290, False)):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        server.bind(("127.0.0.1", port))
        server.settimeout(0.5)
        client.sendto(b"large", ("127.0.0.1", port))
        try:
            received = server.recv(32) == b"large"
        except TimeoutError:
            received = False
        assert received == allowed
PY
' -- "$work" "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)"
"${runner[@]}" verify-large-observation "$work/candidate.nft" "$work/echo.json" "$work/filter.json" "$work/nat.json"
printf '%s\n' 'PASS: native creation and listing exceed 64 KiB, reconstruct identical receipts, and detect late handle drift'
