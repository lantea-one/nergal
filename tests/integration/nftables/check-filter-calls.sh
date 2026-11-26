#!/usr/bin/env bash
# Exercise the independently written source and the imported candidate in separate namespaces.
set -euo pipefail
cd "$(dirname "$0")/../../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
runner=(dotnet tests/integration/nftables/bin/Release/net10.0/Nergal.Nftables.Fixture.dll)
source=tests/integration/nftables/import-filter-calls.nft
"${runner[@]}" import-native "$source" bundle 'Filter=inet/source_filter;Auxiliary=inet/source_early' > "$work/candidate.nft"
for policy in "$source" "$work/candidate.nft"; do
    unshare --user --map-root-user --net bash -euc '
        [[ "$(readlink /proc/self/ns/net)" != "$3" && "$(readlink /proc/self/ns/user)" != "$4" ]]
        ip link set lo up
        nft --echo --handle --json --file "$1" > "$2/echo.json"
        if [[ "$1" == "$2/candidate.nft" ]]; then
            nft --terse --json list table inet nergal_filter > "$2/filter.json"
            nft --terse --json list table inet nergal_aux > "$2/aux.json"
        fi
        python3 - <<PY
import socket
for family, addr in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
    for port, allowed in [(19101, False), (19102, True), (19103, True), (19104, False), (19105, False)]:
        with socket.socket(family, socket.SOCK_DGRAM) as receiver, socket.socket(family, socket.SOCK_DGRAM) as sender:
            receiver.bind((addr, port))
            receiver.settimeout(0.4)
            sender.sendto(b"call", (addr, port))
            try:
                received = receiver.recv(16) == b"call"
            except TimeoutError:
                received = False
            assert received == allowed, (family, port, received)
PY
    ' -- "$policy" "$work" "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)"
done
"${runner[@]}" verify-filter-calls "$work/candidate.nft" "$work/echo.json" "$work/filter.json" "$work/aux.json"
