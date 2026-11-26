#!/usr/bin/env bash
# Run handwritten input and its imported candidate in independent, empty user/network namespaces.
set -euo pipefail
cd "$(dirname "$0")/../../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
runner=(dotnet tests/integration/nftables/bin/Release/net10.0/Nergal.Nftables.Fixture.dll)
source=tests/integration/nftables/import-hop-rate.nft
"${runner[@]}" import-native "$source" bundle 'Filter=inet/source_filter;Auxiliary=inet/source_early' > "$work/candidate.nft"
for policy in "$source" "$work/candidate.nft"; do
    unshare --user --map-root-user --net bash -euc '
        [[ "$(readlink /proc/self/ns/net)" != "$3" && "$(readlink /proc/self/ns/user)" != "$4" ]]
        ip link set lo up
        nft -a -j -e -f "$1" > "$2/echo.json"
        python3 - <<PY
import socket
import time

def probe(addr, port, expected, *, hop=None, source=None):
    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as rx, socket.socket(family, socket.SOCK_DGRAM) as tx:
        rx.bind((addr, port))
        if source:
            tx.bind((source, 0))
        if hop is not None:
            tx.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, hop)
        rx.settimeout(0.1)
        tx.sendto(b"probe", (addr, port))
        try:
            received = rx.recv(16) == b"probe"
        except TimeoutError:
            received = False
        assert received == expected, (addr, port, hop, source, received)

probe("::1", 19300, True, hop=255)
probe("::1", 19300, False, hop=254)
probe("127.0.0.1", 19300, False)
# An earlier hop-limit miss must leave the sole token available.
probe("::1", 19303, False, hop=41)
probe("::1", 19303, True, hop=42)
probe("::1", 19303, False, hop=42)
# A single burst is shared across families and source addresses.
probe("::1", 19301, True)
probe("127.0.0.1", 19301, True)
probe("127.0.0.1", 19301, False, source="127.0.0.2")
probe("::1", 19301, False)
# A second rule has an independent bucket and refills at the declared rate.
probe("127.0.0.1", 19302, True)
probe("::1", 19302, False)
time.sleep(1.05)
probe("::1", 19302, True)
PY
        if [[ "$1" == "$2/candidate.nft" ]]; then
            nft -a -j list table inet nergal_filter > "$2/filter.json"
            nft -a -j list table inet nergal_aux > "$2/aux.json"
        fi
    ' -- "$policy" "$work" "$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/user)"
done
"${runner[@]}" verify-filter-calls "$work/candidate.nft" "$work/echo.json" "$work/filter.json" "$work/aux.json"
