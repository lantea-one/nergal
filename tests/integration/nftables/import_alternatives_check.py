"""Check disjoint native selectors against real packets in a disposable namespace."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys


def run(*command):
    subprocess.run(command, check=True, capture_output=True, timeout=3)


if len(sys.argv) != 4 or os.getuid() != 0:
    raise SystemExit("Invoke with namespace-local root through the integration launcher")
if os.readlink("/proc/self/ns/net") == sys.argv[2] or os.readlink("/proc/self/ns/user") == sys.argv[3]:
    raise SystemExit("Refusing to test in the caller's namespace")

run("ip", "link", "set", "lo", "up")
for address in ("192.0.2.1/32", "192.0.2.2/32", "2001:db8::1/128", "2001:db8::2/128"):
    run("ip", "address", "add", address, "dev", "lo", "nodad")
run("nft", "--file", str(Path(sys.argv[1])))


def admitted(family, kind, source, target, port):
    with socket.socket(family, kind) as server, socket.socket(family, kind) as client:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(0.4)
        client.settimeout(0.4)
        server.bind((target, port))
        client.bind((source, 0))
        try:
            if kind == socket.SOCK_STREAM:
                server.listen()
                client.connect((target, port))
                connection, _ = server.accept()
                connection.close()
            else:
                client.sendto(b"fixture", (target, port))
                assert server.recv(64) == b"fixture"
        except TimeoutError:
            return False
    return True


for family, flag, address, blocked in (
    (socket.AF_INET, "-4", "192.0.2.1", "192.0.2.2"),
    (socket.AF_INET6, "-6", "2001:db8::1", "2001:db8::2"),
):
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        assert admitted(family, kind, address, address, 19042), "Allowed transport or family was omitted"
        assert not admitted(family, kind, blocked, address, 19042), "Earlier drop lost its order"
        assert not admitted(family, kind, address, address, 19043), "Unselected port was admitted"
    run("ping", flag, "-n", "-c", "1", "-W", "1", address)
    assert not admitted(family, socket.SOCK_DGRAM, address, address, 19044), "Tracked packet matched untracked"
    with socket.socket(family, socket.SOCK_DGRAM) as server, socket.socket(family, socket.SOCK_DGRAM) as client:
        server.settimeout(0.4)
        server.bind((address, 19046))
        client.bind((address, 0))
        client.sendto(b"output-dnat", (blocked, 19045))
        assert server.recv(64) == b"output-dnat", "Local DNAT failed to translate address and port"

listing = subprocess.check_output(["nft", "--json", "list", "ruleset"], timeout=3)
counters = [
    statement["counter"]
    for entry in json.loads(listing)["nftables"]
    for statement in entry.get("rule", {}).get("expr", [])
    if "counter" in statement
]
assert len(counters) == 1 and counters[0]["packets"] == 1, "Counter did not track exactly the denied UDP packet"

# The separate fixture table makes just this flow untracked before conntrack.
# It exercises the imported filter predicate without embedding a raw action in it.
subprocess.run(
    ["nft", "--file", "-"],
    input=(
        "add table inet fixture_raw\n"
        "add chain inet fixture_raw output { type filter hook output priority -300; policy accept; }\n"
        "add rule inet fixture_raw output udp dport 19044 notrack\n"
    ),
    text=True, check=True, capture_output=True, timeout=3,
)
for family, address in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
    assert admitted(family, socket.SOCK_DGRAM, address, address, 19044), "Untracked packet did not match"
print("PASS: selector sets, ordered denial, counter, untracked matching and local DNAT in both IP families")
