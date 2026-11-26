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
run("ip", "link", "add", "fixture-in", "type", "veth", "peer", "name", "fixture-peer")
for address in (
    "192.0.2.1/32", "192.0.2.2/32", "192.0.2.4/32", "192.0.2.8/32",
    "2001:db8::1/128", "2001:db8::2/128", "2001:db8::4/128", "2001:db8::8/128",
):
    run("ip", "address", "add", address, "dev", "lo", "nodad")
run("nft", "--file", str(Path(sys.argv[1])))


def admitted(family, kind, source, target, port, source_port=0):
    with socket.socket(family, kind) as server, socket.socket(family, kind) as client:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(0.4)
        client.settimeout(0.4)
        server.bind((target, port))
        client.bind((source, source_port))
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


for family, flag, address, blocked, other_destination, denied_destination in (
    (socket.AF_INET, "-4", "192.0.2.1", "192.0.2.2", "192.0.2.4", "192.0.2.8"),
    (socket.AF_INET6, "-6", "2001:db8::1", "2001:db8::2", "2001:db8::4", "2001:db8::8"),
):
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        assert admitted(family, kind, address, address, 19042), "Allowed transport or family was omitted"
        assert not admitted(family, kind, blocked, address, 19042), "Earlier drop lost its order"
        assert not admitted(family, kind, address, address, 19043), "Unselected port was admitted"
    run("ping", flag, "-n", "-c", "1", "-W", "1", address)
    assert not admitted(family, socket.SOCK_DGRAM, address, address, 19044), "Tracked packet matched untracked"
    assert admitted(family, socket.SOCK_DGRAM, address, address, 19044, 19050), "Raw output failed to mark the packet untracked"
    assert admitted(family, socket.SOCK_DGRAM, address, address, 19047), "A counter-only rule must reach the next verdict"
    for packet in range(5):
        assert admitted(family, socket.SOCK_DGRAM, address, address, 19049), f"Implicit meter burst dropped packet {packet + 1}"
    assert not admitted(family, socket.SOCK_DGRAM, address, address, 19049), "Packet beyond the implicit meter burst was admitted"
    with socket.socket(family, socket.SOCK_DGRAM) as server, socket.socket(family, socket.SOCK_DGRAM) as client:
        server.bind((address, 19048))
        client.settimeout(0.4)
        client.connect((address, 19048))
        client.send(b"reject-check")
        try:
            client.recv(64)
        except ConnectionRefusedError:
            pass
        else:
            raise AssertionError("Default nft reject did not send port unreachable")
    with socket.socket(family, socket.SOCK_DGRAM) as server, socket.socket(family, socket.SOCK_DGRAM) as client:
        server.settimeout(0.4)
        server.bind((address, 19046))
        client.bind((address, 0))
        for original_destination, expected_source in ((blocked, blocked), (other_destination, address)):
            client.sendto(b"output-dnat", (original_destination, 19045))
            payload, source = server.recvfrom(64)
            assert payload == b"output-dnat", "Local DNAT failed to translate address and port"
            assert source[0] == expected_source, "SNAT failed to distinguish original destinations with the same translated target"
        client.sendto(b"denied-dnat", (denied_destination, 19045))
        try:
            server.recvfrom(64)
        except TimeoutError:
            pass
        else:
            raise AssertionError("Filter admitted a translated packet with an unselected original destination")
    for port in (19054, 19055):
        with socket.socket(family, socket.SOCK_DGRAM) as server, socket.socket(family, socket.SOCK_DGRAM) as client:
            server.settimeout(0.4)
            server.bind((address, port))
            client.bind((address, 0))
            client.sendto(b"map", (blocked, port))
            payload, source = server.recvfrom(64)
            assert payload == b"map", f"Map indirection or missing-key fallthrough failed on port {port}"
            assert source[0] == (blocked if port == 19054 else address), "Address-keyed SNAT map changed the wrong packet"


def send_from_peer(family, target, port, peer):
    run(*peer, sys.executable, "-c",
        "import socket,sys; s=socket.socket(int(sys.argv[1]), socket.SOCK_DGRAM); s.sendto(b'from-peer', (sys.argv[2],int(sys.argv[3])))",
        str(family.value), target, str(port))


# On loopback, output conntrack may already have examined the packet before
# prerouting. Send a genuine ingress packet from a second disposable namespace.
with subprocess.Popen(
    [sys.executable, "-c", "import os,signal; os.unshare(0x40000000); print('ready', flush=True); signal.pause()"],
    stdout=subprocess.PIPE,
) as sender:
    try:
        assert sender.stdout.readline() == b"ready\n", "Sender namespace did not start"
        peer = ("nsenter", f"--net=/proc/{sender.pid}/ns/net", "--")
        run("ip", "link", "set", "fixture-peer", "netns", str(sender.pid))
        run("ip", "link", "set", "fixture-in", "up")
        run(*peer, "ip", "link", "set", "fixture-peer", "up")
        for family, target, origin, prefix in (
            (socket.AF_INET, "198.51.100.1", "198.51.100.2", 24),
            (socket.AF_INET6, "2001:db8:2::1", "2001:db8:2::2", 64),
        ):
            run("ip", "address", "add", f"{target}/{prefix}", "dev", "fixture-in", "nodad")
            run(*peer, "ip", "address", "add", f"{origin}/{prefix}", "dev", "fixture-peer", "nodad")
            with socket.socket(family, socket.SOCK_DGRAM) as server:
                server.bind((target, 19051))
                server.settimeout(1)
                send_from_peer(family, target, 19051, peer)
                assert server.recv(64) == b"from-peer", "Raw prerouting failed to mark ingress untracked"
        run("ip", "link", "set", "fixture-in", "name", "fixture-renamed")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as by_index, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as by_name:
            by_index.bind(("198.51.100.1", 19052))
            by_name.bind(("198.51.100.1", 19053))
            by_index.settimeout(1)
            by_name.settimeout(0.4)
            send_from_peer(socket.AF_INET, "198.51.100.1", 19052, peer)
            assert by_index.recv(64) == b"from-peer", "A rename changed the installed input index selector"
            send_from_peer(socket.AF_INET, "198.51.100.1", 19053, peer)
            try:
                by_name.recv(64)
            except TimeoutError:
                pass
            else:
                raise AssertionError("A renamed input interface still matched its old name")
    finally:
        sender.terminate()


def counter_totals(table):
    listing = subprocess.check_output(["nft", "--json", "list", "table", "inet", table], timeout=3)
    return [
        statement["counter"]["packets"]
        for entry in json.loads(listing)["nftables"]
        for statement in entry.get("rule", {}).get("expr", [])
        if "counter" in statement
    ]


assert counter_totals("nergal_filter") == [1, 2, 2, 2, 5, 5], "Counters must count both families once per match and respect meter exhaustion"
assert counter_totals("nergal_nat") == [3, 3, 1, 1], "DNAT and SNAT counters must follow their respective selectors"

print("PASS: selector sets, ordered denial, shared counters, port rejection, raw notrack on prerouting and output, and counted local DNAT")
