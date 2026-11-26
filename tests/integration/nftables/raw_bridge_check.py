"""Compare UDP delivery and bridged frames using synthetic addresses and disposable links."""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time


def run(*args):
    return subprocess.check_output(args, timeout=5)


def address(v6, suffix):
    return f"2001:db8::{suffix:x}" if v6 else f"192.0.2.{suffix}"


def udp(v6, origin, target, expected):
    family = socket.AF_INET6 if v6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sender, socket.socket(family, socket.SOCK_DGRAM) as receiver:
        receiver.bind((address(v6, target), 19204))
        sender.bind((address(v6, origin), 0))
        receiver.settimeout(0.25)
        sender.sendto(b"raw", receiver.getsockname())
        try:
            arrived = receiver.recv(32) == b"raw"
        except TimeoutError:
            arrived = False
        assert arrived == expected, ("raw", v6, origin, target, arrived)


def frame(v6, origin, target, expected, reverse=False):
    # Send valid L3 headers directly over the test wires, bypassing routes and neighbor discovery.
    marker = os.urandom(16)
    family = socket.AF_INET6 if v6 else socket.AF_INET
    source = socket.inet_pton(family, address(v6, origin))
    destination = socket.inet_pton(family, address(v6, target))
    if v6:
        payload = struct.pack("!IHBB16s16s", 6 << 28, len(marker), 253, 64, source, destination)
        ether_type = 0x86dd
    else:
        payload = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(marker), 7, 0, 64, 253, 0, source, destination)
        total = sum(struct.unpack("!10H", payload))
        total = (total & 0xffff) + (total >> 16)
        checksum = 0xffff ^ ((total & 0xffff) + (total >> 16))
        payload = payload[:10] + struct.pack("!H", checksum) + payload[12:]
        ether_type = 0x0800
    ingress, egress = ("wire-out", "wire-in") if reverse else ("wire-in", "wire-out")
    mac = bytes.fromhex("020000000001" if reverse else "020000000002")
    packet = b"\xff" * 6 + mac + struct.pack("!H", ether_type) + payload + marker
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ether_type)) as receiver:
        receiver.bind((egress, ether_type))
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sender:
            sender.bind((ingress, 0))
            sender.send(packet)
        end = time.monotonic() + 0.25
        arrived = False
        while time.monotonic() < end:
            receiver.settimeout(max(0.001, end - time.monotonic()))
            try:
                if marker in receiver.recv(2048):
                    arrived = True
                    break
            except TimeoutError:
                break
        assert arrived == expected, ("bridge", reverse, v6, origin, target, arrived)


def listing(family, table):
    return run("nft", "--json", "list", "table", family, table)


def counts(data, chain):
    return [expr["counter"]["packets"] for item in json.loads(data)["nftables"]
            if item.get("rule", {}).get("chain") == chain for expr in item["rule"]["expr"] if "counter" in expr]


if len(sys.argv) != 5 or os.getuid() != 0 or os.readlink("/proc/self/ns/net") == sys.argv[3] or os.readlink("/proc/self/ns/user") == sys.argv[4]:
    raise SystemExit("Use the disposable user/network namespace launcher")
policy, work = Path(sys.argv[1]), Path(sys.argv[2])
run("ip", "link", "set", "lo", "up")
run("ip", "link", "add", "fixture-bridge", "type", "bridge")
for port, wire in (("edge-in", "wire-in"), ("edge-out", "wire-out")):
    run("ip", "link", "add", port, "type", "veth", "peer", "name", wire)
    run("ip", "link", "set", port, "master", "fixture-bridge")
    for name in (port, wire):
        run("ip", "link", "set", name, "addrgenmode", "none")
        run("ip", "link", "set", name, "up")
run("ip", "link", "set", "fixture-bridge", "addrgenmode", "none")
run("ip", "link", "set", "fixture-bridge", "up")
for v6 in (False, True):
    for suffix in (1, 3, 7, 8, 13, 16):
        run("ip", "address", "add", f"{address(v6, suffix)}/{128 if v6 else 32}", "dev", "lo", *(["nodad"] if v6 else []))
(work / "echo.json").write_bytes(run("nft", "--echo", "--handle", "--json", "--file", policy))
for v6 in (False, True):
    for origin in (3, 7):
        udp(v6, origin, 8, False)
    udp(v6, 1, 8, True)
    udp(v6, 1, 16, False)
udp(True, 1, 13, True)
primary = listing("inet", "nergal_filter")
raw_counts = counts(primary, "rpfilter")
# The unqualified fallback also sees namespace-local background traffic (e.g. IPv6 MLD).
assert len(raw_counts) == 3 and raw_counts[:2] == [2, 2] and raw_counts[2] >= 2, ("raw counter totals", raw_counts)

for v6 in (False, True):
    for origin in (3, 7):
        frame(v6, origin, 8, False)
    frame(v6, 1, 16, True)
    frame(v6, 1, 16, False, reverse=True)
for target in (8, 13):
    frame(True, 1, target, True, reverse=True)
bridge = listing("bridge", "nergal_bridge")
assert counts(bridge, "screen") == [2, 2], "Bridge source counters lost a guard or member"
assert counts(bridge, "forward") == [2], "Unmatched frames must return to the counted drop"
(work / "filter.json").write_bytes(primary)
(work / "bridge.json").write_bytes(bridge)

# The iifname guard ceases matching after rename; the later iif accept follows the original port.
run("ip", "link", "set", "edge-in", "name", "renamed-in")
frame(False, 3, 16, True)
