"""Packet verification for rpfilter, MAC+IP pinning, MSS, destination meters and NAT exemptions.

Only invoke through check-router-constructs.sh inside a fresh user/network namespace.
No host rulesets or server exports are opened by this fixture.
"""
import contextlib
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys


def require(value, message):
    if not value:
        raise AssertionError(message)


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


@contextlib.contextmanager
def network(pid):
    original = os.open('/proc/self/ns/net', os.O_RDONLY)
    target = os.open(f'/proc/{pid}/ns/net', os.O_RDONLY)
    try:
        os.setns(target, 0x40000000)
        yield
    finally:
        os.setns(original, 0x40000000)
        os.close(target)
        os.close(original)


def child():
    proc = subprocess.Popen([sys.executable, '-c',
        "import os,signal; os.unshare(0x40000000); print('ready',flush=True); signal.pause()"], stdout=subprocess.PIPE)
    require(proc.stdout.readline() == b'ready\n', 'Child namespace did not start')
    return proc


def run_in(proc, *args):
    with network(proc.pid):
        return run(*args)


def install(path):
    run('nft', '--check', '-f', str(path))
    return run('nft', '--echo', '--handle', '--json', '-f', str(path))


def tcp(client, server, family, source, target, expected_peer, allowed=True, expected_mss=None):
    with network(server.pid):
        listener = socket.socket(family, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((target, 9001))
        listener.listen()
        listener.settimeout(.5)
        ether_type = 0x0800 if family == socket.AF_INET else 0x86dd
        capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ether_type)) if expected_mss is not None else None
        if capture:
            capture.bind(('eth0', 0))
            capture.settimeout(.5)
    try:
        with network(client.pid):
            sender = socket.socket(family, socket.SOCK_STREAM)
            sender.settimeout(.5)
            sender.bind((source, 0))
            try:
                sender.connect((target, 9001))
            except OSError:
                require(not allowed, 'Permitted pinned TCP connection failed')
                return
            finally:
                sender.close()
        require(allowed, 'MAC/IP mismatch was accepted')
        conn, peer = listener.accept()
        conn.close()
        require(peer[0] == expected_peer, 'Masquerade/return source address differed')
        if capture:
            found = None
            for _ in range(32):
                frame = capture.recv(4096)
                if len(frame) < 54:
                    continue
                offset = 14 + (frame[14] & 15) * 4 if family == socket.AF_INET else 54
                protocol = frame[23] if family == socket.AF_INET else frame[20]
                if len(frame) <= offset + 20 or protocol != 6 or not frame[offset + 13] & 2:
                    continue
                end = offset + ((frame[offset + 12] >> 4) * 4)
                options = frame[offset + 20:end]
                i = 0
                while i < len(options):
                    kind = options[i]
                    if kind == 0:
                        break
                    if kind == 1:
                        i += 1
                        continue
                    length = options[i + 1]
                    if kind == 2:
                        found = struct.unpack('!H', options[i + 2:i + 4])[0]
                    i += length
                if found is not None:
                    break
            require(found == expected_mss, f'Forwarded SYN carried MSS {found}; expected {expected_mss}')
    finally:
        listener.close()
        if capture:
            capture.close()


def meter(client, server, family, source_a, source_b, destination_a, destination_b):
    receivers = []
    with network(server.pid):
        for addr in (destination_a, destination_b):
            receiver = socket.socket(family, socket.SOCK_DGRAM)
            receiver.bind((addr, 19001))
            receiver.settimeout(.2)
            receivers.append(receiver)
    try:
        with network(client.pid):
            for source, target, body in ((source_a, destination_a, b'first'), (source_b, destination_a, b'same-destination'),
                                         (source_b, destination_b, b'other-destination')):
                with socket.socket(family, socket.SOCK_DGRAM) as sender:
                    sender.bind((source, 0))
                    sender.sendto(body, (target, 19001))
        require(receivers[0].recv(64) == b'first', 'First destination token was denied')
        try:
            receivers[0].recv(64)
            raise AssertionError('A different source bypassed the destination meter')
        except socket.timeout:
            pass
        require(receivers[1].recv(64) == b'other-destination', 'Independent destination did not receive its own token')
    finally:
        for receiver in receivers:
            receiver.close()


def checksum(data):
    values = struct.unpack('!' + 'H' * (len(data) // 2), data)
    total = sum(values)
    total = (total & 65535) + (total >> 16)
    total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def spoof(client, source_port, allowed):
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(('192.0.2.1', 19000))
    receiver.settimeout(.2)
    try:
        body = b'raw-synthetic'
        udp = struct.pack('!HHHH', source_port, 19000, 8 + len(body), 0) + body
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                             socket.inet_aton('198.51.100.99'), socket.inet_aton('192.0.2.1'))
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
        with network(client.pid):
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sender:
                sender.sendto(header + udp, ('192.0.2.1', 0))
        try:
            receiver.recv(64)
            received = True
        except socket.timeout:
            received = False
        require(received == allowed, 'Reverse-path filtering / DHCP sport exception differed')
    finally:
        receiver.close()


def main():
    require(len(sys.argv) == 8, 'Use the guarded launcher')
    require(os.readlink('/proc/self/ns/net') != sys.argv[6], 'Refusing host network namespace')
    require(os.readlink('/proc/self/ns/user') != sys.argv[7], 'Refusing host user namespace')
    root = Path(sys.argv[5])
    client, server = child(), child()
    try:
        run('ip', 'link', 'set', 'lo', 'up')
        for proc, router_iface, subnet4, subnet6 in ((client, 'lan0', '192.0.2', '2001:db8:1'), (server, 'wan0', '198.51.100', '2001:db8:2')):
            run('ip', 'link', 'add', router_iface, 'type', 'veth', 'peer', 'name', router_iface + 'p')
            run('ip', 'link', 'set', router_iface + 'p', 'netns', str(proc.pid))
            run_in(proc, 'ip', 'link', 'set', router_iface + 'p', 'name', 'eth0')
            run_in(proc, 'ip', 'link', 'set', 'lo', 'up')
            if proc == client:
                run_in(proc, 'ip', 'link', 'set', 'eth0', 'address', '02:00:00:00:00:01')
            run('ip', 'addr', 'add', subnet4 + '.1/24', 'dev', router_iface)
            run('ip', '-6', 'addr', 'add', subnet6 + '::1/64', 'dev', router_iface, 'nodad')
            for suffix in (2, 3):
                run_in(proc, 'ip', 'addr', 'add', f'{subnet4}.{suffix}/24', 'dev', 'eth0')
                run_in(proc, 'ip', '-6', 'addr', 'add', f'{subnet6}::{suffix}/64', 'dev', 'eth0', 'nodad')
            run('ip', 'link', 'set', router_iface, 'up')
            run_in(proc, 'ip', 'link', 'set', 'eth0', 'up')
            run_in(proc, 'ip', 'route', 'add', 'default', 'via', subnet4 + '.1')
            run_in(proc, 'ip', '-6', 'route', 'add', 'default', 'via', subnet6 + '::1')
        # Fixed neighbor bindings isolate firewall outcomes from multicast NDP delay.
        # The existing router_check.py fixture independently exercises live NDP.
        import json
        for proc, iface, subnet in ((client, 'lan0', '2001:db8:1'), (server, 'wan0', '2001:db8:2')):
            peer_mac = json.loads(run_in(proc, 'ip', '-j', 'link', 'show', 'eth0'))[0]['address']
            router_mac = json.loads(run('ip', '-j', 'link', 'show', iface))[0]['address']
            for suffix in (2, 3):
                run('ip', '-6', 'neigh', 'replace', f'{subnet}::{suffix}', 'lladdr', peer_mac, 'nud', 'permanent', 'dev', iface)
            run_in(proc, 'ip', '-6', 'neigh', 'replace', subnet + '::1', 'lladdr', router_mac, 'nud', 'permanent', 'dev', 'eth0')
        Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
        Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1')
        # Kernel rp_filter is disabled only in this disposable namespace, so the nft rule is what gets tested.
        for name in ('all', 'default', 'lan0', 'wan0'):
            Path(f'/proc/sys/net/ipv4/conf/{name}/rp_filter').write_text('0')
        install(sys.argv[1])
        (root / 'packet-nat-echo.json').write_text(install(sys.argv[2]))
        (root / 'packet-nat-list.json').write_text(run('nft', '--terse', '--json', 'list', 'table', 'inet', 'nergal_nat'))
        if os.environ.get('NERGAL_TEST_ROUTE_MSS') == '1':
            for mtu in (1400, 1320):
                run('ip', 'link', 'set', 'wan0', 'mtu', str(mtu))
                tcp(client, server, socket.AF_INET, '192.0.2.2', '198.51.100.2', '198.51.100.1', expected_mss=mtu - 40)
                tcp(client, server, socket.AF_INET6, '2001:db8:1::2', '2001:db8:2::2', '2001:db8:2::1', expected_mss=mtu - 60)
            run('ip', 'link', 'set', 'wan0', 'mtu', '1500')
            print('PASS: IPv4 and IPv6 forwarded SYN MSS follows two route MTUs')
        else:
            tcp(client, server, socket.AF_INET, '192.0.2.2', '198.51.100.2', '198.51.100.1', expected_mss=1360)
        tcp(client, server, socket.AF_INET, '192.0.2.2', '198.51.100.3', '192.0.2.2')
        tcp(client, server, socket.AF_INET6, '2001:db8:1::2', '2001:db8:2::2', '2001:db8:2::1')
        tcp(client, server, socket.AF_INET6, '2001:db8:1::2', '2001:db8:2::3', '2001:db8:1::2')
        # Disabling a return exemption exposes later masquerade, then restoring it restores the original source.
        run('nft', 'delete', 'table', 'inet', 'nergal_nat')
        install(root / 'router-packet-nat-disabled-return.nft')
        tcp(client, server, socket.AF_INET, '192.0.2.2', '198.51.100.3', '198.51.100.1')
        tcp(client, server, socket.AF_INET6, '2001:db8:1::2', '2001:db8:2::3', '2001:db8:2::1')
        run('nft', 'delete', 'table', 'inet', 'nergal_nat')
        install(sys.argv[2])
        tcp(client, server, socket.AF_INET, '192.0.2.2', '198.51.100.3', '192.0.2.2')
        tcp(client, server, socket.AF_INET6, '2001:db8:1::2', '2001:db8:2::3', '2001:db8:1::2')
        print('PASS: disabling/restoring dual-stack NAT return exemptions changes actual translated packet sources')
        for mode, translated in (('source-miss', False), ('destination-miss', False), ('negated', True)):
            run('nft', 'delete', 'table', 'inet', 'nergal_nat')
            install(root / ('router-packet-nat-' + mode + '.nft'))
            tcp(client, server, socket.AF_INET, '192.0.2.2', '198.51.100.2', '198.51.100.1' if translated else '192.0.2.2')
            tcp(client, server, socket.AF_INET6, '2001:db8:1::2', '2001:db8:2::2', '2001:db8:2::1' if translated else '2001:db8:1::2')
        run('nft', 'delete', 'table', 'inet', 'nergal_nat')
        install(sys.argv[2])
        print('PASS: dual-stack source/destination set misses preserve original sources; negated sets restore masquerade')
        tcp(client, server, socket.AF_INET, '192.0.2.3', '198.51.100.2', None, allowed=False)
        run_in(client, 'ip', 'link', 'set', 'eth0', 'address', '02:00:00:00:00:09')
        tcp(client, server, socket.AF_INET, '192.0.2.2', '198.51.100.2', None, allowed=False)
        run_in(client, 'ip', 'link', 'set', 'eth0', 'address', '02:00:00:00:00:01')
        meter(client, server, socket.AF_INET, '192.0.2.2', '192.0.2.3', '198.51.100.2', '198.51.100.3')
        meter(client, server, socket.AF_INET6, '2001:db8:1::2', '2001:db8:1::3', '2001:db8:2::2', '2001:db8:2::3')
        spoof(client, 19002, False)
        spoof(client, 68, True)
        # Separately compile the exact round-trip samples, including MAC negation/reject and NAT negation.
        run('nft', 'delete', 'table', 'inet', 'nergal_filter')
        run('nft', 'delete', 'table', 'inet', 'nergal_nat')
        (root / 'filter-echo.json').write_text(install(sys.argv[3]))
        (root / 'filter-list.json').write_text(run('nft', '--terse', '--json', 'list', 'table', 'inet', 'nergal_filter'))
        (root / 'nat-echo.json').write_text(install(sys.argv[4]))
        (root / 'nat-list.json').write_text(run('nft', '--terse', '--json', 'list', 'table', 'inet', 'nergal_nat'))
        print('PASS: dual-stack masquerade/return, MAC+IP denial, SYN MSS, per-destination meters, rpfilter and UDP sport exception')
    finally:
        for proc in (client, server):
            proc.terminate()
            proc.wait(timeout=5)


if __name__ == '__main__':
    main()
