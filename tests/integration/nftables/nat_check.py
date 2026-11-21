"""Real 3-namespace dual-stack DNAT, explicit SNAT, and `ct status dnat` packet checks."""
import contextlib
import os
from pathlib import Path
import socket
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise AssertionError(message)


require(len(sys.argv) == 9, "Invoke through check.sh with NAT inputs, output paths, and namespace guards")
require(os.readlink('/proc/self/ns/net') != sys.argv[7], "Router network namespace was not isolated")
require(os.readlink('/proc/self/ns/user') != sys.argv[8], "Router user namespace was not isolated")
require(os.getuid() == 0, "Expected namespace-local root")

CLONE_NEWNET = 0x40000000


def spawn_netns():
    cmd = (
        "import os, signal, sys; "
        f"os.unshare({CLONE_NEWNET}); "
        "sys.stdout.write('ready\\n'); sys.stdout.flush(); "
        "signal.pause()"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    line = proc.stdout.readline()
    if line != b"ready\n":
        err = proc.stderr.read().decode("utf-8", errors="replace")
        proc.kill()
        raise AssertionError(f"Failed spawning isolated netns: {line!r} {err}")
    return proc


@contextlib.contextmanager
def in_netns(pid):
    orig_fd = os.open("/proc/self/ns/net", os.O_RDONLY)
    target_fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    try:
        os.setns(target_fd, CLONE_NEWNET)
        yield
    finally:
        os.setns(orig_fd, CLONE_NEWNET)
        os.close(target_fd)
        os.close(orig_fd)


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def run_in(pid, *args):
    with in_netns(pid):
        return run(*args)


def nft(batch, *flags):
    return subprocess.run(
        ['nft', *flags, '--file', '-'],
        input=batch,
        text=True,
        capture_output=True,
        check=True,
    ).stdout


def check_nat_tcp(client_pid, server_pid, family, listen_ip, target_ip, client_ip, listen_port, target_port, expected_peer, allowed):
    with in_netns(server_pid):
        server = socket.socket(family, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((listen_ip, listen_port))
        server.listen(1)
        server.settimeout(0.5)

    try:
        with in_netns(client_pid):
            client = socket.socket(family, socket.SOCK_STREAM)
            client.settimeout(0.5)
            client.bind((client_ip, 0))
            try:
                client.connect((target_ip, target_port))
            except (socket.timeout, OSError):
                require(not allowed, f"Allowed NAT TCP timed out: {client_ip} -> {target_ip}:{target_port}")
                return
            try:
                require(allowed, f"Denied non-DNAT TCP connected: {client_ip} -> {target_ip}:{target_port}")
                conn, peer = server.accept()
                try:
                    require(peer[0] == expected_peer, f"Expected SNAT source {expected_peer}, observed {peer[0]}")
                    conn.sendall(b'nergal-nat-ok')
                    data = client.recv(64)
                    require(data == b'nergal-nat-ok', f"NAT reply failed: {data!r}")
                finally:
                    conn.close()
            finally:
                client.close()
    finally:
        server.close()


client_proc = spawn_netns()
server_proc = spawn_netns()
try:
    run('ip', 'link', 'set', 'lo', 'up')
    run_in(client_proc.pid, 'ip', 'link', 'set', 'lo', 'up')
    run_in(server_proc.pid, 'ip', 'link', 'set', 'lo', 'up')

    run('ip', 'link', 'add', 'r_cli', 'type', 'veth', 'peer', 'name', 'veth_c', 'netns', str(client_proc.pid))
    run('ip', 'link', 'add', 'r_srv', 'type', 'veth', 'peer', 'name', 'veth_s', 'netns', str(server_proc.pid))

    Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
    Path('/proc/sys/net/ipv6/conf/default/accept_dad').write_text('0')
    Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1')
    Path('/proc/sys/net/ipv6/conf/r_cli/accept_dad').write_text('0')
    Path('/proc/sys/net/ipv6/conf/r_srv/accept_dad').write_text('0')
    Path('/proc/sys/net/ipv6/conf/r_cli/forwarding').write_text('1')
    Path('/proc/sys/net/ipv6/conf/r_srv/forwarding').write_text('1')

    run('ip', 'link', 'set', 'r_cli', 'up')
    run('ip', 'link', 'set', 'r_srv', 'up')
    run('ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'r_cli')
    run('ip', '-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'r_cli', 'nodad')
    run('ip', 'addr', 'add', '198.51.100.1/24', 'dev', 'r_srv')
    run('ip', '-6', 'addr', 'add', '2001:db8:2::1/64', 'dev', 'r_srv', 'nodad')

    with in_netns(client_proc.pid):
        Path('/proc/sys/net/ipv6/conf/veth_c/accept_dad').write_text('0')
    run_in(client_proc.pid, 'ip', 'link', 'set', 'veth_c', 'up')
    run_in(client_proc.pid, 'ip', 'addr', 'add', '192.0.2.2/24', 'dev', 'veth_c')
    run_in(client_proc.pid, 'ip', '-6', 'addr', 'add', '2001:db8:1::2/64', 'dev', 'veth_c', 'nodad')
    run_in(client_proc.pid, 'ip', 'route', 'add', 'default', 'via', '192.0.2.1')
    run_in(client_proc.pid, 'ip', '-6', 'route', 'add', 'default', 'via', '2001:db8:1::1')

    # Server deliberately has NO route back to client subnets (192.0.2.0/24 or 2001:db8:1::/64);
    # connectivity is only possible if explicit SNAT rewrites source addresses to router's server-facing IP.
    with in_netns(server_proc.pid):
        Path('/proc/sys/net/ipv6/conf/veth_s/accept_dad').write_text('0')
    run_in(server_proc.pid, 'ip', 'link', 'set', 'veth_s', 'up')
    run_in(server_proc.pid, 'ip', 'addr', 'add', '198.51.100.2/24', 'dev', 'veth_s')
    run_in(server_proc.pid, 'ip', '-6', 'addr', 'add', '2001:db8:2::2/64', 'dev', 'veth_s', 'nodad')

    filter_batch = Path(sys.argv[1]).read_text()
    nat_batch = Path(sys.argv[2]).read_text()
    Path(sys.argv[3]).write_text(nft(filter_batch, '--echo', '--handle', '--json'))
    Path(sys.argv[5]).write_text(nft(nat_batch, '--echo', '--handle', '--json'))
    Path(sys.argv[4]).write_text(run('nft', '--json', 'list', 'table', 'inet', 'nergal_filter'))
    Path(sys.argv[6]).write_text(run('nft', '--json', 'list', 'table', 'inet', 'nergal_nat'))

    run('ip', '-6', 'neigh', 'flush', 'all')
    run_in(client_proc.pid, 'ip', '-6', 'neigh', 'flush', 'all')
    run_in(server_proc.pid, 'ip', '-6', 'neigh', 'flush', 'all')

    # IPv4 DNAT + explicit SNAT + ct status dnat (vs denied non-DNAT direct access to backend port).
    check_nat_tcp(client_proc.pid, server_proc.pid, socket.AF_INET, '198.51.100.2', '192.0.2.1', '192.0.2.2', 18447, 18446, '198.51.100.1', True)
    check_nat_tcp(client_proc.pid, server_proc.pid, socket.AF_INET, '198.51.100.2', '198.51.100.2', '192.0.2.2', 18447, 18447, '198.51.100.1', False)

    # IPv6 DNAT + explicit SNAT + ct status dnat.
    check_nat_tcp(client_proc.pid, server_proc.pid, socket.AF_INET6, '2001:db8:2::2', '2001:db8:1::1', '2001:db8:1::2', 18447, 18446, '2001:db8:2::1', True)
    check_nat_tcp(client_proc.pid, server_proc.pid, socket.AF_INET6, '2001:db8:2::2', '2001:db8:2::2', '2001:db8:1::2', 18447, 18447, '2001:db8:2::1', False)

    print('PASS: multi-namespace dual-stack DNAT, explicit SNAT (without server default route), and ct status dnat enforcement')
finally:
    for proc in (client_proc, server_proc):
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=2)
