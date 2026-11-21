"""Real multi-namespace routed forwarding, stateful reply, and IPv6 Neighbor Discovery checks."""
import contextlib
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise AssertionError(message)


require(len(sys.argv) == 7, "Invoke through check.sh with namespace guards and output paths")
require(os.readlink('/proc/self/ns/net') != sys.argv[5], "Router network namespace was not isolated")
require(os.readlink('/proc/self/ns/user') != sys.argv[6], "Router user namespace was not isolated")
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
    require(os.readlink(f"/proc/{proc.pid}/ns/net") != os.readlink("/proc/self/ns/net"),
            "Child netns matched router netns")
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


def check_tcp(client_pid, server_pid, family, server_ip, client_ip, port, allowed):
    with in_netns(server_pid):
        server = socket.socket(family, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((server_ip, port))
        server.listen(1)
        server.settimeout(0.5)

    try:
        with in_netns(client_pid):
            client = socket.socket(family, socket.SOCK_STREAM)
            client.settimeout(0.5)
            client.bind((client_ip, 0))
            try:
                client.connect((server_ip, port))
            except (socket.timeout, OSError):
                require(not allowed, f"Allowed routed TCP timed out: {client_ip} -> {server_ip}:{port}")
                return
            try:
                require(allowed, f"Denied routed TCP connected: {client_ip} -> {server_ip}:{port}")
                conn, _ = server.accept()
                try:
                    conn.sendall(b'nergal-srv-ok')
                    data = client.recv(64)
                    require(data == b'nergal-srv-ok', f"Stateful reply failed: {data!r}")
                finally:
                    conn.close()
            finally:
                client.close()
    finally:
        server.close()


def check_ping(pid, flag, target, allowed):
    with in_netns(pid):
        res = subprocess.run(
            ['ping', flag, '-n', '-c', '1', '-W', '1', target],
            capture_output=True,
            text=True,
        )
    require((res.returncode == 0) == allowed,
            f"Unexpected ping ({flag} -> {target}, expected allowed={allowed}): {res.stdout}{res.stderr}")


def check_rate_limit(client_pid, server_pid, family, server_ip, source_a, source_b, port):
    with in_netns(server_pid):
        server = socket.socket(family, socket.SOCK_DGRAM)
        server.bind((server_ip, port))
        server.settimeout(0.25)

    try:
        def recv_count():
            received = []
            while True:
                try:
                    data, _ = server.recvfrom(64)
                    received.append(data)
                except socket.timeout:
                    return received

        with in_netns(client_pid):
            sock_a = socket.socket(family, socket.SOCK_DGRAM)
            sock_b = socket.socket(family, socket.SOCK_DGRAM)
            sock_a.bind((source_a, 0))
            sock_b.bind((source_b, 0))
            try:
                for idx in range(5):
                    sock_a.sendto(f'rl-a-{idx}'.encode(), (server_ip, port))
                got_a = recv_count()
                require(len(got_a) == 2,
                        f"Expected burst=2 packets from {source_a}, got {len(got_a)}: {got_a}")

                for idx in range(2):
                    sock_b.sendto(f'rl-b-{idx}'.encode(), (server_ip, port))
                got_b = recv_count()
                require(len(got_b) == 2,
                        f"Independent source {source_b} was throttled by {source_a}: {got_b}")
            finally:
                sock_a.close()
                sock_b.close()
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
    run_in(client_proc.pid, 'ip', 'addr', 'add', '192.0.2.3/24', 'dev', 'veth_c')
    run_in(client_proc.pid, 'ip', '-6', 'addr', 'add', '2001:db8:1::2/64', 'dev', 'veth_c', 'nodad')
    run_in(client_proc.pid, 'ip', '-6', 'addr', 'add', '2001:db8:1::3/64', 'dev', 'veth_c', 'nodad')
    run_in(client_proc.pid, 'ip', 'route', 'add', 'default', 'via', '192.0.2.1')
    run_in(client_proc.pid, 'ip', '-6', 'route', 'add', 'default', 'via', '2001:db8:1::1')

    with in_netns(server_proc.pid):
        Path('/proc/sys/net/ipv6/conf/veth_s/accept_dad').write_text('0')
    run_in(server_proc.pid, 'ip', 'link', 'set', 'veth_s', 'up')
    run_in(server_proc.pid, 'ip', 'addr', 'add', '198.51.100.2/24', 'dev', 'veth_s')
    run_in(server_proc.pid, 'ip', '-6', 'addr', 'add', '2001:db8:2::2/64', 'dev', 'veth_s', 'nodad')
    run_in(server_proc.pid, 'ip', 'route', 'add', 'default', 'via', '198.51.100.1')
    run_in(server_proc.pid, 'ip', '-6', 'route', 'add', 'default', 'via', '2001:db8:2::1')

    for family in ('ip', 'ip6', 'inet', 'bridge'):
        nft(f'create table {family} foreign_fixture\nadd chain {family} foreign_fixture sentinel\nadd rule {family} foreign_fixture sentinel counter\n')
    foreign = run('nft', '--stateless', 'list', 'ruleset')

    router_batch = Path(sys.argv[1]).read_text()
    echo_json = nft(router_batch, '--echo', '--handle', '--json')
    Path(sys.argv[2]).write_text(echo_json)

    for family in ('ip', 'ip6', 'inet', 'bridge'):
        table = run('nft', '--stateless', 'list', 'table', family, 'foreign_fixture')
        require(table in foreign, f"Foreign {family} table mutated by schema-2 router candidate")

    # Flush neighbor caches so IPv6 Neighbor Discovery packets traverse router input/output chains under drop defaults.
    run('ip', '-6', 'neigh', 'flush', 'all')
    run_in(client_proc.pid, 'ip', '-6', 'neigh', 'flush', 'all')
    run_in(server_proc.pid, 'ip', '-6', 'neigh', 'flush', 'all')

    check_tcp(client_proc.pid, server_proc.pid, socket.AF_INET, '198.51.100.2', '192.0.2.2', 18443, True)
    check_tcp(client_proc.pid, server_proc.pid, socket.AF_INET, '198.51.100.2', '192.0.2.2', 18444, False)
    check_tcp(server_proc.pid, client_proc.pid, socket.AF_INET, '192.0.2.2', '198.51.100.2', 18443, False)

    check_tcp(client_proc.pid, server_proc.pid, socket.AF_INET6, '2001:db8:2::2', '2001:db8:1::2', 18443, True)
    check_tcp(client_proc.pid, server_proc.pid, socket.AF_INET6, '2001:db8:2::2', '2001:db8:1::2', 18444, False)
    check_tcp(server_proc.pid, client_proc.pid, socket.AF_INET6, '2001:db8:1::2', '2001:db8:2::2', 18443, False)

    check_ping(client_proc.pid, '-4', '198.51.100.2', True)
    check_ping(client_proc.pid, '-6', '2001:db8:2::2', True)
    check_ping(server_proc.pid, '-4', '192.0.2.2', False)
    check_ping(server_proc.pid, '-6', '2001:db8:1::2', False)

    check_rate_limit(client_proc.pid, server_proc.pid, socket.AF_INET, '198.51.100.2', '192.0.2.2', '192.0.2.3', 18445)
    check_rate_limit(client_proc.pid, server_proc.pid, socket.AF_INET6, '2001:db8:2::2', '2001:db8:1::2', '2001:db8:1::3', 18445)

    list_json = run('nft', '--json', 'list', 'table', 'inet', 'nergal_filter')
    terse_json = run('nft', '--terse', '--json', 'list', 'table', 'inet', 'nergal_filter')
    require('"elem"' in list_json, "Expected populated dynamic set elements in plain listing")
    Path(sys.argv[3]).write_text(list_json)
    Path(sys.argv[4]).write_text(terse_json)

    print('PASS: multi-namespace IPv4/IPv6 routed forwarding, stateful reply, interface matching, IPv6 Neighbor Discovery, and per-source rate limiting')
finally:
    for proc in (client_proc, server_proc):
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=2)
