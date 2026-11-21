"""Real Linux bridge filtering and multi-table atomic commit/replacement checks in isolated namespaces."""
import contextlib
import os
from pathlib import Path
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise AssertionError(message)


require(len(sys.argv) == 7, "Invoke through check.sh with bundle inputs, output paths, and namespace guards")
require(os.readlink('/proc/self/ns/net') != sys.argv[5], "Bridge network namespace was not isolated")
require(os.readlink('/proc/self/ns/user') != sys.argv[6], "Bridge user namespace was not isolated")
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


def nft(batch, success=True):
    result = subprocess.run(['nft', '--file', '-'], input=batch, text=True, capture_output=True)
    require((result.returncode == 0) == success,
            f"Unexpected nft exit ({result.returncode}): {result.stderr}")


def check_ping(pid, flag, target, allowed):
    with in_netns(pid):
        res = subprocess.run(['ping', flag, '-n', '-c', '1', '-W', '1', target], capture_output=True, text=True)
    require((res.returncode == 0) == allowed,
            f"Unexpected bridge ping ({flag} -> {target}, expected allowed={allowed}): {res.stdout}{res.stderr}")


host_a = spawn_netns()
host_b = spawn_netns()
try:
    run('ip', 'link', 'set', 'lo', 'up')
    run('ip', 'link', 'add', 'br0', 'type', 'bridge')
    run('ip', 'link', 'set', 'br0', 'up')

    run('ip', 'link', 'add', 'veth_br_a', 'type', 'veth', 'peer', 'name', 'eth_a', 'netns', str(host_a.pid))
    run('ip', 'link', 'add', 'veth_br_b', 'type', 'veth', 'peer', 'name', 'eth_b', 'netns', str(host_b.pid))
    run('ip', 'link', 'set', 'veth_br_a', 'master', 'br0')
    run('ip', 'link', 'set', 'veth_br_b', 'master', 'br0')
    run('ip', 'link', 'set', 'veth_br_a', 'up')
    run('ip', 'link', 'set', 'veth_br_b', 'up')

    with in_netns(host_a.pid):
        Path('/proc/sys/net/ipv6/conf/eth_a/accept_dad').write_text('0')
    run_in(host_a.pid, 'ip', 'link', 'set', 'lo', 'up')
    run_in(host_a.pid, 'ip', 'link', 'set', 'eth_a', 'up')
    run_in(host_a.pid, 'ip', 'addr', 'add', '192.0.2.10/24', 'dev', 'eth_a')
    run_in(host_a.pid, 'ip', '-6', 'addr', 'add', '2001:db8:10::10/64', 'dev', 'eth_a', 'nodad')

    with in_netns(host_b.pid):
        Path('/proc/sys/net/ipv6/conf/eth_b/accept_dad').write_text('0')
    run_in(host_b.pid, 'ip', 'link', 'set', 'lo', 'up')
    run_in(host_b.pid, 'ip', 'link', 'set', 'eth_b', 'up')
    run_in(host_b.pid, 'ip', 'addr', 'add', '192.0.2.20/24', 'dev', 'eth_b')
    run_in(host_b.pid, 'ip', '-6', 'addr', 'add', '2001:db8:10::20/64', 'dev', 'eth_b', 'nodad')

    for family in ('ip', 'ip6', 'inet', 'bridge'):
        nft(f'create table {family} foreign_fixture\nadd chain {family} foreign_fixture sentinel\nadd rule {family} foreign_fixture sentinel counter\n')
    foreign = run('nft', '--stateless', 'list', 'ruleset')

    bundle_v1 = Path(sys.argv[1]).read_text()
    bundle_v2 = Path(sys.argv[2]).read_text()

    # An invalid command at the end of a multi-table batch must abort all 3 tables cleanly.
    nft(bundle_v1 + 'add rule bridge nergal_bridge missing_chain drop\n', success=False)
    require(run('nft', '--stateless', 'list', 'ruleset') == foreign,
            "Invalid multi-table batch partially created tables")

    nft(bundle_v1)
    # ARP + IPv4 bridged frames allowed; IPv6 bridged frames dropped by bridge nergal_bridge.
    check_ping(host_a.pid, '-4', '192.0.2.20', True)
    check_ping(host_a.pid, '-6', '2001:db8:10::20', False)

    # Atomic multi-table replacement removes nergal_nat and enables IPv6 on bridge nergal_bridge.
    nft(bundle_v2)
    nat_check = subprocess.run(['nft', 'list', 'table', 'inet', 'nergal_nat'], capture_output=True)
    require(nat_check.returncode != 0, "Owned nergal_nat table should have been removed by atomic replacement")

    for family in ('ip', 'ip6', 'inet', 'bridge'):
        table = run('nft', '--stateless', 'list', 'table', family, 'foreign_fixture')
        require(table in foreign, f"Foreign {family} table mutated by atomic multi-table replacement")

    check_ping(host_a.pid, '-4', '192.0.2.20', True)
    check_ping(host_a.pid, '-6', '2001:db8:10::20', True)

    Path(sys.argv[3]).write_text(run('nft', '--json', 'list', 'table', 'inet', 'nergal_filter'))
    Path(sys.argv[4]).write_text(run('nft', '--json', 'list', 'table', 'bridge', 'nergal_bridge'))

    print('PASS: Linux bridge L2 filtering, multi-table atomic failure rollback, and targeted multi-table replacement')
finally:
    for proc in (host_a, host_b):
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=2)
