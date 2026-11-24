"""Real auxiliary/bridge packets and receipt-bound recovery. Fresh namespaces only; no exports."""
import contextlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid


def require(condition, message):
    if not condition:
        raise AssertionError(message)


require(len(sys.argv) == 6, 'Invoke through the guarded launcher')
agent, compiler, scenario, parent_user, parent_net = sys.argv[1:]
require(os.readlink('/proc/self/ns/user') != parent_user, 'User isolation missing')
require(os.readlink('/proc/self/ns/net') != parent_net, 'Network isolation missing')
require(os.getuid() == 0, 'Namespace root required')


def run(*args, text=None):
    return subprocess.run(args, input=text, check=True, capture_output=True, text=True, timeout=20).stdout


def nft(text):
    return run('nft', '-f', '-', text=text)


def snapshot():
    return run('nft', '--terse', '--json', 'list', 'ruleset')


@contextlib.contextmanager
def network(process):
    original = os.open('/proc/self/ns/net', os.O_RDONLY)
    target = os.open(f'/proc/{process.pid}/ns/net', os.O_RDONLY)
    try:
        os.setns(target, 0x40000000)
        yield
    finally:
        os.setns(original, 0x40000000)
        os.close(original)
        os.close(target)


def inside(process, *args):
    with network(process):
        return run(*args)


def udp(family, port):
    address = '127.0.0.1' if family == socket.AF_INET else '::1'
    with socket.socket(family, socket.SOCK_DGRAM) as receiver, socket.socket(family, socket.SOCK_DGRAM) as sender:
        receiver.bind((address, port))
        receiver.settimeout(.15)
        sender.sendto(b'auxiliary', (address, port))
        try:
            return receiver.recv(32) == b'auxiliary'
        except TimeoutError:
            return False


def wait(predicate, message):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.1)
    raise AssertionError(message)


def counter(family):
    objects = json.loads(run('nft', '--json', 'list', 'table', family, 'foreign_probe'))['nftables']
    return sum(expr['counter']['packets'] for item in objects if 'rule' in item for expr in item['rule']['expr'] if 'counter' in expr)


def tcp(client, server, family, port=18080, allowed=True, wrong_source=False, destination=3):
    target = f'192.0.2.{destination}' if family == socket.AF_INET else f'2001:db8:1::{destination}'
    source = ('192.0.2.4' if wrong_source else '192.0.2.2') if family == socket.AF_INET else ('2001:db8:1::4' if wrong_source else '2001:db8:1::2')
    with network(server):
        listener = socket.socket(family, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((target, port))
        listener.listen()
        listener.settimeout(.3)
    try:
        with network(client):
            sender = socket.socket(family, socket.SOCK_STREAM)
            sender.settimeout(.3)
            sender.bind((source, 0))
            try:
                sender.connect((target, port))
            except OSError:
                require(not allowed, f'Expected bridge TCP allow failed: family={family}, port={port}')
                return
            finally:
                sender.close()
        require(allowed, f'Bridge TCP denial failed: family={family}, port={port}')
        accepted, _ = listener.accept()
        accepted.close()
    finally:
        listener.close()


def bridge_packets(children):
    client, server = children
    for family in (socket.AF_INET, socket.AF_INET6):
        tcp(client, server, family)
        tcp(client, server, family, port=18081, allowed=False)
        tcp(client, server, family, wrong_source=True, allowed=False)
        tcp(client, server, family, destination=5, allowed=False)  # Jump matches; destination misses regular-chain return.
        tcp(client, server, family, destination=6)  # Base destination misses jump; existing default accept is preserved.
        tcp(client, server, family, port=18082, wrong_source=True)
        tcp(client, server, family, port=18082)
    require(counter('bridge') == 0, 'Bridge priority -5 drop reached the later -4 hook')
    inside(client, 'ip', 'link', 'set', 'eth0', 'address', '02:00:00:00:00:09')
    for address in ('192.0.2.2', '192.0.2.4', '2001:db8:1::2', '2001:db8:1::4'):
        inside(server, 'ip', 'neigh', 'replace', address, 'lladdr', '02:00:00:00:00:09', 'nud', 'permanent', 'dev', 'eth0')
    for family in (socket.AF_INET, socket.AF_INET6):
        tcp(client, server, family, allowed=False)
        tcp(client, server, family, port=18082)
    for address in ('192.0.2.2', '192.0.2.4', '2001:db8:1::2', '2001:db8:1::4'):
        inside(server, 'ip', 'neigh', 'replace', address, 'lladdr', '02:00:00:00:00:01', 'nud', 'permanent', 'dev', 'eth0')
    inside(client, 'ip', 'link', 'set', 'eth0', 'address', '02:00:00:00:00:01')
    inside(server, 'ip', 'link', 'set', 'eth0', 'address', '02:00:00:00:00:08')
    for address in ('192.0.2.3', '2001:db8:1::3'):
        inside(client, 'ip', 'neigh', 'replace', address, 'lladdr', '02:00:00:00:00:08', 'nud', 'permanent', 'dev', 'eth0')
    for family in (socket.AF_INET, socket.AF_INET6):
        tcp(client, server, family, allowed=False)
        tcp(client, server, family, port=18082)
    inside(server, 'ip', 'link', 'set', 'eth0', 'address', '02:00:00:00:00:02')
    for address in ('192.0.2.3', '2001:db8:1::3'):
        inside(client, 'ip', 'neigh', 'replace', address, 'lladdr', '02:00:00:00:00:02', 'nud', 'permanent', 'dev', 'eth0')
    run('ip', 'link', 'set', 'br0', 'name', 'br1')
    tcp(client, server, socket.AF_INET, port=18081)
    require(counter('bridge') > 0, 'Bridge-name exclusion did not reach the later hook')
    run('ip', 'link', 'set', 'br1', 'name', 'br0')


def topology():
    children = []
    try:
        run('ip', 'link', 'add', 'br0', 'type', 'bridge')
        run('ip', 'link', 'set', 'br0', 'up')
        for index in range(2):
            process = subprocess.Popen([sys.executable, '-c', "import os,signal; os.unshare(0x40000000); print('ready',flush=True); signal.pause()"], stdout=subprocess.PIPE)
            children.append(process)
            require(process.stdout.readline() == b'ready\n', 'Peer namespace missing')
            port = f'lan{index}'
            run('ip', 'link', 'add', port, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', str(process.pid))
            run('ip', 'link', 'set', port, 'master', 'br0')
            run('ip', 'link', 'set', port, 'up')
            inside(process, 'ip', 'link', 'set', 'lo', 'up')
            inside(process, 'ip', 'link', 'set', 'eth0', 'address', f'02:00:00:00:00:0{index + 1}')
            inside(process, 'ip', 'link', 'set', 'eth0', 'up')
            inside(process, 'ip', 'addr', 'add', f'192.0.2.{index + 2}/24', 'dev', 'eth0')
            inside(process, 'ip', '-6', 'addr', 'add', f'2001:db8:1::{index + 2}/64', 'dev', 'eth0', 'nodad')
        for peer, target, mac in [(children[0], 3, 2), (children[1], 2, 1)]:
            for address in (f'192.0.2.{target}', f'2001:db8:1::{target}'):
                inside(peer, 'ip', 'neigh', 'replace', address, 'lladdr', f'02:00:00:00:00:0{mac}', 'nud', 'permanent', 'dev', 'eth0')
        for address in ('192.0.2.4', '2001:db8:1::4'):
            inside(children[1], 'ip', 'neigh', 'replace', address, 'lladdr', '02:00:00:00:00:01', 'nud', 'permanent', 'dev', 'eth0')
        inside(children[0], 'ip', 'addr', 'add', '192.0.2.4/24', 'dev', 'eth0')
        inside(children[0], 'ip', '-6', 'addr', 'add', '2001:db8:1::4/64', 'dev', 'eth0', 'nodad')
        for target in (5, 6):
            inside(children[1], 'ip', 'addr', 'add', f'192.0.2.{target}/24', 'dev', 'eth0')
            inside(children[1], 'ip', '-6', 'addr', 'add', f'2001:db8:1::{target}/64', 'dev', 'eth0', 'nodad')
            for address in (f'192.0.2.{target}', f'2001:db8:1::{target}'):
                inside(children[0], 'ip', 'neigh', 'replace', address, 'lladdr', '02:00:00:00:00:02', 'nud', 'permanent', 'dev', 'eth0')
        return children
    except BaseException:
        for process in children:
            process.terminate()
            process.wait(timeout=5)
        raise


run('ip', 'link', 'set', 'lo', 'up')
for family, hook, port in [('inet', 'input', 19000), ('bridge', 'forward', 18081)]:
    nft(f'create table {family} foreign_probe\nadd chain {family} foreign_probe probe {{ type filter hook {hook} priority -4; policy accept; }}\nadd rule {family} foreign_probe probe {"udp" if family == "inet" else "tcp"} dport {port} counter\n')
foreign = {f: run('nft', '--stateless', 'list', 'table', f, 'foreign_probe') for f in ('inet', 'bridge')}
blocked = json.loads(run('dotnet', compiler, 'auxiliary-acceptance-json'))
opened = json.loads(run('dotnet', compiler, 'auxiliary-open-json'))
children = topology() if scenario in ('native', 'lifecycle') else []
process = None
try:
    if scenario == 'native':
        artifact = run('dotnet', compiler, 'auxiliary-acceptance-native')
        run('nft', '--check', '-f', '-', text=artifact)
        nft(artifact)
        for family in (socket.AF_INET, socket.AF_INET6):
            require(not udp(family, 19000), 'Early inet drop failed')
            require(not udp(family, 19001), 'Early inet accept bypassed the primary drop')
            require(udp(family, 19002), 'Unrelated loopback service failed')
        require(counter('inet') == 0, 'Early priority -5 drop reached later -4 hook')
        bridge_packets(children)
    else:
        with tempfile.TemporaryDirectory(prefix='nergal-auxiliary-') as temporary:
            root = Path(temporary)
            state = root / 'state'
            state.mkdir(mode=0o700)
            endpoint = root / 'control.sock'
            run('dotnet', agent, 'enroll', str(state))
            def start():
                p = subprocess.Popen(['dotnet', agent, 'control-serve', str(state), str(endpoint), '0'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                ready, _, _ = select.select([p.stdout], [], [], 10)
                require(ready and p.stdout.readline().strip() == 'Listening for authorized control requests.', 'Agent startup failed')
                return p
            def exchange(command, **fields):
                wire = json.dumps({'schemaVersion': 1, 'command': command, **fields}).encode()
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.settimeout(12)
                    client.connect(str(endpoint))
                    client.sendall(struct.pack('>I', len(wire)) + wire)
                    client.shutdown(socket.SHUT_WR)
                    def exact(length):
                        data = b''
                        while len(data) < length:
                            chunk = client.recv(length - len(data))
                            require(bool(chunk), 'Truncated agent reply')
                            data += chunk
                        return data
                    length = struct.unpack('>I', exact(4))[0]
                    require(0 < length <= 262144, 'Invalid reply length')
                    reply = json.loads(exact(length))
                    require(client.recv(1) == b'', 'Trailing reply bytes')
                    return reply
            def apply(bundle, timeout=30):
                op = str(uuid.uuid4())
                reply = exchange('prepare-apply', operationId=op, confirmationTimeoutSeconds=timeout, bundle=bundle)
                require(reply['outcome'] == 'appliedPendingConfirmation', f'Apply failed: {reply}')
                return op, reply['watchdogId']
            def complete(command, op, wd):
                reply = exchange(command, operationId=op, watchdogId=wd)
                require(reply['outcome'] == ('confirmed' if command == 'confirm' else 'rolledBack'), f'{command} failed: {reply}')
            process = start()
            if scenario == 'foreign-collision':
                nft('create table inet nergal_aux\n')
                before = snapshot()
                reply = exchange('prepare-apply', operationId=str(uuid.uuid4()), confirmationTimeoutSeconds=30, bundle=blocked)
                require(reply['outcome'] == 'drift' and snapshot() == before, 'Foreign auxiliary collision was modified')
            else:
                op, wd = apply(blocked, timeout=2 if scenario not in ('lifecycle', 'explicit-drift') else 30)
                if scenario == 'lifecycle':
                    for family in (socket.AF_INET, socket.AF_INET6):
                        require(not udp(family, 19000) and not udp(family, 19001) and udp(family, 19002), 'Initial agent packet enforcement differed')
                    require(counter('inet') == 0, 'Priority -5 ordering differed')
                    bridge_packets(children)
                    complete('confirm', op, wd)
                    primary = run('nft', '--stateless', 'list', 'table', 'inet', 'nergal_filter')
                    op, wd = apply(opened, timeout=2)
                    require(udp(socket.AF_INET, 19000), 'Auxiliary-only change not applied')
                    process.terminate()
                    process.communicate(timeout=10)
                    process = None
                    wait(lambda: not udp(socket.AF_INET, 19000), 'Independent watchdog did not restore packets after controller loss')
                    process = start()
                    wait(lambda: exchange('status')['outcome'] == 'matched', 'Restored receipt did not match after restart')
                    op, wd = apply(opened, timeout=4)
                    # Restart the actual independent watchdog using its protected operation identity.
                    matches = []
                    for path in Path('/proc').glob('[0-9]*/cmdline'):
                        try:
                            args = path.read_bytes().split(b'\0')
                            if b'watch' in args and op.encode() in args and str(state).encode() in args:
                                matches.append(int(path.parent.name))
                        except (FileNotFoundError, PermissionError):
                            pass
                    require(len(matches) == 1, 'Independent watchdog identity ambiguous')
                    os.kill(matches[0], signal.SIGKILL)
                    watcher = subprocess.Popen(['dotnet', agent, 'watch', str(state), op, wd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    ready, _, _ = select.select([watcher.stdout], [], [], 10)
                    require(ready and watcher.stdout.readline().strip() == 'WATCHING', 'Restarted watchdog did not arm')
                    output, error = watcher.communicate(timeout=12)
                    require(watcher.returncode == 0 and output.strip() == 'RolledBack', 'Restarted watchdog failed: ' + error)
                    require(not udp(socket.AF_INET6, 19000), 'Restarted watchdog did not restore IPv6 packets')
                    op, wd = apply(opened)
                    complete('confirm', op, wd)
                    process.terminate()
                    process.communicate(timeout=10)
                    process = start()
                    require(exchange('status')['outcome'] == 'matched' and udp(socket.AF_INET6, 19000), 'Confirmed auxiliary policy did not survive agent restart')
                    op, wd = apply(blocked)
                    complete('rollback', op, wd)
                    require(udp(socket.AF_INET, 19000) and udp(socket.AF_INET6, 19000), 'Explicit rollback lost confirmed auxiliary policy')
                    filter_only = {'schemaVersion': 1, 'filter': opened['filter']}
                    op, wd = apply(filter_only)
                    require('nergal_aux' not in snapshot() and 'nergal_bridge' not in snapshot(), 'Auxiliary table removal failed')
                    complete('rollback', op, wd)
                    require(exchange('status')['outcome'] == 'matched', 'Rollback failed to recreate removed auxiliary scope')
                    require(run('nft', '--stateless', 'list', 'table', 'inet', 'nergal_filter') == primary, 'Auxiliary-only lifecycle changed primary semantics')
                else:
                    if scenario == 'timeout-recreated':
                        table = run('nft', '--stateless', 'list', 'table', 'inet', 'nergal_aux')
                        nft('delete table inet nergal_aux\n' + table)
                    elif scenario == 'missing-table':
                        nft('delete table inet nergal_aux\n')
                    elif scenario == 'nat-set-drift':
                        listed = json.loads(run('nft', '--handle', '--json', 'list', 'table', 'inet', 'nergal_nat'))
                        handle = next(item['rule']['handle'] for item in listed['nftables'] if 'rule' in item and item['rule']['chain'] == 'postrouting')
                        nft(f'replace rule inet nergal_nat postrouting handle {handle} meta nfproto ipv4 ip saddr {{ 192.0.2.0/24, 198.51.100.0/24 }} ip daddr {{ 203.0.113.30, 203.0.113.40 }} return\n')
                    elif scenario == 'bridge-set-drift':
                        listed = json.loads(run('nft', '--handle', '--json', 'list', 'table', 'bridge', 'nergal_bridge'))
                        handle = next(item['rule']['handle'] for item in listed['nftables'] if 'rule' in item and item['rule']['chain'] == 'service' and any('return' in expr for expr in item['rule']['expr']))
                        nft(f'replace rule bridge nergal_bridge service handle {handle} ether saddr 02:00:00:00:00:01 ether type ip ip saddr {{ 192.0.2.2, 192.0.2.90 }} ip daddr {{ 192.0.2.30, 192.0.2.99 }} tcp dport 18080 return\n')
                    elif scenario == 'unknown-expression':
                        nft('add rule inet nergal_aux input counter\n')
                    else:
                        nft('add rule inet nergal_aux input udp dport 19005 drop\n')
                    before = snapshot()
                    if scenario == 'explicit-drift':
                        reply = exchange('rollback', operationId=op, watchdogId=wd)
                        require(reply['activePhase'] == 'recoveryRequired', 'Explicit rollback ignored auxiliary drift')
                    wait(lambda: exchange('status').get('activePhase') == 'recoveryRequired', 'Unexpected native state was not recovery-blocked')
                    require(snapshot() == before, 'Recovery overwrote drifted, recreated, missing or unknown native state')
    for family, expected in foreign.items():
        require(run('nft', '--stateless', 'list', 'table', family, 'foreign_probe') == expected, 'Foreign probe semantics changed')
    print('PASS: auxiliary acceptance ' + scenario, flush=True)
finally:
    if process is not None:
        process.terminate()
        process.communicate(timeout=10)
    for child in children:
        child.terminate()
        child.wait(timeout=5)
