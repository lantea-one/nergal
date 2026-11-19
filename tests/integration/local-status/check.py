"""Actual Unix sockets/SO_PEERCRED and protected native read-only status in disposable multi-UID namespaces."""
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import sys
import tempfile
from runtime import stage_client_runtime
from browser_status import verify_browser_status


def require(condition, message):
    if not condition:
        raise AssertionError(message)


require(len(sys.argv) == 5, 'Invoke through check.sh')
assembly, enrollment, parent_user, parent_net = sys.argv[1:]
require(os.readlink('/proc/self/ns/user') != parent_user, 'User isolation missing')
require(os.readlink('/proc/self/ns/net') != parent_net, 'Network isolation missing')
require(os.getuid() == 0, 'Namespace root required')
maps = [tuple(map(int, line.split())) for line in Path('/proc/self/uid_map').read_text().splitlines()]
require(any(start <= 2 < start + count for start, _, count in maps), 'Mapped controller/browser UIDs required')
client_code = Path(__file__).with_name('client.py').read_text()


def run(arguments, text=None):
    result = subprocess.run(arguments, input=text, capture_output=True, text=True, timeout=10)
    require(result.returncode == 0, 'Conformance subprocess failed')
    return result.stdout


def nft(text):
    run(['nft', '--file', '-'], text)


for family in ('ip', 'ip6', 'inet', 'bridge'):
    nft(f'create table {family} foreign_fixture\nadd chain {family} foreign_fixture sentinel\n')
foreign = {family: run(['nft', '--stateless', 'list', 'table', family, 'foreign_fixture'])
           for family in ('ip', 'ip6', 'inet', 'bridge')}
children = []
with tempfile.TemporaryDirectory(prefix='nergal-status-') as root:
    root = Path(root)
    os.chmod(root, 0o711)
    client_dotnet, client_assembly = stage_client_runtime(root, assembly)
    state = root / 'agent'
    state.mkdir(mode=0o700)
    endpoint = root / 'endpoint'
    endpoint.mkdir(mode=0o700)
    os.chown(endpoint, 0, 1)
    os.chmod(endpoint, 0o2710)
    socket_path = endpoint / 'status.sock'
    database = state / 'journal.db'
    count_file = state / 'provider-count'
    baseline = run(['dotnet', enrollment, 'prepare', str(state)])
    nft(baseline)
    observed = run(['nft', '--json', 'list', 'table', 'inet', 'nergal_filter'])
    run(['dotnet', enrollment, 'bind', str(state)], observed)
    protected = database.read_bytes()

    def command(mode='serve'):
        return ['dotnet', assembly, mode, str(state), str(socket_path), parent_user, parent_net]

    def start(mode='serve'):
        process = subprocess.Popen(command(mode), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        children.append(process)
        ready, _, _ = select.select([process.stdout], [], [], 10)
        require(ready and process.stdout.readline().strip() == 'READY', 'Listener failed to acknowledge readiness')
        return process

    def stop(process, success=True, code=None):
        output, error = process.communicate('stop\n', timeout=8)
        require((process.returncode == 0) == success, 'Listener stop outcome differed')
        if code:
            require(error.strip() == code, 'Listener ownership failure code missing')

    def count():
        return int(count_file.read_text())

    def frame(payload):
        return struct.pack('>I', len(payload)) + payload

    def client(uid, wire=b'', outcome='invalidRequest', half_close=True, closed=False, fragmented=False):
        spec = {'uid': uid, 'socket': str(socket_path), 'database': str(database), 'wire': wire.hex(),
                'outcome': outcome, 'halfClose': half_close, 'closed': closed, 'fragmented': fragmented}

        def drop():
            try:
                os.setgroups([])
            except PermissionError:
                pass
            os.setgid(1)  # Both controller and browser can traverse/connect; UID authorization must still differ.
            os.setuid(uid)

        result = subprocess.run([sys.executable, '-c', client_code], input=json.dumps(spec), capture_output=True,
                                text=True, timeout=7, preexec_fn=drop,
                                env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
        require(result.returncode == 0, f'Client conformance failed for {outcome}: {result.stderr}')
        require(result.stdout.strip() == ('CLOSED' if closed else 'OK'), 'Client outcome missing')

    def managed_client(outcome):
        def drop():
            try:
                os.setgroups([])
            except PermissionError:
                pass
            os.setgid(1)
            os.setuid(1)
        result = subprocess.run([client_dotnet, client_assembly, 'query', '0', str(socket_path), parent_user, parent_net],
                                preexec_fn=drop, capture_output=True, text=True, timeout=8,
                                env={'PATH': os.defpath, 'LANG': 'C.UTF-8', 'DOTNET_ROOT': str(Path(client_dotnet).parent)})
        require(result.returncode == 0, 'Managed client query failed: ' + result.stderr)
        require(json.loads(result.stdout) == {'schemaVersion': 1, 'outcome': outcome, 'revision': '1'}, 'Managed native status differs')

    try:
        os.chmod(endpoint, 0o2770)
        rejected = subprocess.run(command(), stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
        require(rejected.returncode == 1 and rejected.stderr.strip() == 'socket.parentPolicy', 'Writable shared parent was accepted')
        require(not socket_path.exists(), 'Unsafe parent created a listener')
        os.chmod(endpoint, 0o2710)
        linked = root / 'linked'
        linked.symlink_to(endpoint)
        linked_command = command()
        linked_command[4] = str(linked / 'status.sock')
        rejected = subprocess.run(linked_command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
        require(rejected.returncode == 1 and rejected.stderr.strip() == 'socket.symlink', 'Symlink parent was accepted')
        # Startup may not adopt/unlink even a stale-looking foreign path.
        socket_path.write_text('foreign sentinel')
        os.chown(socket_path, 2, 1)
        before = socket_path.read_bytes()
        rejected = subprocess.run(command(), stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
        require(rejected.returncode == 1 and rejected.stderr.strip() == 'socket.exists', 'Existing path was accepted')
        require(socket_path.read_bytes() == before, 'Existing path was changed')
        socket_path.unlink()  # Test-owned sentinel teardown only.
        rejected = subprocess.run(command('overflow'), stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
        require(rejected.returncode == 1 and rejected.stderr.strip() == 'peer.overflowUid', 'Overflow UID was trusted')
        require(not socket_path.exists(), 'Rejected startup created a listener')
        print('PASS: preexisting path preserved and ambiguous overflow authority refused', flush=True)

        server = start()
        client(2, outcome='denied', half_close=False)  # No bytes: rejection must precede any framing read.
        client(0, outcome='denied', half_close=False)  # Root is not implicitly trusted.
        require(count() == 0, 'Unauthorized peer reached the provider')
        good = b'{"schemaVersion":1,"command":"status"}'
        bad = [
            frame(b'{"schemaVersion":1,"command":"apply"}'),
            frame(b'{"schemaVersion":1,"command":"status","uid":1}'),
            frame(b'{"schemaVersion":1,"command":"status","command":"apply"}'),
            frame(b'{"schemaVersion":2,"command":"status"}'),
            frame(b'flush ruleset'),
            struct.pack('>I', 0), struct.pack('>I', 0xffffffff), b'\x00\x00',
            frame(good) + b'extra',
        ]
        for wire in bad:
            client(1, wire)
        client(1, frame(good), half_close=False, closed=True)
        require(count() == 0, 'Malformed/incomplete/unknown request reached the provider')
        print('PASS: kernel UID authorization, no implicit root, bounded invalid frames and no provider dispatch', flush=True)

        client(1, frame(good), 'matched', fragmented=True)
        require(count() == 1, 'Authorized fragmented status did not reach the real provider once')
        managed_client('matched')
        require(count() == 2, 'Managed matched query did not reach the provider once')
        verify_browser_status(root, client_dotnet, socket_path, count)
        nft('add chain inet nergal_filter input { policy drop; }\n')
        client(1, frame(good), 'drift')
        managed_client('drift')
        require(count() == 5 and database.read_bytes() == protected, 'Read-only status modified protected state')
        print('PASS: independent client reads real matched/drift status without direct journal access or state writes', flush=True)

        database.write_bytes(b'corrupt synthetic journal')
        client(2, outcome='denied', half_close=False)
        require(count() == 5, 'Denied peer probed a corrupt journal')
        client(1, frame(good), 'unavailable')
        require(count() == 6 and database.read_bytes() == b'corrupt synthetic journal', 'Unavailable status repaired or exposed state')
        stop(server)
        require(not socket_path.exists(), 'Owned listener path was not cleaned up')
        print('PASS: corrupt state is unavailable only to authorized status, with metadata-free denial/error replies', flush=True)

        server = start('slow')
        client(1, frame(good), closed=True)
        require(count() == 1, 'Slow provider was not invoked once')
        client(2, outcome='denied', half_close=False)
        require(count() == 1, 'Expired provider exchange compromised subsequent authorization')
        stop(server)
        print('PASS: provider deadline closes the exchange and listener continues authorizing peers', flush=True)

        server = start()
        socket_path.rename(root / 'moved.socket')
        socket_path.write_text('replacement foreign sentinel')
        os.chown(socket_path, 2, 1)
        stop(server, success=False, code='socket.pathChanged')
        require(socket_path.read_text() == 'replacement foreign sentinel', 'Cleanup removed a foreign replacement path')
        print('PASS: shutdown refuses to unlink a replaced socket pathname', flush=True)
        for family, original in foreign.items():
            require(run(['nft', '--stateless', 'list', 'table', family, 'foreign_fixture']) == original, 'Foreign table changed')
        print('PASS: all native provider operations were read-only and foreign tables preserved', flush=True)
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)
