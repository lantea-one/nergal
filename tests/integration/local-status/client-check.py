"""Real unprivileged managed client against independent, hostile Unix wire servers; no firewall access."""
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
from runtime import stage_client_runtime


def require(condition, message):
    if not condition:
        raise AssertionError(message)


require(len(sys.argv) == 4, 'Invoke through check.sh')
assembly, parent_user, parent_net = sys.argv[1:]
require(os.readlink('/proc/self/ns/user') != parent_user, 'User isolation missing')
require(os.readlink('/proc/self/ns/net') != parent_net, 'Network isolation missing')
require(os.getuid() == 0, 'Namespace root required')
server_code = Path(__file__).with_name('server.py').read_text()


def drop(uid):
    def action():
        try:
            os.setgroups([])
        except PermissionError:
            pass
        os.setgid(1)
        os.setuid(uid)
    return action


with tempfile.TemporaryDirectory(prefix='nergal-client-') as root:
    root = Path(root)
    os.chmod(root, 0o711)
    dotnet, assembly = stage_client_runtime(root, assembly)
    endpoint = root / 'endpoint'
    endpoint.mkdir()
    os.chown(endpoint, 0, 1)
    os.chmod(endpoint, 0o2710)
    path = endpoint / 'status.sock'
    # Each client gets a private runtime home; it never writes the service-owned endpoint directory.
    client_home = root / 'client'
    client_home.mkdir(mode=0o700)
    os.chown(client_home, 1, 1)
    client_env = {'PATH': os.defpath, 'LANG': 'C.UTF-8', 'DOTNET_CLI_HOME': str(client_home),
                  'DOTNET_ROOT': str(Path(dotnet).parent), 'DOTNET_CLI_TELEMETRY_OPTOUT': '1',
                  'DOTNET_SKIP_FIRST_TIME_EXPERIENCE': '1', 'DOTNET_NOLOGO': '1'}

    def query(expected='0', cancel=False):
        return subprocess.run([dotnet, assembly, 'query-cancel' if cancel else 'query', expected, str(path), parent_user, parent_net],
                              preexec_fn=drop(1), env=client_env, capture_output=True, text=True, timeout=8)

    def frame(payload):
        return struct.pack('>I', len(payload)) + payload

    def scenario(wire, expected_code=None, expected_reply=None, mode='invalid', fragmented=False, server_uid=0):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            os.chown(path, 0, 1)
            os.chmod(path, 0o660)
            spec = {'fd': listener.fileno(), 'uid': server_uid, 'mode': mode, 'wire': wire.hex(), 'fragmented': fragmented}
            server = subprocess.Popen([sys.executable, '-c', server_code], pass_fds=(listener.fileno(),), preexec_fn=drop(server_uid),
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                server.stdin.write(json.dumps(spec))
                server.stdin.close()
                ready, _, _ = select.select([server.stdout], [], [], 5)
                require(ready and server.stdout.readline().strip() == 'READY', 'Independent server not ready')
                result = query(cancel=mode == 'cancel')
                if expected_code:
                    require(result.returncode == 1 and result.stderr.strip() == expected_code and result.stdout == '',
                            f'Client expected {expected_code}, got {result.returncode}: {result.stderr} {result.stdout}')
                else:
                    require(result.returncode == 0 and json.loads(result.stdout) == expected_reply,
                            f'Client valid reply failed: {result.stderr}')
                require(server.wait(timeout=5) == 0, 'Independent server failed: ' + server.stderr.read())
                require(server.stdout.read().strip() == ('NO_REQUEST' if mode == 'wrong-peer' else 'SERVED'), 'Server observation missing')
                require(path.is_socket() and path.stat().st_uid == 0, 'Client modified server pathname')
            finally:
                if server.poll() is None:
                    server.kill()
                    server.wait(timeout=5)
                path.unlink()

    scenario(b'', 'server.denied', mode='wrong-peer', server_uid=2)
    print('PASS: filesystem-owned endpoint with wrong kernel peer UID receives no request bytes', flush=True)
    for outcome in ('matched', 'drift', 'unbound', 'denied', 'invalidRequest', 'unavailable'):
        reply = {'schemaVersion': 1, 'outcome': outcome}
        if outcome in ('matched', 'drift', 'unbound'):
            reply['revision'] = '18446744073709551615'
        scenario(frame(json.dumps(reply).encode()), expected_reply=reply, mode='valid', fragmented=True)
    print('PASS: all typed replies and full UInt64 revisions survive independent fragmented exchanges', flush=True)
    good = frame(b'{"schemaVersion":1,"outcome":"matched","revision":"1"}')
    malformed = [b'', b'\x00\x00', struct.pack('>I', 0), struct.pack('>I', 4097), struct.pack('>I', 0xffffffff),
                 good[:-1], good + b'extra', frame(b'not json'),
                 frame(b'{"schemaVersion":1,"outcome":"denied","revision":"1"}'),
                 frame(b'{"schemaVersion":1,"outcome":"matched","revision":1}'),
                 frame(b'{"schemaVersion":1,"outcome":"matched","revision":"01"}'),
                 frame(b'{"schemaVersion":1,"outcome":"matched","revision":"0"}'),
                 frame(b'{"schemaVersion":1,"outcome":"matched","revision":"18446744073709551616"}'),
                 frame(b'{"schemaVersion":2,"outcome":"denied"}'),
                 frame(b'{"schemaVersion":1,"outcome":"denied","outcome":"matched"}'),
                 frame(b'{"schemaVersion":1,"outcome":"applied"}')]
    for wire in malformed:
        scenario(wire, 'reply.invalid')
    scenario(b'', 'exchange.timeout', mode='blocked')
    scenario(good, 'exchange.timeout', mode='blocked')  # Complete-looking frame without reply EOF is not success.
    scenario(b'', 'query.canceled', mode='cancel')
    print('PASS: malformed/truncated/trailing replies fail without partial status; missing data/EOF and cancellation are bounded', flush=True)

    missing = query()
    require(missing.returncode == 1 and missing.stderr.strip() == 'socket.missing', 'Missing endpoint was accepted')
    path.write_text('foreign file')
    os.chown(path, 0, 1)
    os.chmod(path, 0o660)
    rejected = query()
    require(rejected.returncode == 1 and rejected.stderr.strip() == 'socket.metadata', 'Regular-file endpoint was accepted')
    require(path.read_text() == 'foreign file', 'Client modified foreign file')
    path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        os.chown(path, 0, 1)
        os.chmod(path, 0o666)
        rejected = query()
        require(rejected.returncode == 1 and rejected.stderr.strip() == 'socket.metadata', 'Public-write endpoint accepted')
        os.chmod(path, 0o660)
        os.link(path, root / 'socket-alias')
        rejected = query()
        require(rejected.returncode == 1 and rejected.stderr.strip() == 'socket.metadata', 'Shared socket inode accepted')
        (root / 'socket-alias').unlink()
        os.chmod(endpoint, 0o2770)
        rejected = query()
        require(rejected.returncode == 1 and rejected.stderr.strip() == 'socket.parentPolicy', 'Writable shared parent accepted')
        os.chmod(endpoint, 0o2710)
        overflow = Path('/proc/sys/kernel/overflowuid').read_text().strip()
        rejected = query(expected=overflow)
        require(rejected.returncode == 1 and rejected.stderr.strip() == 'peer.overflowUid', 'Overflow server authority accepted')
        path.unlink()
    print('PASS: missing/foreign/unsafe/shared-inode endpoints and ambiguous overflow authority fail closed without writes', flush=True)
