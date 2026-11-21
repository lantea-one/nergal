"""Protected expected receipts plus actual kernel observations, inside fresh disposable namespaces."""
import json
import os
import select
import socket
import struct
from pathlib import Path
import subprocess
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise AssertionError(message)


require(len(sys.argv) == 5, 'Invoke through check.sh')
assembly, scenario, parent_user, parent_net = sys.argv[1:]
require(os.readlink('/proc/self/ns/user') != parent_user, 'User isolation missing')
require(os.readlink('/proc/self/ns/net') != parent_net, 'Network isolation missing')
require(os.getuid() == 0, 'Namespace root required')


def run(arguments, text=None, success=True, error=None):
    try:
        result = subprocess.run(arguments, input=text, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        raise AssertionError('Conformance process timed out') from None
    require((result.returncode == 0) == success, 'Unexpected conformance result')
    if error:
        require(result.stderr.strip() == error, 'Expected protected-state denial code missing')
    return result.stdout


def nft(text, success=True, check=False):
    return run(['nft'] + (['--check'] if check else []) + ['--file', '-'], text, success)


def observation():
    return run(['nft', '--json', 'list', 'table', 'inet', 'nergal_filter'])


for family in ('ip', 'ip6', 'inet', 'bridge'):
    nft(f'create table {family} foreign_fixture\nadd chain {family} foreign_fixture sentinel\n')
foreign = {family: run(['nft', '--stateless', 'list', 'table', family, 'foreign_fixture'])
           for family in ('ip', 'ip6', 'inet', 'bridge')}
with tempfile.TemporaryDirectory(prefix='nergal-enrollment-') as state:
    os.chmod(state, 0o700)

    def probe(mode, text=None, success=True, error=None):
        return run(['dotnet', assembly, mode, state], text, success, error)

    if scenario in ('cli', 'cli-collision'):
        agent = Path('src/Nergal.Agent/bin/Release/net10.0/nergal-agent.dll').resolve()
        command = ['dotnet', str(agent), 'enroll', state]
        if scenario == 'cli-collision':
            nft(probe('foreign'))
            original = observation()
            run(command, success=False)
            require(observation() == original and probe('receipt').strip() == 'UNBOUND', 'Collision changed ownership')
        else:
            run(command)
            original = observation()
            require(json.loads(probe('verify', original))['IsMatch'], 'CLI failed to bind the independently listed table')
            listed = json.loads(original)['nftables']
            require(len(listed) == 3 and listed[2]['chain']['policy'] == 'accept', 'Unexpected filtering policy')
        receipt = probe('receipt')
        run(command, success=False, error='journal.exists')
        require(observation() == original and probe('receipt') == receipt, 'Repeat invocation mutated protected state')
        if scenario == 'cli':
            socket_path = Path(state) / 'status.sock'
            database = Path(state) / 'journal.db'
            protected = database.read_bytes()
            listener = subprocess.Popen(
                ['dotnet', str(agent), 'status-serve', state, str(socket_path), '0'],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready, _, _ = select.select([listener.stdout], [], [], 10)
                require(ready and listener.stdout.readline().strip() == 'Listening for authorized status queries.',
                        'Agent status-serve did not announce readiness')

                def query_status():
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                        client.settimeout(5)
                        client.connect(str(socket_path))
                        request_payload = b'{"schemaVersion":1,"command":"status"}'
                        client.sendall(struct.pack('>I', len(request_payload)) + request_payload)
                        client.shutdown(socket.SHUT_WR)
                        header = b''
                        while len(header) < 4:
                            chunk = client.recv(4 - len(header))
                            require(bool(chunk), 'Incomplete reply length from status-serve')
                            header += chunk
                        length = struct.unpack('>I', header)[0]
                        body = b''
                        while len(body) < length:
                            chunk = client.recv(length - len(body))
                            require(bool(chunk), 'Truncated reply from status-serve')
                            body += chunk
                        require(client.recv(1) == b'', 'Unexpected trailing bytes from status-serve')
                        return json.loads(body.decode('utf-8'))

                require(query_status() == {'schemaVersion': 1, 'outcome': 'matched', 'revision': '1'},
                        'status-serve did not classify enrolled baseline as matched')
                nft('add chain inet nergal_filter input { policy drop; }\n')
                require(query_status() == {'schemaVersion': 1, 'outcome': 'drift', 'revision': '1'},
                        'status-serve did not detect kernel policy drift')
                require(database.read_bytes() == protected, 'status-serve mutated protected state')
                listener.terminate()
                listener.communicate(timeout=10)
                require(listener.returncode == 0, f'status-serve did not exit cleanly on SIGTERM: {listener.returncode}')
                require(not socket_path.exists(), 'status-serve did not unlink its owned socket on SIGTERM')
            finally:
                if listener.poll() is None:
                    listener.kill()
                    listener.communicate(timeout=5)
        print('PASS: local CLI exclusive creation, receipt and retry contract: ' + scenario, flush=True)
    else:
        mode = 'prepare-family' if scenario == 'family' else ('prepare-schema1' if scenario == 'schema1' else 'prepare')
        candidate = probe(mode)  # Protected intent exists before any exclusive resource creation.
        if scenario == 'collision':
            nft(probe('foreign'))
            before = run(['nft', '--stateless', 'list', 'ruleset'])
            nft(candidate, success=False, check=True)
            nft(candidate, success=False)
            probe('bind', observation(), False, 'ownership.stale')
            require(probe('receipt').strip() == 'UNBOUND', 'Foreign table was adopted')
            require(run(['nft', '--stateless', 'list', 'ruleset']) == before, 'Conflicting foreign resource changed')
            print('PASS: conflicting native resource is preserved and cannot be bound', flush=True)
        elif scenario == 'schema1':
            run(['ip', 'link', 'set', 'lo', 'up'])
            def udp_allowed(family, address, port):
                with socket.socket(family, socket.SOCK_DGRAM) as receiver, socket.socket(family, socket.SOCK_DGRAM) as sender:
                    receiver.bind((address, port))
                    receiver.settimeout(0.4)
                    sender.sendto(b'schema1', (address, port))
                    try:
                        return receiver.recv(32) == b'schema1'
                    except TimeoutError:
                        return False

            require(udp_allowed(socket.AF_INET, '127.0.0.1', 18099) and udp_allowed(socket.AF_INET6, '::1', 18099),
                    'Loopback UDP baseline check failed')
            nft(candidate, check=True)
            nft(candidate)
            probe('bind', observation())
            require(json.loads(probe('verify', observation()))['IsMatch'], 'Full schema-1 baseline failed to bind')
            receipt = probe('receipt')
            require(udp_allowed(socket.AF_INET, '127.0.0.1', 18091), 'Permitted schema-1 UDP port failed')
            require(not udp_allowed(socket.AF_INET, '127.0.0.1', 18099), 'Unmatched IPv4 UDP was not dropped')
            require(not udp_allowed(socket.AF_INET6, '::1', 18099), 'Unmatched IPv6 UDP was not dropped')
            nft('add rule inet nergal_filter input meta nfproto ipv4 udp dport 18099 accept\n')
            require(udp_allowed(socket.AF_INET, '127.0.0.1', 18099), 'Added schema-1 UDP rule did not take effect')
            require('state.drift' in json.loads(probe('verify', observation(), False))['ErrorCodes'], 'Schema-1 rule drift missed')
            probe('bind', observation(), False, 'resource.baselineMismatch')
            nft('add rule inet nergal_filter input meta nfproto ipv4 counter accept\n')
            probe('verify', observation(), False, 'observation.rule')
            require(probe('receipt') == receipt, 'Schema-1 drift or unsupported counter modified receipt')
            print('PASS: full schema-1 receipt binds CIDR/protocol/port rules, matches packets, and detects drift', flush=True)
        elif scenario == 'family':
            run(['ip', 'link', 'set', 'lo', 'up'])
            def packet(family, address):
                with socket.socket(family, socket.SOCK_DGRAM) as receiver, socket.socket(family, socket.SOCK_DGRAM) as sender:
                    receiver.bind((address, 0))
                    receiver.settimeout(0.5)
                    sender.sendto(b'fixture', receiver.getsockname())
                    try:
                        return receiver.recv(32) == b'fixture'
                    except TimeoutError:
                        return False

            require(packet(socket.AF_INET, '127.0.0.1') and packet(socket.AF_INET6, '::1'), 'Loopback control failed')
            nft(candidate, check=True)
            nft(candidate)
            probe('bind', observation())
            require(json.loads(probe('verify', observation()))['IsMatch'], 'Ordered family baseline failed to bind')
            require(not packet(socket.AF_INET, '127.0.0.1') and packet(socket.AF_INET6, '::1'), 'Family packet decisions differed')
            receipt = probe('receipt')
            nft('insert rule inet nergal_filter input meta nfproto ipv4 accept\n')
            require(packet(socket.AF_INET, '127.0.0.1'), 'Inserted first verdict did not change IPv4 outcome')
            require('state.drift' in json.loads(probe('verify', observation(), False))['ErrorCodes'], 'Ordered rule drift missed')
            probe('bind', observation(), False, 'resource.baselineMismatch')
            nft('add rule inet nergal_filter input meta nfproto ipv4 counter accept\n')
            probe('verify', observation(), False, 'observation.rule')
            require(probe('receipt') == receipt, 'Drift or unsupported expressions changed the stored receipt')
            print('PASS: rule-bearing receipt matches dual-stack packet outcomes and detects ordered changes', flush=True)
        else:
            nft(candidate, check=True)
            nft(candidate)
            original = observation()
            probe('verify', original, False, 'resource.unbound')
            probe('bind', original)
            receipt = probe('receipt')
            database = Path(state) / 'journal.db'
            protected = database.read_bytes()
            probe('bind', original)  # Lost-ack retry is idempotent, not a new enrollment.
            require(json.loads(probe('verify', original))['IsMatch'], 'Protected receipt did not survive reopen')
            probe('try-start', success=False, error='resource.boundApplyUnavailable')
            require(database.read_bytes() == protected, 'Read-only reconciliation or denied apply changed state')
            print('PASS: protected intent binds once, reopens, verifies and disables legacy apply', flush=True)

            nft('add chain inet nergal_filter input { policy drop; }\n')
            mismatch = json.loads(probe('verify', observation(), False))
            require('state.drift' in mismatch['ErrorCodes'], 'Policy drift was accepted')
            probe('bind', observation(), False, 'resource.baselineMismatch')
            nft('add chain inet nergal_filter input { policy accept; }\n')
            nft('delete table inet nergal_filter\n' + candidate)
            replacement = observation()
            mismatch = json.loads(probe('verify', replacement, False))
            require('handle.mismatch' in mismatch['ErrorCodes'], 'Recreated table was accepted')
            probe('bind', replacement, False, 'resource.alreadyBound')
            require(probe('receipt') == receipt and database.read_bytes() == protected, 'Rejected state replaced the protected receipt')
            print('PASS: policy drift and copied-marker recreation cannot rewrite protected expected state', flush=True)

            payload = json.dumps({'candidate': candidate, 'state': state})
            run(['unshare', '--net', sys.executable, str(Path(__file__).with_name('other_namespace.py')), assembly], payload)
            require(probe('receipt') == receipt and database.read_bytes() == protected, 'Cross-namespace check changed protected state')
            print('PASS: a second real namespace cannot satisfy the protected receipt', flush=True)

    for family, before in foreign.items():
        require(run(['nft', '--stateless', 'list', 'table', family, 'foreign_fixture']) == before, 'Foreign table changed')
    print('PASS: foreign ip/ip6/inet/bridge sentinel tables preserved', flush=True)
