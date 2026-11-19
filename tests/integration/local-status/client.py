"""Independent wire client after real UID/GID drop and exec; no inherited agent artifact memory."""
import json
import os
from pathlib import Path
import socket
import struct
import sys

spec = json.load(sys.stdin)
assert os.geteuid() == spec['uid'], 'Client credential drop failed'
if spec['uid'] != 0:
    cap = next(line for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:'))
    assert int(cap.split()[1], 16) == 0, 'Client retained effective capabilities'
    try:
        Path(spec['database']).read_bytes()
    except PermissionError:
        pass
    else:
        raise AssertionError('Controller/browser could directly read agent state')


def exact(connection, size):
    result = b''
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        assert chunk, 'Incomplete reply frame'
        result += chunk
    return result


with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.settimeout(4)
    connection.connect(spec['socket'])  # Group permits both roles; the server must separately authorize UID.
    _, server_uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    assert server_uid == 0, 'Unexpected agent peer identity'
    wire = bytes.fromhex(spec.get('wire', ''))
    if spec.get('fragmented'):
        for value in wire:
            connection.sendall(bytes([value]))
    elif wire:
        connection.sendall(wire)
    if spec.get('halfClose', True):
        connection.shutdown(socket.SHUT_WR)
    if spec.get('closed'):
        assert connection.recv(1) == b'', 'Expired exchange was not closed'
        print('CLOSED')
    else:
        size = struct.unpack('>I', exact(connection, 4))[0]
        assert 1 <= size <= 4096, 'Invalid reply size'
        reply = json.loads(exact(connection, size))
        try:
            assert connection.recv(1) == b'', 'Unexpected extra reply bytes'
        except ConnectionResetError:
            # Rejected surplus bytes are deliberately not drained without bound.
            assert spec['outcome'] == 'invalidRequest', 'Valid exchange reset after reply'
        assert reply['schemaVersion'] == 1 and reply['outcome'] == spec['outcome'], 'Unexpected reply classification'
        if spec['outcome'] in ('matched', 'drift', 'unbound'):
            assert set(reply) == {'schemaVersion', 'outcome', 'revision'} and reply['revision'] == '1', 'Invalid resource revision'
        else:
            assert set(reply) == {'schemaVersion', 'outcome'}, 'Denial/error disclosed resource metadata'
        print('OK')
