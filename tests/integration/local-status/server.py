"""Independent Unix wire server. Only an inherited test-owned listener and synthetic reply spec are accepted."""
import json
import os
import select
import socket
import struct
import sys

spec = json.load(sys.stdin)
assert os.geteuid() == spec['uid'], 'Server credential drop failed'
with socket.socket(fileno=spec['fd']) as listener:
    listener.listen(1)  # Peer credentials must reflect this process, not the parent that bound the test inode.
    print('READY', flush=True)
    connection, _ = listener.accept()
    with connection:
        connection.settimeout(5)
        request = b''
        while True:
            part = connection.recv(8192)
            if not part:
                break
            request += part
            assert len(request) <= 4100, 'Client sent unbounded data'
        if spec['mode'] == 'wrong-peer':
            assert request == b'', 'Client sent intent before kernel server authentication'
            print('NO_REQUEST', flush=True)
        else:
            expected = b'{"schemaVersion":1,"command":"status"}'
            assert request == struct.pack('>I', len(expected)) + expected, 'Client request or half-close differs'
            wire = bytes.fromhex(spec['wire'])
            try:
                if spec.get('fragmented'):
                    for value in wire:
                        connection.sendall(bytes([value]))
                else:
                    connection.sendall(wire)
                if spec['mode'] in ('blocked', 'cancel'):
                    # Request EOF is only SHUT_WR, not full disconnect. Wait for HUP
                    # so the server does not accidentally close the reply side early.
                    poll = select.poll()
                    poll.register(connection, select.POLLHUP | select.POLLERR)
                    assert poll.poll(5000), 'Client did not close on deadline/cancellation'
            except (BrokenPipeError, ConnectionResetError):
                assert spec['mode'] != 'valid', 'Client rejected a valid reply'
            print('SERVED', flush=True)
