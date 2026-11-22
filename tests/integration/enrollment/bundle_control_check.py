"""Synthetic same-UID multi-table receipt/apply regression in disposable namespaces.

This supplements, and never substitutes for, distinct mapped-UID authorization tests.
"""
import json
import os
from pathlib import Path
import select
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


agent, parent_user, parent_net = sys.argv[1:]
require(os.readlink('/proc/self/ns/user') != parent_user, 'User isolation missing')
require(os.readlink('/proc/self/ns/net') != parent_net, 'Network isolation missing')
require(os.getuid() == 0, 'Namespace root required')


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=15).stdout


run('ip', 'link', 'set', 'lo', 'up')
run('nft', 'add', 'table', 'inet', 'foreign_fixture')
foreign = run('nft', '--json', 'list', 'table', 'inet', 'foreign_fixture')


def packet(family, address):
    with socket.socket(family, socket.SOCK_DGRAM) as receiver, socket.socket(family, socket.SOCK_DGRAM) as sender:
        receiver.bind((address, 0))
        receiver.settimeout(0.25)
        sender.sendto(b'bundle-check', receiver.getsockname())
        return receiver.recv(32) == b'bundle-check'


def bundle(address):
    return {'schemaVersion': 1, 'filter': {'schemaVersion': 1, 'inputDefaultVerdict': 'accept', 'rules': []},
            'nat': {'schemaVersion': 1, 'dnatRules': [], 'snatRules': [
                {'family': 'ipv4', 'source': '192.0.2.0/24', 'translatedAddress': address, 'outputInterface': 'wan0'}]},
            'bridge': {'schemaVersion': 1, 'defaultVerdict': 'accept', 'rules': [
                {'verdict': 'drop', 'inputInterface': 'br0', 'etherType': 'ipv4'}]}}


with tempfile.TemporaryDirectory(prefix='nergal-bundle-control-') as temporary:
    root = Path(temporary)
    state = root / 'state'
    state.mkdir(mode=0o700)
    endpoint = root / 'control.sock'
    run('dotnet', agent, 'enroll', str(state))

    def start():
        process = subprocess.Popen(['dotnet', agent, 'control-serve', str(state), str(endpoint), '0'],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ready, _, _ = select.select([process.stdout], [], [], 10)
        require(ready and process.stdout.readline().strip() == 'Listening for authorized control requests.', 'Agent not ready')
        return process

    def exchange(command, **fields):
        wire = json.dumps({'schemaVersion': 1, 'command': command, **fields}).encode()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(10)
            client.connect(str(endpoint))
            client.sendall(struct.pack('>I', len(wire)) + wire)
            client.shutdown(socket.SHUT_WR)
            def exact(length):
                data = b''
                while len(data) < length:
                    chunk = client.recv(length - len(data))
                    require(bool(chunk), 'Truncated reply')
                    data += chunk
                return data
            length = struct.unpack('>I', exact(4))[0]
            require(0 < length <= 262144, 'Unbounded reply')
            result = json.loads(exact(length))
            require(client.recv(1) == b'', 'Trailing reply data')
            return result

    def apply(address, timeout=15):
        operation = str(uuid.uuid4())
        result = exchange('prepare-apply', operationId=operation, confirmationTimeoutSeconds=timeout, bundle=bundle(address))
        require(result['outcome'] == 'appliedPendingConfirmation', f'Prepare failed: {result}')
        return operation, result['watchdogId']

    def completed(command, operation, watchdog, outcome):
        result = exchange(command, operationId=operation, watchdogId=watchdog)
        require(result['outcome'] == outcome, f'{command} failed: {result}')

    process = start()
    try:
        operation, watchdog = apply('198.51.100.2')
        completed('confirm', operation, watchdog, 'confirmed')
        require(exchange('status')['outcome'] == 'matched', 'Confirmed composite receipt did not match')
        baseline = run('nft', '--stateless', 'list', 'table', 'inet', 'nergal_nat')
        process.terminate()
        process.communicate(timeout=10)
        process = start()
        require(exchange('status')['outcome'] == 'matched', 'Complete receipt did not survive restart')
        operation, watchdog = apply('198.51.100.3')
        completed('rollback', operation, watchdog, 'rolledBack')
        require(run('nft', '--stateless', 'list', 'table', 'inet', 'nergal_nat') == baseline, 'Explicit rollback lost NAT baseline')
        apply('198.51.100.4', timeout=2)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            status = exchange('status')
            if status['outcome'] == 'matched':
                break
            time.sleep(0.1)
        require(status['outcome'] == 'matched' and status['revision'] == '2', 'Independent timeout rollback did not restore receipt')
        require(run('nft', '--stateless', 'list', 'table', 'inet', 'nergal_nat') == baseline, 'Timeout rollback lost auxiliary-only baseline')
        require(packet(socket.AF_INET, '127.0.0.1') and packet(socket.AF_INET6, '::1'), 'Rollback changed dual-stack packets')
        # Recreating only an auxiliary table with the same owner marker must fail its recorded native fingerprint.
        original = run('nft', '--stateless', 'list', 'table', 'inet', 'nergal_nat')
        subprocess.run(['nft', '-f', '-'], input='delete table inet nergal_nat\n' + original, text=True, check=True)
        require(exchange('status')['outcome'] == 'drift', 'Copied-marker auxiliary recreation was adopted')
        denied = exchange('prepare-apply', operationId=str(uuid.uuid4()), confirmationTimeoutSeconds=15, bundle=bundle('198.51.100.5'))
        require(denied['outcome'] == 'drift', f'Drifted baseline allowed mutation: {denied}')
        require(run('nft', '--json', 'list', 'table', 'inet', 'foreign_fixture') == foreign, 'Foreign state changed')
        print('PASS: complete multi-table confirm, restart, explicit and independent timeout rollback, dual-stack packets and auxiliary recreation denial')
    finally:
        process.terminate()
        process.communicate(timeout=10)
