"""Actual processes, kill windows and packet restoration; never invoked on host state.

Protocol lines synchronize readiness/kill points. Timeouts bound failure and packet
assertions. Waiting for a real deadline is intentional in confirmation tests.
"""
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time
import uuid


def require(condition, message):
    if not condition:
        raise AssertionError(message)


require(len(sys.argv) == 5, 'Invoke through check.sh')
assembly, scenario, parent_net, parent_user = sys.argv[1:]
require(os.readlink('/proc/self/ns/net') != parent_net, 'Network isolation missing')
require(os.readlink('/proc/self/ns/user') != parent_user, 'User isolation missing')
require(os.getuid() == 0, 'Namespace-local root required')


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10).stdout


def nft(text):
    return subprocess.run(['nft', '--file', '-'], input=text, text=True,
                          capture_output=True, check=True, timeout=5).stdout


run('ip', 'link', 'set', 'lo', 'up')
run('ip', 'address', 'add', '192.0.2.1/32', 'dev', 'lo', 'nodad')
run('ip', 'address', 'add', '2001:db8::1/128', 'dev', 'lo', 'nodad')
for family in ('ip', 'ip6', 'inet', 'bridge'):
    nft(f'create table {family} foreign_fixture\nadd chain {family} foreign_fixture sentinel\n')
foreign = {family: run('nft', '--stateless', 'list', 'table', family, 'foreign_fixture')
           for family in ('ip', 'ip6', 'inet', 'bridge')}
children = []
operation = str(uuid.uuid4())


def packet_check(allowed):
    # Use UDP and TCP in each IP family; listeners are ready before sending.
    for family, address in ((socket.AF_INET, '192.0.2.1'), (socket.AF_INET6, '2001:db8::1')):
        with socket.socket(family, socket.SOCK_DGRAM) as server:
            server.bind((address, 18081))
            server.settimeout(0.15)
            with socket.socket(family, socket.SOCK_DGRAM) as client:
                client.sendto(b'isolated-watchdog', (address, 18081))
            try:
                payload, _ = server.recvfrom(128)
            except socket.timeout:
                require(not allowed, f'Allowed UDP blocked: {address}')
            else:
                require(allowed and payload == b'isolated-watchdog', f'Denied UDP arrived: {address}')
        with socket.socket(family, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((address, 18080))
            server.listen(1)
            server.settimeout(1)
            with socket.socket(family, socket.SOCK_STREAM) as client:
                client.settimeout(0.15)
                try:
                    client.connect((address, 18080))
                except socket.timeout:
                    require(not allowed, f'Allowed TCP blocked: {address}')
                else:
                    require(allowed, f'Denied TCP connected: {address}')
                    accepted, _ = server.accept()
                    accepted.close()


def ready(process, expected):
    readable, _, _ = select.select([process.stdout], [], [], 12)
    require(readable, f'No readiness acknowledgment: {expected}')
    line = process.stdout.readline().strip()
    require(line == expected, f'Expected {expected}, got {line}; exit={process.poll()}')


def finish(process, code=0, expected=None):
    output, error = process.communicate(timeout=15)
    require(process.returncode == code, f'Unexpected process exit {process.returncode}: {error}')
    if expected is not None:
        require(expected in output.splitlines(), f'Missing outcome {expected}: {output}')


def kill(process):
    process.kill()
    process.communicate(timeout=5)
    require(process.returncode < 0, 'Process did not terminate by signal')


with tempfile.TemporaryDirectory(prefix='nergal-watchdog-') as state:
    os.chmod(state, 0o700)

    def command(mode, timeout=3000):
        return ['dotnet', assembly, mode, state, parent_net, parent_user, operation, str(timeout)]

    def call(mode, timeout=3000, success=True):
        result = subprocess.run(command(mode, timeout), capture_output=True, text=True, timeout=15)
        require((result.returncode == 0) == success,
                f'{mode} exit={result.returncode}: {result.stderr}')
        return result.stdout

    def spawn(mode):
        process = subprocess.Popen(command(mode), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        children.append(process)
        return process

    try:
        call('seed')
        packet_check(True)
        duration = 5000 if scenario == 'confirmation' else 3000
        call('begin', duration)
        watchdog = spawn('watch-pause-after-restore' if scenario == 'restore_ack' else 'watch')
        ready(watchdog, 'WATCHING')
        armed_at = time.monotonic()
        original_deadline = json.loads(call('status'))['deadlineTicks']
        if scenario == 'before_apply':
            worker = spawn('apply-pause-before')
            ready(worker, 'BEFORE_APPLY')
            kill(worker)
            packet_check(True)
            finish(watchdog, expected='RolledBack')
            packet_check(True)
        elif scenario == 'after_apply':
            worker = spawn('apply-pause-after')
            ready(worker, 'APPLIED_BEFORE_ACK')
            packet_check(False)
            kill(worker)
            finish(watchdog, expected='RolledBack')
            packet_check(True)
        elif scenario == 'watchdog_restart':
            call('apply')
            packet_check(False)
            kill(watchdog)
            restarted = spawn('watch')
            ready(restarted, 'WATCHING')
            require(json.loads(call('status'))['deadlineTicks'] == original_deadline,
                    'Watchdog restart changed the persisted deadline')
            finish(restarted, expected='RolledBack')
            packet_check(True)
        elif scenario == 'restore_ack':
            call('apply')
            packet_check(False)
            ready(watchdog, 'RESTORED_BEFORE_ACK')
            packet_check(True)
            kill(watchdog)
            restarted = spawn('watch')
            ready(restarted, 'WATCHING')
            finish(restarted, expected='RolledBack')
            packet_check(True)
        elif scenario == 'confirmation':
            call('apply')
            packet_check(False)
            call('confirm')
            finish(watchdog, expected='Confirmed')
            # Wait through the old real deadline to catch an incorrectly retained rollback timer.
            remaining = duration / 1000 + 0.1 - (time.monotonic() - armed_at)
            if remaining > 0:
                time.sleep(remaining)
            again = spawn('watch')
            ready(again, 'WATCHING')
            finish(again, expected='Confirmed')
            packet_check(False)
        elif scenario == 'foreign_state':
            call('apply')
            nft('add chain inet nergal_filter unexpected_foreign_chain\n')
            before = run('nft', '--stateless', 'list', 'ruleset')
            finish(watchdog, code=1, expected='RecoveryRequired')
            require(run('nft', '--stateless', 'list', 'ruleset') == before,
                    'Unexpected table shape was overwritten')
            call('begin', success=False)
        elif scenario in ('corrupt_journal', 'missing_journal'):
            call('apply')
            packet_check(False)
            kill(watchdog)
            before = run('nft', '--stateless', 'list', 'ruleset')
            database = Path(state) / 'journal.db'
            if scenario == 'corrupt_journal':
                database.write_bytes(b'not a journal')
            else:
                database.unlink()
            restarted = spawn('watch')
            finish(restarted, code=1)
            require(run('nft', '--stateless', 'list', 'ruleset') == before,
                    'Invalid journal allowed kernel writes')
            call('confirm', success=False)
        else:
            raise AssertionError('Unknown scenario')
        if scenario not in ('corrupt_journal', 'missing_journal'):
            status = json.loads(call('status'))
            expected = 'Confirmed' if scenario == 'confirmation' else 'RecoveryRequired' if scenario == 'foreign_state' else 'RolledBack'
            require(status['phase'] == expected, f'Wrong durable phase: {status}')
            require(status['revision'] == (2 if scenario == 'confirmation' else 1), 'Incorrect confirmed revision')
            if scenario != 'confirmation':
                call('confirm', success=False)
        for family, baseline in foreign.items():
            require(run('nft', '--stateless', 'list', 'table', family, 'foreign_fixture') == baseline,
                    f'Foreign {family} table changed')
        print(f'PASS: {scenario}, durable decision and foreign-table preservation', flush=True)
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)
