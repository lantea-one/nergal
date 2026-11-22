"""Real nergal-agent control-serve (SO_PEERCRED) and tls-serve (TLS 1.3 pinned mTLS) with real packets and autonomous watchdog rollback."""
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time


def require(condition, message):
    if not condition:
        raise AssertionError(message)


require(len(sys.argv) == 4, 'Invoke through check.sh')
agent_dll, parent_user, parent_net = sys.argv[1:]
require(os.readlink('/proc/self/ns/user') != parent_user, 'User isolation missing')
require(os.readlink('/proc/self/ns/net') != parent_net, 'Network isolation missing')
require(os.getuid() == 0, 'Namespace root required')
maps = [tuple(map(int, line.split())) for line in Path('/proc/self/uid_map').read_text().splitlines()]
require(any(start <= 2 < start + count for start, _, count in maps), 'Mapped controller/browser UIDs required')


def run(arguments, text=None, success=True):
    result = subprocess.run(arguments, input=text, capture_output=True, text=True, timeout=15)
    require((result.returncode == 0) == success,
            f'Command {arguments} returned {result.returncode} (expected {"0" if success else "non-zero"}): {result.stderr}')
    return result


def nft(text):
    run(['nft', '--file', '-'], text)


def frame(payload_obj):
    raw = json.dumps(payload_obj, separators=(',', ':')).encode('utf-8')
    return struct.pack('>I', len(raw)) + raw


def read_reply(sock):
    header = b''
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        require(bool(chunk), 'Incomplete control reply header')
        header += chunk
    length = struct.unpack('>I', header)[0]
    require(1 <= length <= 262_144, f'Unexpected control frame length {length}')
    body = b''
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        require(bool(chunk), 'Truncated control reply payload')
        body += chunk
    return json.loads(body.decode('utf-8'))


def unix_exchange(sock_path, request_obj, uid, gid=1, expect_error=False):
    wire = frame(request_obj)
    # Run inside a child process after permanent UID/GID drop so CapEff == 0 and kernel SO_PEERCRED reflects uid.
    script = (
        "import json, os, socket, struct, sys\n"
        "from pathlib import Path\n"
        "spec = json.load(sys.stdin)\n"
        "if spec['uid'] != 0:\n"
        "    cap = next(l for l in Path('/proc/self/status').read_text().splitlines() if l.startswith('CapEff:'))\n"
        "    assert int(cap.split()[1], 16) == 0\n"
        "    try:\n"
        "        Path(spec['db']).read_bytes()\n"
        "        raise AssertionError('Unprivileged client read journal.db')\n"
        "    except PermissionError:\n"
        "        pass\n"
        "with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:\n"
        "    s.settimeout(10)\n"
        "    s.connect(spec['sock'])\n"
        "    _, srv_uid, _ = struct.unpack('3i', s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))\n"
        "    assert srv_uid == 0\n"
        "    try:\n"
        "        s.sendall(bytes.fromhex(spec['wire']))\n"
        "        s.shutdown(socket.SHUT_WR)\n"
        "    except (BrokenPipeError, ConnectionResetError):\n"
        "        pass\n"
        "    hdr = b''\n"
        "    while len(hdr) < 4:\n"
        "        c = s.recv(4 - len(hdr))\n"
        "        if not c:\n"
        "            raise AssertionError('EOF reading reply header')\n"
        "        hdr += c\n"
        "    n = struct.unpack('>I', hdr)[0]\n"
        "    body = b''\n"
        "    while len(body) < n:\n"
        "        c = s.recv(n - len(body))\n"
        "        if not c:\n"
        "            raise AssertionError('EOF reading reply payload')\n"
        "        body += c\n"
        "    try:\n"
        "        assert s.recv(1) == b''\n"
        "    except ConnectionResetError:\n"
        "        pass\n"
        "    print(body.decode('utf-8'))\n"
    )

    def drop():
        try:
            os.setgroups([])
        except PermissionError:
            pass
        os.setgid(gid)
        os.setuid(uid)

    res = subprocess.run(
        [sys.executable, '-c', script],
        input=json.dumps({'sock': str(sock_path), 'wire': wire.hex(), 'uid': uid, 'db': str(journal_db)}),
        capture_output=True,
        text=True,
        timeout=15,
        preexec_fn=drop,
        env={'PATH': os.defpath, 'LANG': 'C.UTF-8'},
    )
    if expect_error:
        return res
    require(res.returncode == 0, f'Unix client uid={uid} failed: {res.stderr}')
    return json.loads(res.stdout)


def tls_exchange(host, port, client_cert, client_key, expected_server_pin, request_obj):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    with socket.create_connection((host, port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname='nergal-agent') as tls_sock:
            require(tls_sock.version() == 'TLSv1.3', f'Expected TLSv1.3, got {tls_sock.version()}')
            der = tls_sock.getpeercert(binary_form=True)
            require(bool(der), 'Server certificate missing')
            actual_pin = hashlib.sha256(der).hexdigest()
            require(actual_pin == expected_server_pin, 'Server certificate thumbprint mismatch')
            tls_sock.sendall(frame(request_obj))
            reply = read_reply(tls_sock)
            return reply


def udp_loopback(family, address):
    with socket.socket(family, socket.SOCK_DGRAM) as receiver, socket.socket(family, socket.SOCK_DGRAM) as sender:
        receiver.bind((address, 0))
        receiver.settimeout(0.35)
        sender.sendto(b'nergal-ctrl', receiver.getsockname())
        try:
            return receiver.recv(32) == b'nergal-ctrl'
        except TimeoutError:
            return False


def wait_until(predicate, timeout=8.0, message='Timed out waiting for condition'):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        val = predicate()
        if val:
            return val
        time.sleep(0.1)
    raise AssertionError(message)


run(['ip', 'link', 'set', 'lo', 'up'])
for family in ('ip', 'ip6', 'inet', 'bridge'):
    nft(f'create table {family} foreign_fixture\nadd chain {family} foreign_fixture sentinel\n')
foreign = {family: run(['nft', '--stateless', 'list', 'table', family, 'foreign_fixture']).stdout
           for family in ('ip', 'ip6', 'inet', 'bridge')}

with tempfile.TemporaryDirectory(prefix='nergal-ctrl-e2e-') as root_str:
    root = Path(root_str)
    os.chmod(root, 0o711)
    state = root / 'state'
    state.mkdir(mode=0o700)
    journal_db = state / 'journal.db'
    endpoint = root / 'endpoint'
    endpoint.mkdir()
    os.chown(endpoint, 0, 1)
    os.chmod(endpoint, 0o2710)
    control_sock = endpoint / 'control.sock'

    run(['dotnet', agent_dll, 'enroll', str(state)])
    require(udp_loopback(socket.AF_INET, '127.0.0.1') and udp_loopback(socket.AF_INET6, '::1'),
            'Initial loopback baseline failed')

    # --- Part 1: Authenticated Unix peer-UID control-serve ---
    ctrl_proc = subprocess.Popen(
        ['dotnet', agent_dll, 'control-serve', str(state), str(control_sock), '1', '1'],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready, _, _ = select.select([ctrl_proc.stdout], [], [], 10)
        require(ready and ctrl_proc.stdout.readline().strip() == 'Listening for authorized control requests.',
                'control-serve failed to announce readiness')

        # Unallowlisted browser UID 2 (sharing GID 1 socket access) is denied cleanly without touching journal.
        db_snapshot = journal_db.read_bytes()
        denied_reply = unix_exchange(control_sock, {'schemaVersion': 1, 'command': 'status'}, uid=2)
        require(denied_reply == {'schemaVersion': 1, 'outcome': 'denied'}, f'Expected denied for UID 2, got {denied_reply}')
        require(journal_db.read_bytes() == db_snapshot, 'Denied peer modified journal')

        # Controller UID 1 queries initial status.
        st1 = unix_exchange(control_sock, {'schemaVersion': 1, 'command': 'status'}, uid=1)
        require(st1 == {'schemaVersion': 1, 'outcome': 'matched', 'revision': '1'}, f'Unexpected initial status: {st1}')

        drop_v4_policy = {
            'schemaVersion': 1,
            'inputDefaultVerdict': 'accept',
            'forwardDefaultVerdict': 'drop',
            'outputDefaultVerdict': 'drop',
            'rules': [
                {'family': 'ipv4', 'protocol': 'udp', 'verdict': 'drop', 'chain': 'input', 'connectionStates': 0},
                {'family': 'ipv6', 'protocol': 'udp', 'verdict': 'accept', 'chain': 'input', 'connectionStates': 0},
            ],
        }

        # 1A. PrepareApply -> verify real packet drop -> disconnect -> autonomous watchdog timeout rollback restores packets.
        op1 = '10000000-0000-0000-0000-000000000001'
        prep1 = unix_exchange(control_sock, {
            'schemaVersion': 1,
            'command': 'prepare-apply',
            'operationId': op1,
            'confirmationTimeoutSeconds': 2,
            'policy': drop_v4_policy,
        }, uid=1)
        require(prep1['outcome'] == 'appliedPendingConfirmation' and prep1['operationId'] == op1 and prep1['activePhase'] == 'awaitingConfirmation',
                f'Unexpected PrepareApply reply: {prep1}')
        require(not udp_loopback(socket.AF_INET, '127.0.0.1') and udp_loopback(socket.AF_INET6, '::1'),
                'Candidate applied via control-serve did not enforce IPv4 drop / IPv6 accept')

        restored = wait_until(
            lambda: (lambda r: r if r.get('outcome') == 'matched' else None)(
                unix_exchange(control_sock, {'schemaVersion': 1, 'command': 'status'}, uid=1)),
            timeout=8.0,
            message='Autonomous watchdog did not roll back unconfirmed control-serve apply')
        require(restored == {'schemaVersion': 1, 'outcome': 'matched', 'revision': '1'}, f'Unexpected post-rollback status: {restored}')
        require(udp_loopback(socket.AF_INET, '127.0.0.1') and udp_loopback(socket.AF_INET6, '::1'),
                'Autonomous watchdog rollback did not restore IPv4 loopback packets')

        # 1B. PrepareApply -> status inspection -> explicit Rollback restores packets immediately.
        op2 = '10000000-0000-0000-0000-000000000002'
        prep2 = unix_exchange(control_sock, {
            'schemaVersion': 1,
            'command': 'prepare-apply',
            'operationId': op2,
            'confirmationTimeoutSeconds': 15,
            'policy': drop_v4_policy,
        }, uid=1)
        require(prep2['outcome'] == 'appliedPendingConfirmation', f'Unexpected op2 prepare reply: {prep2}')
        require(not udp_loopback(socket.AF_INET, '127.0.0.1'), 'op2 candidate did not drop IPv4')
        rb2 = unix_exchange(control_sock, {
            'schemaVersion': 1,
            'command': 'rollback',
            'operationId': op2,
            'watchdogId': prep2['watchdogId'],
        }, uid=1)
        require(rb2['outcome'] == 'rolledBack' and rb2['revision'] == '1' and rb2['activePhase'] == 'rolledBack',
                f'Explicit rollback failed: {rb2}')
        require(udp_loopback(socket.AF_INET, '127.0.0.1') and udp_loopback(socket.AF_INET6, '::1'),
                'Explicit rollback did not restore IPv4 packets')

        # 1C. PrepareApply -> Confirm persists revision 2 and enforces packet filter beyond window.
        op3 = '10000000-0000-0000-0000-000000000003'
        prep3 = unix_exchange(control_sock, {
            'schemaVersion': 1,
            'command': 'prepare-apply',
            'operationId': op3,
            'confirmationTimeoutSeconds': 10,
            'policy': drop_v4_policy,
        }, uid=1)
        require(prep3['outcome'] == 'appliedPendingConfirmation', f'op3 prepare failed: {prep3}')
        conf3 = unix_exchange(control_sock, {
            'schemaVersion': 1,
            'command': 'confirm',
            'operationId': op3,
            'watchdogId': prep3['watchdogId'],
        }, uid=1)
        require(conf3['outcome'] == 'confirmed' and conf3['revision'] == '2' and conf3['activePhase'] == 'confirmed',
                f'op3 confirm failed: {conf3}')
        require(not udp_loopback(socket.AF_INET, '127.0.0.1') and udp_loopback(socket.AF_INET6, '::1'),
                'Confirmed control-serve candidate did not persist packet enforcement')

        ctrl_proc.terminate()
        out, err = ctrl_proc.communicate(timeout=10)
        require(ctrl_proc.returncode == 0, f'control-serve clean SIGTERM shutdown failed: rc={ctrl_proc.returncode} err={err}')
        require(not control_sock.exists(), 'control-serve did not unlink its socket on shutdown')
    finally:
        if ctrl_proc.poll() is None:
            ctrl_proc.kill()
            ctrl_proc.communicate(timeout=5)

    print('PASS: control-serve SO_PEERCRED authorization, real packet enforcement, explicit rollback, autonomous watchdog rollback, and confirm', flush=True)

    # --- Part 2: TLS 1.3 pinned mTLS tls-serve ---
    pki = root / 'pki'
    pki.mkdir(mode=0o700)
    openssl_cnf = pki / 'ext.cnf'
    openssl_cnf.write_text(
        "[req]\n"
        "distinguished_name = dn\n"
        "prompt = no\n"
        "[dn]\n"
        "CN = nergal-test\n"
        "[srv_ext]\n"
        "basicConstraints = critical, CA:FALSE\n"
        "keyUsage = critical, digitalSignature\n"
        "extendedKeyUsage = serverAuth\n"
        "subjectAltName = IP:127.0.0.1,DNS:nergal-agent\n"
        "[cli_ext]\n"
        "basicConstraints = critical, CA:FALSE\n"
        "keyUsage = critical, digitalSignature\n"
        "extendedKeyUsage = clientAuth\n"
    )

    def gen_cert(name, ext_section):
        cert = pki / f'{name}.crt'
        key = pki / f'{name}.key'
        run([
            'openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
            '-nodes', '-days', '1', '-config', str(openssl_cnf), '-extensions', ext_section,
            '-keyout', str(key), '-out', str(cert),
        ])
        os.chmod(key, 0o600)
        der = subprocess.run(['openssl', 'x509', '-in', str(cert), '-outform', 'DER'], capture_output=True, check=True).stdout
        return cert, key, hashlib.sha256(der).hexdigest()

    srv_cert, srv_key, srv_pin = gen_cert('server', 'srv_ext')
    cli_cert, cli_key, cli_pin = gen_cert('client', 'cli_ext')
    rogue_cert, rogue_key, _ = gen_cert('rogue', 'cli_ext')
    wrongeku_cert, wrongeku_key, _ = gen_cert('wrongeku', 'srv_ext')

    # tls-serve refuses unsafe 0644 server private key permissions.
    os.chmod(srv_key, 0o644)
    bad_key_res = run(['dotnet', agent_dll, 'tls-serve', str(state), '127.0.0.1:0', str(srv_cert), str(srv_key), cli_pin], success=False)
    require('tls.keyPermissions' in bad_key_res.stderr, f'Expected tls.keyPermissions, got {bad_key_res.stderr}')
    os.chmod(srv_key, 0o600)

    tls_proc = subprocess.Popen(
        ['dotnet', agent_dll, 'tls-serve', str(state), '127.0.0.1:0', str(srv_cert), str(srv_key), cli_pin],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready, _, _ = select.select([tls_proc.stdout], [], [], 10)
        line = tls_proc.stdout.readline().strip() if ready else ''
        require(line.startswith('LISTENING 127.0.0.1:'), f'tls-serve failed to print LISTENING endpoint, got: {line!r}')
        tls_port = int(line.split(':')[1])

        # Unpinned client cert and wrong-EKU client cert must fail TLS 1.3 mTLS handshake or subsequent read.
        for bad_name, bad_c, bad_k in (('rogue', rogue_cert, rogue_key), ('wrong-eku', wrongeku_cert, wrongeku_key)):
            rejected = False
            try:
                tls_exchange('127.0.0.1', tls_port, bad_c, bad_k, srv_pin, {'schemaVersion': 1, 'command': 'status'})
            except Exception:
                rejected = True
            require(rejected, f'tls-serve accepted unauthenticated {bad_name} client certificate')

        # Pinned client queries status -> revision 2 matched.
        st_tls = tls_exchange('127.0.0.1', tls_port, cli_cert, cli_key, srv_pin, {'schemaVersion': 1, 'command': 'status'})
        require(st_tls == {'schemaVersion': 1, 'outcome': 'matched', 'revision': '2'}, f'Unexpected tls status: {st_tls}')

        # Pinned client sends Schema 2 default-drop policy (IPv4 TCP allowed + IPv6 established/related to enable conntrack + IPv4 UDP accept + IPv6 UDP drop) -> revision 3.
        schema2_flip = {
            'schemaVersion': 2,
            'inputDefaultVerdict': 'drop',
            'forwardDefaultVerdict': 'drop',
            'outputDefaultVerdict': 'accept',
            'rules': [
                {'family': 'ipv4', 'protocol': 'tcp', 'verdict': 'accept', 'chain': 'input', 'connectionStates': 0},
                {'family': 'ipv6', 'protocol': 'tcp', 'verdict': 'accept', 'chain': 'input', 'connectionStates': 6},
                {'family': 'ipv4', 'protocol': 'udp', 'verdict': 'accept', 'chain': 'input', 'connectionStates': 0},
                {'family': 'ipv6', 'protocol': 'udp', 'verdict': 'drop', 'chain': 'input', 'connectionStates': 0},
            ],
        }
        op4 = '20000000-0000-0000-0000-000000000004'
        prep4 = tls_exchange('127.0.0.1', tls_port, cli_cert, cli_key, srv_pin, {
            'schemaVersion': 1,
            'command': 'prepare-apply',
            'operationId': op4,
            'confirmationTimeoutSeconds': 10,
            'policy': schema2_flip,
        })
        require(prep4['outcome'] == 'appliedPendingConfirmation', f'tls prepareApply failed: {prep4}')
        require(udp_loopback(socket.AF_INET, '127.0.0.1') and not udp_loopback(socket.AF_INET6, '::1'),
                'Schema 2 policy applied over TLS did not enforce IPv4-accept / IPv6-drop')
        conf4 = tls_exchange('127.0.0.1', tls_port, cli_cert, cli_key, srv_pin, {
            'schemaVersion': 1,
            'command': 'confirm',
            'operationId': op4,
            'watchdogId': prep4['watchdogId'],
        })
        require(conf4['outcome'] == 'confirmed' and conf4['revision'] == '3', f'tls confirm failed: {conf4}')

        # Now conntrack is active in the netns; verify strict tcp-dport + ct state established,related + UDP drop -> autonomous watchdog rollback restores baseline.
        drop_both = {
            'schemaVersion': 2,
            'inputDefaultVerdict': 'drop',
            'forwardDefaultVerdict': 'drop',
            'outputDefaultVerdict': 'accept',
            'rules': [
                {'family': 'ipv4', 'protocol': 'tcp', 'verdict': 'accept', 'chain': 'input', 'connectionStates': 6},
                {'family': 'ipv4', 'protocol': 'tcp', 'destinationPort': tls_port, 'verdict': 'accept', 'chain': 'input', 'connectionStates': 0},
                {'family': 'ipv4', 'protocol': 'udp', 'verdict': 'drop', 'chain': 'input', 'connectionStates': 0},
                {'family': 'ipv6', 'protocol': 'udp', 'verdict': 'drop', 'chain': 'input', 'connectionStates': 0},
            ],
        }
        op5 = '20000000-0000-0000-0000-000000000005'
        prep5 = tls_exchange('127.0.0.1', tls_port, cli_cert, cli_key, srv_pin, {
            'schemaVersion': 1,
            'command': 'prepare-apply',
            'operationId': op5,
            'confirmationTimeoutSeconds': 2,
            'policy': drop_both,
        })
        require(prep5['outcome'] == 'appliedPendingConfirmation', f'op5 tls prepare failed: {prep5}')
        require(not udp_loopback(socket.AF_INET, '127.0.0.1') and not udp_loopback(socket.AF_INET6, '::1'),
                'op5 drop-both policy did not block packets')

        tls_restored = wait_until(
            lambda: (lambda r: r if r.get('outcome') == 'matched' else None)(
                tls_exchange('127.0.0.1', tls_port, cli_cert, cli_key, srv_pin, {'schemaVersion': 1, 'command': 'status'})),
            timeout=8.0,
            message='Autonomous watchdog did not roll back unconfirmed tls-serve apply')
        require(tls_restored == {'schemaVersion': 1, 'outcome': 'matched', 'revision': '3'}, f'Unexpected tls rollback status: {tls_restored}')
        require(udp_loopback(socket.AF_INET, '127.0.0.1') and not udp_loopback(socket.AF_INET6, '::1'),
                'Autonomous watchdog rollback after tls-serve apply did not restore Schema 2 baseline packets')

        tls_proc.terminate()
        out, err = tls_proc.communicate(timeout=10)
        require(tls_proc.returncode == 0, f'tls-serve SIGTERM shutdown failed: rc={tls_proc.returncode} err={err}')
    finally:
        if tls_proc.poll() is None:
            tls_proc.kill()
            tls_proc.communicate(timeout=5)

    for family, snapshot in foreign.items():
        require(run(['nft', '--stateless', 'list', 'table', family, 'foreign_fixture']).stdout == snapshot,
                f'Foreign table mutated in {family}')

    print('PASS: tls-serve TLS 1.3 pinned mTLS handshake checks, Schema 2 packet filtering, confirm, and autonomous watchdog rollback', flush=True)
