"""Full-stack unprivileged Kestrel two-phase confirmed apply and autonomous watchdog rollback in disposable namespaces."""
import hashlib
from html.parser import HTMLParser
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode

from runtime import stage_client_runtime


def require(condition, message):
    if not condition:
        raise AssertionError(message)


require(len(sys.argv) == 4, 'Invoke through check.sh')
agent_dll, parent_user, parent_net = sys.argv[1:]
require(os.readlink('/proc/self/ns/user') != parent_user, 'User isolation missing')
require(os.readlink('/proc/self/ns/net') != parent_net, 'Network isolation missing')
require(os.getuid() == 0, 'Namespace root required')
maps = [tuple(map(int, line.split())) for line in Path('/proc/self/uid_map').read_text().splitlines()]
require(any(start <= 2 < start + count for start, _, count in maps), 'Mapped controller UIDs required')

SOURCE = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('session_fixture', SOURCE / 'tests/integration/local-sessions/check.py')
sessions = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sessions)


class CsrfParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.value = None

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == 'input' and fields.get('name') == '__RequestVerificationToken' and self.value is None:
            self.value = fields.get('value')


class WebClient:
    def __init__(self, port, tls_ctx):
        self.port = port
        self.tls = tls_ctx
        self.cookies = {}

    def request(self, path, expected, form=None, json_body=None, headers=None, expected_location_contains=None):
        conn = http.client.HTTPSConnection('127.0.0.1', self.port, context=self.tls, timeout=15)
        req_headers = dict(headers or {})
        if self.cookies:
            req_headers['Cookie'] = '; '.join(f'{k}={v}' for k, v in self.cookies.items())
        method = 'GET'
        payload = None
        if form is not None:
            method = 'POST'
            req_headers['Content-Type'] = 'application/x-www-form-urlencoded'
            payload = urlencode(form)
        elif json_body is not None:
            method = 'POST'
            req_headers['Content-Type'] = 'application/json'
            payload = json.dumps(json_body)
        try:
            conn.request(method, path, payload, req_headers)
            resp = conn.getresponse()
            body = resp.read().decode('utf-8', errors='replace')
            location = resp.getheader('Location')
            require(resp.status == expected, f'{method} {path}: expected HTTP {expected}, got {resp.status} ({body[:300]})')
            for name, value in resp.getheaders():
                if name.lower() == 'set-cookie':
                    pair, *_ = value.split('; ')
                    key, val = pair.split('=', 1)
                    self.cookies[key] = val
            if expected_location_contains is not None:
                require(location is not None and expected_location_contains in location,
                        f'{method} {path}: expected Location containing {expected_location_contains!r}, got {location!r}')
            return body, location
        finally:
            conn.close()

    def token(self, path):
        body, _ = self.request(path, 200)
        parser = CsrfParser()
        parser.feed(body)
        require(bool(parser.value), f'Missing antiforgery token on {path}')
        return parser.value

    def login(self, username, password):
        csrf = self.token('/login')
        self.request('/login', 302, form={
            'username': username,
            'password': password,
            '__RequestVerificationToken': csrf,
        }, expected_location_contains='/session')


def run(arguments, text=None, env=None):
    res = subprocess.run(arguments, input=text, capture_output=True, text=True, timeout=20, env=env)
    require(res.returncode == 0, f'Command {arguments} failed ({res.returncode}): {res.stderr}')
    return res


def nft(text):
    run(['nft', '--file', '-'], text)


def udp_loopback(family, address, port=0):
    with socket.socket(family, socket.SOCK_DGRAM) as receiver, socket.socket(family, socket.SOCK_DGRAM) as sender:
        receiver.bind((address, port))
        receiver.settimeout(0.35)
        sender.sendto(b'nergal-web-apply', receiver.getsockname())
        try:
            return receiver.recv(32) == b'nergal-web-apply'
        except TimeoutError:
            return False


def wait_until(predicate, timeout=10.0, message='Timed out waiting for condition'):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        val = predicate()
        if val:
            return val
        time.sleep(0.15)
    raise AssertionError(message)


def chown_tree(path, uid, gid, dir_mode=0o700, file_mode=None):
    os.chown(path, uid, gid)
    os.chmod(path, dir_mode)
    for root_dir, dirs, files in os.walk(path):
        for d in dirs:
            p = Path(root_dir) / d
            os.chown(p, uid, gid)
            os.chmod(p, dir_mode)
        for f in files:
            p = Path(root_dir) / f
            os.chown(p, uid, gid)
            if file_mode is not None:
                os.chmod(p, file_mode)


run(['ip', 'link', 'set', 'lo', 'up'])
for family in ('ip', 'ip6', 'inet', 'bridge'):
    nft(f'create table {family} foreign_fixture\nadd chain {family} foreign_fixture sentinel\n')
foreign = {family: run(['nft', '--stateless', 'list', 'table', family, 'foreign_fixture']).stdout
           for family in ('ip', 'ip6', 'inet', 'bridge')}

with tempfile.TemporaryDirectory(prefix='nergal-web-apply-') as root_str:
    root = Path(root_str)
    os.chmod(root, 0o711)

    dotnet_bin, _ = stage_client_runtime(root, agent_dll)
    framework = Path(shutil.which('dotnet')).resolve().parent / 'shared/Microsoft.AspNetCore.App'
    runtime_shared = Path(dotnet_bin).parent / 'shared/Microsoft.AspNetCore.App'
    if not runtime_shared.exists():
        shutil.copytree(framework, runtime_shared)
    web_dir = root / 'web'
    shutil.copytree(sessions.DLL.parent, web_dir)
    for tree in (web_dir, runtime_shared):
        for directory, _, files in os.walk(tree):
            os.chmod(directory, 0o755)
            for filename in files:
                os.chmod(Path(directory) / filename, 0o644)

    # 1. Agent state (UID 0) and Unix socket directory (0:1 mode 2710) + mTLS certs.
    agent_state = root / 'agent-state'
    agent_state.mkdir(mode=0o700)
    endpoint_dir = root / 'endpoint'
    endpoint_dir.mkdir()
    os.chown(endpoint_dir, 0, 1)
    os.chmod(endpoint_dir, 0o2710)
    control_sock = endpoint_dir / 'control.sock'

    server_pki = root / 'server-pki'
    server_pki.mkdir(mode=0o700)
    client_pki = root / 'client-pki'
    client_pki.mkdir(mode=0o700)
    openssl_cnf = root / 'ext.cnf'
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

    def gen_cert(directory, name, ext_section):
        cert = directory / f'{name}.crt'
        key = directory / f'{name}.key'
        run([
            'openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
            '-nodes', '-days', '1', '-config', str(openssl_cnf), '-extensions', ext_section,
            '-keyout', str(key), '-out', str(cert),
        ])
        os.chmod(key, 0o600)
        der = subprocess.run(['openssl', 'x509', '-in', str(cert), '-outform', 'DER'], capture_output=True, check=True).stdout
        return cert, key, hashlib.sha256(der).hexdigest()

    srv_cert, srv_key, srv_pin = gen_cert(server_pki, 'server', 'srv_ext')
    cli_cert, cli_key, cli_pin = gen_cert(client_pki, 'client', 'cli_ext')
    chown_tree(client_pki, 1, 1, dir_mode=0o700)
    os.chmod(cli_cert, 0o600)
    os.chmod(cli_key, 0o600)

    run(['dotnet', agent_dll, 'enroll', str(agent_state)])
    require(udp_loopback(socket.AF_INET, '127.0.0.1') and udp_loopback(socket.AF_INET6, '::1'), 'Initial loopback failed')

    # 2. Controller state + local admin & separate auditor account DB owned by unprivileged UID 1.
    controller_root = root / 'controller'
    controller_root.mkdir(mode=0o700)
    tls_ctx = sessions.provision(controller_root)
    auditor_accounts = root / 'auditor-accounts'
    auditor_accounts.mkdir(mode=0o700)
    run(['dotnet', str(sessions.ADMIN_TOOL), 'account', 'init', str(auditor_accounts)])
    run(['dotnet', str(sessions.ADMIN_TOOL), 'account', 'provision', str(auditor_accounts),
         'fixture-auditor', '--role', 'auditor', '--password-stdin'],
        text=sessions.PASSWORD + '\n')
    ctrl_state_dir = controller_root / 'state'
    ctrl_state_dir.mkdir(mode=0o700)
    run(['dotnet', str(sessions.ADMIN_TOOL), 'controller', 'init', str(ctrl_state_dir)])
    chown_tree(controller_root, 1, 1, dir_mode=0o700)
    chown_tree(auditor_accounts, 1, 1, dir_mode=0o700)

    def drop_to_controller():
        try:
            os.setgroups([])
        except PermissionError:
            pass
        os.setgid(1)
        os.setuid(1)
        cap = next(line for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:'))
        require(int(cap.split()[1], 16) == 0, f'Controller retained unexpected capabilities: {cap}')

    def start_web(account_dir):
        web_env = {
            k: v for k, v in os.environ.items()
            if not k.lower().startswith(('aspnetcore_', 'kestrel__', 'localsessions__', 'agentstatus__', 'controllerstate__', 'oidc__', 'logging__'))
        }
        web_env.update({
            'HOME': str(controller_root / 'profile'),
            'XDG_DATA_HOME': str(controller_root / 'profile'),
            'ASPNETCORE_URLS': 'https://127.0.0.1:0',
            'Kestrel__Certificates__Default__Path': str(controller_root / 'tls.crt'),
            'Kestrel__Certificates__Default__KeyPath': str(controller_root / 'tls.key'),
            'LocalSessions__Enabled': 'true',
            'LocalSessions__AccountDirectory': str(account_dir),
            'LocalSessions__KeyDirectory': str(controller_root / 'keys'),
            'LocalSessions__CertificateFile': str(controller_root / 'wrapping.pfx'),
            'ControllerState__Enabled': 'true',
            'ControllerState__Directory': str(ctrl_state_dir),
            'ControllerState__TlsClientCertificatePath': str(cli_cert),
            'ControllerState__TlsClientKeyPath': str(cli_key),
            'Logging__LogLevel__Microsoft.Hosting.Lifetime': 'Information',
        })
        log_file = tempfile.TemporaryFile(mode='w+b')
        proc = subprocess.Popen(
            [dotnet_bin, str(web_dir / 'Nergal.Web.dll')],
            cwd=str(web_dir),
            env=web_env,
            preexec_fn=drop_to_controller,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 20
        https_port = None
        while time.monotonic() < deadline:
            text = os.pread(log_file.fileno(), 100_000, 0).decode(errors='replace')
            match = re.search(r'Now listening on: https://127\.0\.0\.1:(\d+)', text)
            if match:
                https_port = int(match.group(1))
                break
            if proc.poll() is not None:
                raise AssertionError(f'Nergal.Web refused startup:\n{text}')
            time.sleep(0.1)
        require(https_port is not None, 'Timed out waiting for Kestrel HTTPS port')
        return proc, log_file, https_port

    ctrl_proc = subprocess.Popen(
        ['dotnet', agent_dll, 'control-serve', str(agent_state), str(control_sock), '1', '1'],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    tls_proc = subprocess.Popen(
        ['dotnet', agent_dll, 'tls-serve', str(agent_state), '127.0.0.1:0', str(srv_cert), str(srv_key), cli_pin],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    web_proc = None
    web_log = None
    try:
        ready, _, _ = select.select([ctrl_proc.stdout], [], [], 10)
        require(ready and ctrl_proc.stdout.readline().strip() == 'Listening for authorized control requests.',
                'control-serve readiness failed')
        ready_tls, _, _ = select.select([tls_proc.stdout], [], [], 10)
        tls_line = tls_proc.stdout.readline().strip() if ready_tls else ''
        require(tls_line.startswith('LISTENING 127.0.0.1:'), f'tls-serve readiness failed: {tls_line!r}')
        tls_port = int(tls_line.split(':')[1])

        web_proc, web_log, https_port = start_web(controller_root / 'accounts')

        # Unauthenticated clients are rejected.
        anon = WebClient(https_port, tls_ctx)
        anon.request('/manage/apply', 401)
        anon.request('/controller/apply/status?hostId=00000000-0000-0000-0000-000000000001', 401)

        admin = WebClient(https_port, tls_ctx)
        admin.login('fixture-admin', sessions.PASSWORD)

        admin_csrf = admin.token('/session')
        unix_host = json.loads(admin.request('/controller/hosts', 201, json_body={
            'name': 'unix-agent',
            'transportKind': 'unix',
            'endpoint': str(control_sock),
            'expectedServerUserId': 0,
            'socketGroupId': 1,
        }, headers={'RequestVerificationToken': admin_csrf})[0])
        tls_host = json.loads(admin.request('/controller/hosts', 201, json_body={
            'name': 'tls-agent',
            'transportKind': 'tls',
            'endpoint': f'127.0.0.1:{tls_port}',
            'pinnedServerThumbprint': srv_pin,
        }, headers={'RequestVerificationToken': admin_csrf})[0])

        unix_id = unix_host['id']
        tls_id = tls_host['id']

        rev1_json = json.dumps({
            'schemaVersion': 1,
            'filter': {
                'schemaVersion': 2,
                'inputDefaultVerdict': 'accept',
                'forwardDefaultVerdict': 'drop',
                'outputDefaultVerdict': 'accept',
                'rules': [
                    {'family': 'ipv4', 'protocol': 'udp', 'verdict': 'drop', 'chain': 'input', 'connectionStates': []},
                    {'family': 'ipv6', 'protocol': 'udp', 'verdict': 'accept', 'chain': 'input', 'connectionStates': []},
                ],
            },
        })
        rev2_json = json.dumps({
            'schemaVersion': 1,
            'filter': {
                'schemaVersion': 2,
                'inputDefaultVerdict': 'accept',
                'forwardDefaultVerdict': 'drop',
                'outputDefaultVerdict': 'accept',
                'rules': [
                    {'family': 'ipv4', 'protocol': 'udp', 'verdict': 'accept', 'chain': 'input', 'connectionStates': []},
                    {'family': 'ipv6', 'protocol': 'udp', 'verdict': 'drop', 'chain': 'input', 'connectionStates': []},
                ],
            },
        })
        # Pin controller-created versions through the real UI before the existing packet/rollback cases.
        class DraftParser(HTMLParser):
            value = None
            def handle_starttag(self, tag, attrs):
                fields = dict(attrs)
                if tag == 'input' and fields.get('name') == 'bundleJson':
                    self.value = fields['value']

        def pin_probe(bundle, name, kind, address, index):
            _, location = admin.request('/manage/objects/save', 302, form={
                'expectedVersion': '0', 'name': name, 'kind': kind, 'description': '', 'entries': address,
                '__RequestVerificationToken': admin.token('/manage/objects'),
            }, expected_location_contains='/manage/objects?objectId=')
            object_id = location.split('objectId=')[1]
            body, _ = admin.request('/manage/policies/objects', 200, form={
                'bundleJson': bundle, 'ruleIndex': str(index), 'slot': 'source',
                'selection': object_id + '/1', 'operation': 'attach',
                '__RequestVerificationToken': admin.token('/manage/policies'),
            })
            parser = DraftParser(); parser.feed(body)
            require(parser.value is not None, 'Pinned draft did not retain JSON')
            reference = json.loads(parser.value)['filter']['rules'][index]['sourceObject']
            require(reference['nativeSet'] is True, 'New UI attachment lost native shared-set projection')
            require(reference['id'] == object_id and reference['version'] == 1, 'Pinned object identity lost')
            return parser.value

        rev1_json = pin_probe(rev1_json, 'probe4', 'ipv4', '127.0.0.1', 0)
        rev2_json = pin_probe(rev2_json, 'probe6', 'ipv6', '::1', 1)

        def set_state(bundle, index, enabled):
            fields = {'bundleJson': bundle, 'scope': 'Filter', 'ruleIndex': str(index),
                      '__RequestVerificationToken': admin.token('/manage/policies')}
            if enabled:
                fields['enabled'] = 'true'
            body, _ = admin.request('/manage/policies/rules/state', 200, form=fields)
            parser = DraftParser(); parser.feed(body)
            require(parser.value is not None, 'State change lost its draft')
            rule = json.loads(parser.value)['filter']['rules'][index]
            require(rule.get('enabled', True) == enabled, 'State flag was not preserved')
            return parser.value

        # An omitted dormant IPv6 drop must not defeat the existing allowed IPv6 packet probes.
        dormant = json.loads(rev1_json)
        dormant['filter']['rules'].insert(1, {'family': 'ipv6', 'protocol': 'udp', 'verdict': 'drop',
                                             'description': 'Retained dormant IPv6 drop'})
        rev1_json = set_state(json.dumps(dormant), 1, False)
        # The next revision enables its pinned IPv6 drop through the same actual UI boundary.
        pending = json.loads(rev2_json); pending['filter']['rules'][1]['enabled'] = False
        rev2_json = set_state(json.dumps(pending), 1, True)

        rev3_bundle_json = json.dumps({
            'schemaVersion': 1,
            'filter': {
                'schemaVersion': 2,
                'inputDefaultVerdict': 'accept',
                'forwardDefaultVerdict': 'drop',
                'outputDefaultVerdict': 'accept',
                'rules': [
                    {'family': 'ipv4', 'protocol': 'udp', 'verdict': 'accept', 'chain': 'input', 'connectionStates': []},
                ],
            },
            'nat': {
                'schemaVersion': 1,
                'dnatRules': [{'family': 'ipv4', 'protocol': 'tcp', 'originalDestination': '192.0.2.1/32', 'translatedAddress': '198.51.100.2', 'translatedPort': 8443}],
                'snatRules': [
                    {'family': 'ipv4', 'source': '192.0.2.0/24', 'translatedAddress': '198.51.100.2', 'outputInterface': 'wan0'},
                ],
            },
            'bridge': {
                'schemaVersion': 1,
                'defaultVerdict': 'accept', 'priority': -5,
                'rules': [
                    {'verdict': 'drop', 'bridgeName': 'br0', 'etherType': 'ipv4', 'jumpTarget': 'service'},
                ],
                'subChains': [{'name': 'service', 'rules': [{'etherType': 'any', 'verdict': 'drop', 'return': True}]}],
            },
            'auxiliaryFilter': {'priority': -5, 'filter': {
                'schemaVersion': 2, 'inputDefaultVerdict': 'accept', 'forwardDefaultVerdict': 'accept', 'outputDefaultVerdict': 'accept',
                'rules': [{'family': family, 'protocol': 'udp', 'verdict': 'drop', 'destinationPort': 19003, 'chain': 'input'} for family in ('ipv4', 'ipv6')],
            }},
        })

        # Carry controller-created port snapshots through the real multi-UID Unix/TLS apply boundary.
        _, location = admin.request('/manage/objects/save', 302, form={
            'expectedVersion': '0', 'name': 'probe_ports', 'kind': 'port', 'description': '', 'entries': '80\n443',
            '__RequestVerificationToken': admin.token('/manage/objects'),
        }, expected_location_contains='/manage/objects?objectId=')
        port_id = location.split('objectId=')[1]
        transport = json.loads(rev3_bundle_json)
        transport['nat']['snatRules'][0]['protocol'] = 'tcp'
        transport['bridge']['rules'][0]['protocol'] = 'tcp'
        transport['bridge']['rules'][0]['family'] = 'ipv4'
        transport['bridge']['rules'][0]['sourceMac'] = '02:00:00:00:00:01'
        transport['bridge']['rules'][0]['destinationMac'] = '02:00:00:00:00:02'
        transport['bridge']['subChains'][0]['rules'][0]['family'] = 'ipv4'
        transport['bridge']['subChains'][0]['rules'][0]['sourceMac'] = '02:00:00:00:00:01'
        transport['bridge']['subChains'][0]['rules'][0]['protocol'] = 'tcp'
        rev3_bundle_json = json.dumps(transport)
        for scope in ('dnat', 'postrouting', 'bridge', 'bridgeChain'):
            fields = {'bundleJson': rev3_bundle_json, 'scope': scope, 'slot': 'ports', 'ruleIndex': '0',
                      'selection': port_id + '/1', 'operation': 'attach', '__RequestVerificationToken': admin.token('/manage/policies')}
            if scope == 'bridgeChain':
                fields['chain'] = 'service'
            body, _ = admin.request('/manage/policies/objects', 200, form=fields)
            parser = DraftParser(); parser.feed(body)
            require(parser.value is not None, 'Transport port selection lost draft intent')
            rev3_bundle_json = parser.value
        for slot, name, entries in (('source', 'probe_sources', '192.0.2.0/24\n198.51.100.0/24'),
                                     ('destination', 'probe_destinations', '203.0.113.10\n203.0.113.20')):
            _, location = admin.request('/manage/objects/save', 302, form={
                'expectedVersion': '0', 'name': name, 'kind': 'ipv4', 'description': '', 'entries': entries,
                '__RequestVerificationToken': admin.token('/manage/objects'),
            }, expected_location_contains='/manage/objects?objectId=')
            object_id = location.split('objectId=')[1]
            for scope in ('dnat', 'postrouting', 'bridge', 'bridgeChain'):
                fields = {'bundleJson': rev3_bundle_json, 'scope': scope, 'slot': slot, 'ruleIndex': '0',
                          'selection': object_id + '/1', 'operation': 'attach', '__RequestVerificationToken': admin.token('/manage/policies')}
                if scope == 'bridgeChain':
                    fields['chain'] = 'service'
                body, _ = admin.request('/manage/policies/objects', 200, form=fields)
                parser = DraftParser(); parser.feed(body)
                require(parser.value is not None, 'NAT/bridge address selection lost draft intent')
                rev3_bundle_json = parser.value
        pinned = json.loads(rev3_bundle_json)
        require(len(pinned['nat']['snatRules'][0]['sourceObject']['entries']) == 2 and
                len(pinned['nat']['snatRules'][0]['destinationObject']['entries']) == 2,
                'Complete address snapshots were not retained for native apply')
        for rule in (pinned['bridge']['rules'][0], pinned['bridge']['subChains'][0]['rules'][0]):
            require(len(rule['sourceObject']['entries']) == 2 and len(rule['destinationObject']['entries']) == 2 and
                    rule['sourceMac'] == '02:00:00:00:00:01', 'Complete bridge MAC/address snapshots lost before native apply')
        require(len(pinned['nat']['dnatRules'][0]['sourceObject']['entries']) == 2 and
                len(pinned['nat']['dnatRules'][0]['destinationObject']['entries']) == 2,
                'Complete DNAT address snapshots lost before native apply')
        require(pinned['nat']['dnatRules'][0]['originalPortObject']['id'] == port_id and
                pinned['nat']['snatRules'][0]['destinationPortObject']['id'] == port_id and
                pinned['bridge']['rules'][0]['destinationPortObject']['id'] == port_id and
                pinned['bridge']['subChains'][0]['rules'][0]['destinationPortObject']['id'] == port_id,
                'Transport port identity was not retained across all selected scopes')

        for idx, (bundle, note) in enumerate([(rev1_json, 'drop-v4-udp'), (rev2_json, 'drop-v6-udp'), (rev3_bundle_json, 'multitable-filter-nat-bridge')], start=1):
            csrf = admin.token('/manage/policies')
            admin.request('/manage/policies/save', 302, form={
                'bundleJson': bundle,
                'summary': note,
                '__RequestVerificationToken': csrf,
            }, expected_location_contains=f'/manage/policies?revision={idx}')

        # Missing CSRF rejected with 400.
        admin.request('/controller/apply/start', 400, json_body={'hostId': unix_id, 'revision': 1, 'confirmationTimeoutSeconds': 10})

        def table_exists(family, name):
            res = subprocess.run(['nft', '--stateless', 'list', 'table', family, name],
                                 capture_output=True, text=True)
            return res.returncode == 0, res.stdout

        # Part 1: MVC start (2s timeout) -> real packet drop -> NO confirm -> autonomous watchdog rollback.
        mvc_csrf = admin.token(f'/manage/apply?hostId={unix_id}')
        admin.request('/manage/apply/start', 302, form={
            'hostId': unix_id,
            'revision': '1',
            'confirmationTimeoutSeconds': '2',
            '__RequestVerificationToken': mvc_csrf,
        }, expected_location_contains='notice=appliedPendingConfirmation')

        pending_html, _ = admin.request(f'/manage/apply?hostId={unix_id}&revision=1', 200)
        require('Confirm active apply' in pending_html and 'Immediate rollback' in pending_html,
                'Apply view did not show confirmation and rollback controls')
        require(not udp_loopback(socket.AF_INET, '127.0.0.1') and udp_loopback(socket.AF_INET6, '::1'),
                'Confirmed-apply candidate started via Web did not enforce kernel IPv4 UDP drop')

        restored = wait_until(
            lambda: (lambda r: r if r.get('outcome') == 'matched' else None)(
                json.loads(admin.request(f'/controller/apply/status?hostId={unix_id}', 200)[0])),
            timeout=10.0,
            message='Watchdog did not roll back unconfirmed web-started apply')
        require(restored['revision'] == '1' and restored['lastKnownRevision'] == '1', f'Unexpected post-watchdog status: {restored}')
        require(udp_loopback(socket.AF_INET, '127.0.0.1') and udp_loopback(socket.AF_INET6, '::1'),
                'Autonomous watchdog rollback did not restore IPv4 loopback packets')

        # Part 2: MVC start -> confirm -> persists rev 2 cleanly beyond window.
        mvc_csrf = admin.token(f'/manage/apply?hostId={unix_id}')
        admin.request('/manage/apply/start', 302, form={
            'hostId': unix_id,
            'revision': '1',
            'confirmationTimeoutSeconds': '10',
            '__RequestVerificationToken': mvc_csrf,
        }, expected_location_contains='notice=appliedPendingConfirmation')
        require(not udp_loopback(socket.AF_INET, '127.0.0.1'), 'Second start did not drop IPv4 UDP')
        live_pending = json.loads(admin.request(f'/controller/apply/status?hostId={unix_id}', 200)[0])
        require(live_pending['outcome'] == 'appliedPendingConfirmation', f'Unexpected pending status: {live_pending}')

        confirm_csrf = admin.token(f'/manage/apply?hostId={unix_id}')
        admin.request('/manage/apply/confirm', 302, form={
            'hostId': unix_id,
            'operationId': live_pending['operationId'],
            'watchdogId': live_pending['watchdogId'],
            'targetRevision': '1',
            '__RequestVerificationToken': confirm_csrf,
        }, expected_location_contains='notice=confirmed')

        confirmed_status = json.loads(admin.request(f'/controller/apply/status?hostId={unix_id}', 200)[0])
        require(confirmed_status['outcome'] == 'matched' and confirmed_status['revision'] == '2' and confirmed_status['lastKnownRevision'] == '2',
                f'Confirmed unix host status mismatch: {confirmed_status}')
        require(not udp_loopback(socket.AF_INET, '127.0.0.1') and udp_loopback(socket.AF_INET6, '::1'),
                'Confirmed Web apply did not enforce kernel packet rule')

        # Part 3: TLS 1.3 pinned mTLS host -> start rev 2 (drop IPv6 UDP) -> rollback -> start -> confirm rev 3.
        tls_start1 = json.loads(admin.request('/controller/apply/start', 200, json_body={
            'hostId': tls_id, 'revision': 2, 'confirmationTimeoutSeconds': 15,
        }, headers={'RequestVerificationToken': admin_csrf})[0])
        require(tls_start1['outcome'] == 'appliedPendingConfirmation', f'TLS start1 failed: {tls_start1}')
        require(udp_loopback(socket.AF_INET, '127.0.0.1') and not udp_loopback(socket.AF_INET6, '::1'),
                'TLS start1 did not flip UDP enforcement to IPv6 drop')

        tls_rb = json.loads(admin.request('/controller/apply/rollback', 200, json_body={
            'hostId': tls_id,
            'operationId': tls_start1['operationId'],
            'watchdogId': tls_start1['watchdogId'],
        }, headers={'RequestVerificationToken': admin_csrf})[0])
        require(tls_rb['outcome'] == 'rolledBack' and tls_rb['revision'] == '2', f'TLS rollback failed: {tls_rb}')
        require(not udp_loopback(socket.AF_INET, '127.0.0.1') and udp_loopback(socket.AF_INET6, '::1'),
                'TLS explicit rollback did not restore rev 2 kernel packet filter')

        tls_start2 = json.loads(admin.request('/controller/apply/start', 200, json_body={
            'hostId': tls_id, 'revision': 2, 'confirmationTimeoutSeconds': 15,
        }, headers={'RequestVerificationToken': admin_csrf})[0])
        require(tls_start2['outcome'] == 'appliedPendingConfirmation', f'TLS start2 failed: {tls_start2}')
        tls_conf = json.loads(admin.request('/controller/apply/confirm', 200, json_body={
            'hostId': tls_id,
            'operationId': tls_start2['operationId'],
            'watchdogId': tls_start2['watchdogId'],
            'targetRevision': 2,
        }, headers={'RequestVerificationToken': admin_csrf})[0])
        require(tls_conf['outcome'] == 'confirmed' and tls_conf['revision'] == '3' and tls_conf['lastKnownRevision'] == '3',
                f'TLS confirm failed: {tls_conf}')
        require(udp_loopback(socket.AF_INET, '127.0.0.1') and not udp_loopback(socket.AF_INET6, '::1'),
                'TLS confirm did not persist IPv6 UDP drop')

        # Part 3b: Multi-table (filter + nat + bridge) over TLS: watchdog rollback removes aux tables, then confirm persists all 3 tables.
        mt_start1 = json.loads(admin.request('/controller/apply/start', 200, json_body={
            'hostId': tls_id, 'revision': 3, 'confirmationTimeoutSeconds': 2,
        }, headers={'RequestVerificationToken': admin_csrf})[0])
        require(mt_start1['outcome'] == 'appliedPendingConfirmation', f'Multi-table start1 failed: {mt_start1}')
        nat_ok, nat_out = table_exists('inet', 'nergal_nat')
        br_ok, br_out = table_exists('bridge', 'nergal_bridge')
        require(table_exists('inet', 'nergal_aux')[0], 'Early inet table missing during pending HTTPS apply')
        require(not udp_loopback(socket.AF_INET, '127.0.0.1', 19003) and not udp_loopback(socket.AF_INET6, '::1', 19003), 'Early inet HTTPS apply did not enforce dual-stack packets')
        require(nat_ok and 'nergal:v1:' in nat_out and '198.51.100.2' in nat_out, f'nergal_nat missing during pending apply: {nat_out}')
        require(br_ok and 'nergal:v1:' in br_out and 'br0' in br_out, f'nergal_bridge missing during pending apply: {br_out}')

        mt_restored = wait_until(
            lambda: (lambda r: r if r.get('outcome') == 'matched' else None)(
                json.loads(admin.request(f'/controller/apply/status?hostId={tls_id}', 200)[0])),
            timeout=10.0,
            message='Watchdog did not roll back unconfirmed multi-table apply')
        require(mt_restored['revision'] == '3', f'Unexpected post-multitable-rollback status: {mt_restored}')
        require(not table_exists('inet', 'nergal_aux')[0] and not table_exists('inet', 'nergal_nat')[0] and not table_exists('bridge', 'nergal_bridge')[0],
                'Autonomous watchdog rollback did not delete auxiliary NAT/bridge tables')

        mt_start2 = json.loads(admin.request('/controller/apply/start', 200, json_body={
            'hostId': tls_id, 'revision': 3, 'confirmationTimeoutSeconds': 15,
        }, headers={'RequestVerificationToken': admin_csrf})[0])
        require(mt_start2['outcome'] == 'appliedPendingConfirmation', f'Multi-table start2 failed: {mt_start2}')
        mt_conf = json.loads(admin.request('/controller/apply/confirm', 200, json_body={
            'hostId': tls_id,
            'operationId': mt_start2['operationId'],
            'watchdogId': mt_start2['watchdogId'],
            'targetRevision': 3,
        }, headers={'RequestVerificationToken': admin_csrf})[0])
        require(mt_conf['outcome'] == 'confirmed' and mt_conf['revision'] == '4' and mt_conf['lastKnownRevision'] == '4',
                f'Multi-table confirm failed: {mt_conf}')
        require(table_exists('inet', 'nergal_aux')[0] and table_exists('inet', 'nergal_nat')[0] and table_exists('bridge', 'nergal_bridge')[0],
                'Confirmed multi-table apply did not persist auxiliary NAT and bridge tables')
        require(udp_loopback(socket.AF_INET, '127.0.0.1') and udp_loopback(socket.AF_INET6, '::1'),
                'Confirmed multi-table apply did not update filter table enforcement')

        web_proc.terminate()
        web_proc.wait(timeout=10)
        web_log.close()
        web_proc = None
        web_log = None

        # Part 4: Auditor RBAC verification against same controller.db and running agents.
        web_proc, web_log, aud_port = start_web(auditor_accounts)
        auditor = WebClient(aud_port, tls_ctx)
        auditor.login('fixture-auditor', sessions.PASSWORD)

        auditor_html, _ = auditor.request(f'/manage/apply?hostId={tls_id}', 200)
        require('Start confirmed apply' not in auditor_html, 'Auditor rendered apply start controls')
        require('matched' in auditor_html, 'Auditor did not see live matched status')
        aud_status = json.loads(auditor.request(f'/controller/apply/status?hostId={tls_id}', 200)[0])
        require(aud_status['outcome'] == 'matched' and aud_status['revision'] == '4', f'Unexpected auditor status: {aud_status}')

        aud_csrf = auditor.token('/session')
        auditor.request('/manage/apply/start', 403, form={
            'hostId': unix_id,
            'revision': '1',
            'confirmationTimeoutSeconds': '10',
            '__RequestVerificationToken': aud_csrf,
        })
        for ep in ('/controller/apply/start', '/controller/apply/confirm', '/controller/apply/rollback'):
            auditor.request(ep, 403, json_body={
                'hostId': unix_id, 'revision': 1, 'operationId': unix_id, 'watchdogId': unix_id,
            }, headers={'RequestVerificationToken': aud_csrf})

        # Verify controller audit trail recorded start, rollback, and confirm actions cleanly.
        entries = json.loads(auditor.request('/controller/audit', 200)[0])['entries']
        actions = [(e['action'], e['target'], e['outcome'], e['detailCode']) for e in entries]
        require(('apply.confirm', 'unix-agent', 'confirmed', None) in actions, 'Missing unix confirm audit')
        require(('apply.rollback', 'tls-agent', 'rolled_back', None) in actions, 'Missing tls rollback audit')
        require(('apply.confirm', 'tls-agent', 'confirmed', None) in actions, 'Missing tls confirm audit')
    finally:
        if web_proc is not None and web_proc.poll() is None:
            web_proc.terminate()
            web_proc.wait(timeout=10)
        if web_log is not None:
            web_log.close()
        for proc in (ctrl_proc, tls_proc):
            if proc.poll() is None:
                proc.terminate()
                proc.communicate(timeout=10)

    for family, snapshot in foreign.items():
        require(run(['nft', '--stateless', 'list', 'table', family, 'foreign_fixture']).stdout == snapshot,
                f'Foreign table mutated in {family}')

    print('PASS: unprivileged Kestrel two-phase apply, autonomous watchdog packet rollback, explicit rollback, and TLS/Unix confirmation', flush=True)
