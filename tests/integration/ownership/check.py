"""Expected receipt versus native observations; all kernel state is synthetic and namespace-local."""
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid


def require(condition, message):
    if not condition:
        raise AssertionError(message)


require(len(sys.argv) == 4, 'Invoke through check.sh')
assembly, parent_user, parent_net = sys.argv[1:]
require(os.readlink('/proc/self/ns/user') != parent_user, 'User isolation missing')
require(os.readlink('/proc/self/ns/net') != parent_net, 'Network isolation missing')
require(os.getuid() == 0, 'Namespace root required')


def run(arguments, input=None, success=True):
    try:
        result = subprocess.run(arguments, input=input, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        raise AssertionError('Conformance subprocess timed out') from None
    require((result.returncode == 0) == success, 'Unexpected conformance subprocess result')
    return result.stdout


def nft(batch):
    run(['nft', '--file', '-'], batch)


def observation():
    return run(['nft', '--json', 'list', 'table', 'inet', 'nergal_filter'])


def namespace():
    return int(os.readlink('/proc/self/ns/net').removeprefix('net:[').removesuffix(']'))


def verify(receipt, text, success, expected_code=None):
    payload = receipt | {'observation': text, 'currentBoot': boot, 'currentNamespace': namespace()}
    result = json.loads(run(['dotnet', assembly, 'verify'], json.dumps(payload), success))
    if expected_code:
        require(expected_code in result['ErrorCodes'], 'Expected receipt mismatch code missing')


boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
owner, resource = str(uuid.uuid4()), str(uuid.uuid4())
candidate = run(['dotnet', assembly, 'emit', owner, resource])
for family in ('ip', 'ip6', 'inet', 'bridge'):
    nft(f'create table {family} foreign_fixture\nadd chain {family} foreign_fixture sentinel\n')
foreign = {family: run(['nft', '--stateless', 'list', 'table', family, 'foreign_fixture'])
           for family in ('ip', 'ip6', 'inet', 'bridge')}
run(['nft', '--check', '--file', '-'], candidate)
nft(candidate)
original = observation()
inspected = json.loads(run(['dotnet', assembly, 'inspect'], original))
receipt = {'boot': boot, 'namespace': namespace(), 'owner': owner, 'resource': resource,
           'handle': inspected['TableHandle'], 'digest': inspected['Digest']}
verify(receipt, original, True)
print('PASS: tagged candidate and complete native observation match expected bindings', flush=True)

nft('add chain inet nergal_filter input { policy drop; }\n')
verify(receipt, observation(), False, 'state.drift')
nft('add chain inet nergal_filter input { policy accept; }\n')
verify(receipt, observation(), True)
nft('add chain inet nergal_filter unexpected_chain\n')
state = run(['nft', '--stateless', 'list', 'ruleset'])
rejected = json.loads(run(['dotnet', assembly, 'inspect'], observation(), False))
require(rejected['error'] == 'observation.unsupportedObjects', 'Unexpected objects were ignored')
require(run(['nft', '--stateless', 'list', 'ruleset']) == state, 'Observation probe mutated kernel state')
nft('delete chain inet nergal_filter unexpected_chain\n')
print('PASS: real policy drift and unexpected objects rejected without observation-side writes', flush=True)

# Deliberately recreate the fixture-owned resource with an identical name/comment/policy.
nft('delete table inet nergal_filter\n' + candidate)
replacement = observation()
require(json.loads(run(['dotnet', assembly, 'inspect'], replacement))['TableHandle'] != receipt['handle'],
        'Recreation did not yield a different native handle')
verify(receipt, replacement, False, 'handle.mismatch')
print('PASS: same-name/same-comment replacement is not adopted as the expected resource', flush=True)

# A second real namespace must not reuse the first namespace's receipt, even with copied marker bytes.
payload = {'candidate': candidate, 'receipt': receipt}
run(['unshare', '--net', sys.executable, str(Path(__file__).with_name('other_namespace.py')), assembly], json.dumps(payload))
print('PASS: a different real network namespace cannot satisfy the expected context', flush=True)
for family, expected in foreign.items():
    require(run(['nft', '--stateless', 'list', 'table', family, 'foreign_fixture']) == expected,
            'Foreign table changed during identity conformance')
print('PASS: foreign ip/ip6/inet/bridge tables preserved', flush=True)
