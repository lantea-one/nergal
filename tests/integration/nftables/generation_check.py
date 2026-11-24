"""Read-only generation queries bound real config changes, not dynamic packet-meter updates."""
import json
import os
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise AssertionError(message)


require(len(sys.argv) == 4, 'Invoke through check-generation.sh with isolation guards')
require(os.readlink('/proc/self/ns/user') != sys.argv[2], 'User namespace must be isolated')
require(os.readlink('/proc/self/ns/net') != sys.argv[3], 'Network namespace must be isolated')
require(os.getuid() == 0, 'Expected namespace-local root')
fixture = sys.argv[1]


def generation():
    return int(subprocess.check_output(['dotnet', fixture, 'generation'], text=True, timeout=5))


def nft(commands):
    subprocess.run(['nft', '-f', '-'], input=commands, text=True, check=True, capture_output=True, timeout=5)


initial = generation()
require(generation() == initial, 'Read-only queries changed configuration generation')
nft('''table inet nergal_generation_fixture {
 set clients { type ipv4_addr; elements = { 192.0.2.1 }; }
 chain input { type filter hook input priority 0; policy accept;
  ip protocol icmp meter per_source { ip saddr limit rate 100/second } counter accept
 }
}''')
created = generation()
require(created != initial, 'Table creation must change transaction generation')
listing = json.loads(subprocess.check_output(['nft', '--json', '--handle', 'list', 'set', 'inet', 'nergal_generation_fixture', 'clients']))
handle = next(item['set']['handle'] for item in listing['nftables'] if 'set' in item)
nft('add element inet nergal_generation_fixture clients { 198.51.100.1 }')
changed = generation()
require(changed != created, 'Same-handle set-element changes must invalidate snapshot collection')
listing = json.loads(subprocess.check_output(['nft', '--json', '--handle', 'list', 'set', 'inet', 'nergal_generation_fixture', 'clients']))
require(next(item['set']['handle'] for item in listing['nftables'] if 'set' in item) == handle,
        'Fixture did not exercise same-handle set mutation')
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
subprocess.run(['ping', '-c', '3', '-i', '0.05', '-W', '1', '127.0.0.1'], check=True, capture_output=True, timeout=5)
require(generation() == changed, 'Dynamic meter traffic must not invalidate configuration snapshots')
rules = json.loads(subprocess.check_output(['nft', '--json', 'list', 'table', 'inet', 'nergal_generation_fixture']))
require(any(expr.get('counter', {}).get('packets', 0) >= 3
            for item in rules['nftables'] for expr in item.get('rule', {}).get('expr', [])),
        'Real packets did not traverse the dynamic meter')
# Single-ID user mappings cannot setuid: use capsh to drop NET_ADMIN in this namespace instead.
denied = subprocess.run(['capsh', '--drop=cap_net_admin', '--', '-c',
                         'exec "$1" "$2" generation-denied', 'generation-check',
                         subprocess.check_output(['which', 'dotnet'], text=True).strip(), fixture],
                        check=True, capture_output=True, text=True, timeout=5)
require(denied.stdout == 'denied', 'Unprivileged generation query did not fail closed')
nft('delete table inet nergal_generation_fixture')
require(generation() != changed, 'Table deletion must change transaction generation')
print('Generation: stable reads, same-handle set drift, dynamic meter packets and capability denial passed')
