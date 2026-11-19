"""Real input-hook packets and transaction denials in a fresh user/network namespace.

Socket timeouts bound denied-packet assertions; no service startup sleeps are used.
This loopback fixture does not verify forwarding, neighbor discovery, NAT or rollback.
"""
import os
from pathlib import Path
import socket
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise AssertionError(message)


# Refuse direct invocation in the caller's namespaces, even if invoked as root.
require(len(sys.argv) == 4, "Invoke through check.sh with namespace guards")
require(os.readlink('/proc/self/ns/net') != sys.argv[2], "Network namespace was not isolated")
require(os.readlink('/proc/self/ns/user') != sys.argv[3], "User namespace was not isolated")
require(os.getuid() == 0, "Expected namespace-local root")


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def nft(batch, success=True, check=False):
    args = ['nft'] + (['--check'] if check else []) + ['--file', '-']
    result = subprocess.run(args, input=batch, text=True, capture_output=True)
    require((result.returncode == 0) == success,
            f"Unexpected nft result ({result.returncode}): {result.stderr}")


def state():
    return run('nft', '--stateless', 'list', 'ruleset')


run('ip', 'link', 'set', 'lo', 'up')
for address in ('192.0.2.1/32', '192.0.2.2/32', '192.0.2.3/32',
                '2001:db8::1/128', '2001:db8::2/128', '2001:db8::3/128'):
    run('ip', 'address', 'add', address, 'dev', 'lo', 'nodad')

candidate = Path(sys.argv[1]).read_text()
for family in ('ip', 'ip6', 'inet', 'bridge'):
    nft(f'create table {family} foreign_fixture\n'
        f'add chain {family} foreign_fixture sentinel\n'
        f'add rule {family} foreign_fixture sentinel counter\n')
foreign = state()
# Check mode must leave the complete namespace unchanged.
nft(candidate, check=True)
require(state() == foreign, "Check mode changed state")
# Even a conflicting reserved name is foreign until ownership is proven.
nft('create table inet nergal_filter\nadd chain inet nergal_filter sentinel\n')
collision = state()
nft(candidate, success=False, check=True)
nft(candidate, success=False)
require(state() == collision, "Collision changed existing tables")
nft('delete table inet nergal_filter\n')
# A kernel-invalid command after a valid candidate must prevent all provisioning.
nft(candidate + 'add rule inet nergal_filter missing_chain accept\n', success=False)
require(state() == foreign, "Invalid batch was partially installed")
nft(candidate)
installed = state()
nft(candidate, success=False)
require(state() == installed, "Repeated provisioning mutated the installed table")
for family in ('ip', 'ip6', 'inet', 'bridge'):
    table = run('nft', '--stateless', 'list', 'table', family, 'foreign_fixture')
    require(table in foreign, f"Foreign {family} table changed")
print('PASS: check-only, foreign tables, collision refusal and atomic failure')


def tcp(family, destination, source, port, allowed):
    with socket.socket(family, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((destination, port))
        server.listen(1)
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(0.3)
            client.bind((source, 0))
            try:
                client.connect((destination, port))
            except socket.timeout:
                require(not allowed, f"Allowed TCP timed out: {source} -> {destination}:{port}")
            else:
                require(allowed, f"Denied TCP connected: {source} -> {destination}:{port}")
                connection, _ = server.accept()
                connection.close()


def udp(family, destination, source, port, allowed):
    with socket.socket(family, socket.SOCK_DGRAM) as server:
        server.bind((destination, port))
        server.settimeout(0.3)
        with socket.socket(family, socket.SOCK_DGRAM) as client:
            client.bind((source, 0))
            client.sendto(b'nergal-isolated-fixture', (destination, port))
            try:
                payload, _ = server.recvfrom(128)
            except socket.timeout:
                require(not allowed, f"Allowed UDP timed out: {source} -> {destination}:{port}")
            else:
                require(allowed and payload == b'nergal-isolated-fixture',
                        f"Denied UDP arrived: {source} -> {destination}:{port}")


for family, target, other, wrong_destination, ping_flag in (
        (socket.AF_INET, '192.0.2.1', '192.0.2.2', '192.0.2.3', '-4'),
        (socket.AF_INET6, '2001:db8::1', '2001:db8::2', '2001:db8::3', '-6')):
    tcp(family, target, target, 18080, True)
    tcp(family, target, target, 18082, False)  # First drop precedes broad TCP accept.
    tcp(family, target, other, 18080, False)
    tcp(family, wrong_destination, target, 18080, False)
    udp(family, target, target, 18081, True)
    udp(family, target, target, 18083, False)  # Unmatched default drop.
    udp(family, target, other, 18081, False)
    udp(family, wrong_destination, target, 18081, False)
    run('ping', ping_flag, '-n', '-c', '1', '-W', '1', target)
print('PASS: IPv4/IPv6 TCP, UDP, ICMP; rule order, source/destination scopes and default denial')
