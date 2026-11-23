"""Real packet outcomes for disabling accept/drop rules; fresh namespaces and owned synthetic tables only."""
import os
from pathlib import Path
import socket
import subprocess
import sys


def main():
    root, host_net, host_user = sys.argv[1:]
    assert os.readlink('/proc/self/ns/net') != host_net
    assert os.readlink('/proc/self/ns/user') != host_user
    root = Path(root)
    def run(args, text=None):
        return subprocess.run(args, input=text, text=True, capture_output=True, check=True).stdout
    run(['ip', 'link', 'set', 'lo', 'up'])
    for suffix in (1, 2, 4):
        run(['ip', '-6', 'addr', 'add', f'2001:db8::{suffix}/128', 'dev', 'lo', 'nodad'])
    run(['nft', '-f', '-'], 'create table inet foreign_fixture\n')
    foreign = run(['nft', 'list', 'table', 'inet', 'foreign_fixture'])
    exists = False
    for mode, allowed in [('state-accept-on', True), ('state-accept-off', False), ('state-accept-on', True),
                          ('state-drop-on', False), ('state-drop-off', True), ('state-drop-on', False)]:
        candidate = (root / (mode + '.nft')).read_text()
        replacement = ('delete table inet nergal_filter\n' if exists else '') + candidate
        run(['nft', '--check', '-f', '-'], replacement); run(['nft', '-f', '-'], replacement); exists = True
        for family, prefix in [(socket.AF_INET, '127.0.0.'), (socket.AF_INET6, '2001:db8::')]:
            with socket.socket(family, socket.SOCK_DGRAM) as receiver, socket.socket(family, socket.SOCK_DGRAM) as sender:
                receiver.settimeout(0.25); receiver.bind((prefix + '1', 19001))
                sender.bind((prefix + '2', 0)); sender.sendto(b'rule-state', receiver.getsockname())
                try: received = receiver.recv(128) == b'rule-state'
                except TimeoutError: received = False
                assert received == allowed, (mode, family, allowed)
        assert run(['nft', 'list', 'table', 'inet', 'foreign_fixture']) == foreign
    print('PASS: dual-stack disabling/restoring accept and drop rules changes real packet admission and preserves foreign tables')


if __name__ == '__main__':
    main()
