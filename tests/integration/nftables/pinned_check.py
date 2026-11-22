"""Dual-stack pinned source/destination/port snapshots in a fresh disposable namespace."""
import os
from pathlib import Path
import socket
import subprocess
import sys


def run(args, text=None):
    return subprocess.run(args, input=text, text=True, capture_output=True, check=True).stdout


def main():
    candidate, echo, listing, host_net, host_user = sys.argv[1:]
    assert os.readlink('/proc/self/ns/net') != host_net
    assert os.readlink('/proc/self/ns/user') != host_user
    run(['ip', 'link', 'set', 'lo', 'up'])
    for suffix in range(1, 6):
        run(['ip', '-6', 'addr', 'add', f'2001:db8::{suffix}/128', 'dev', 'lo'])
    run(['nft', '-f', '-'], 'create table inet foreign_fixture\n')
    foreign = run(['nft', 'list', 'table', 'inet', 'foreign_fixture'])
    text = Path(candidate).read_text()
    run(['nft', '--check', '-f', '-'], text)
    Path(echo).write_text(run(['nft', '--echo', '--handle', '--json', '-f', '-'], text))
    Path(listing).write_text(run(['nft', '--terse', '--json', 'list', 'table', 'inet', 'nergal_filter']))
    for family, prefix in [(socket.AF_INET, '127.0.0.'), (socket.AF_INET6, '2001:db8::')]:
        for source, destination, port, permitted in [(2, 1, 19001, True), (4, 1, 19003, True),
                (3, 1, 19001, False), (2, 5, 19001, False), (2, 1, 19002, False)]:
            with socket.socket(family, socket.SOCK_DGRAM) as receiver, socket.socket(family, socket.SOCK_DGRAM) as sender:
                receiver.settimeout(0.25); receiver.bind((prefix + str(destination), port))
                sender.bind((prefix + str(source), 0)); sender.sendto(b'pinned-fixture', (prefix + str(destination), port))
                try:
                    data = receiver.recv(128); received = data == b'pinned-fixture'
                except TimeoutError:
                    received = False
                assert received == permitted, (family, source, destination, port, permitted)
    assert run(['nft', 'list', 'table', 'inet', 'foreign_fixture']) == foreign
    print('PASS: dual-stack pinned source/destination/port admission and independent mismatch denial; foreign table preserved')


if __name__ == '__main__':
    main()
