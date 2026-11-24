"""Low IPv6 intervals require complete creation evidence and still enforce actual member/miss packets."""
import os
from pathlib import Path
import socket
import subprocess
import sys

assert len(sys.argv) == 6
assert os.readlink('/proc/self/ns/user') != sys.argv[4] and os.readlink('/proc/self/ns/net') != sys.argv[5]
assert os.getuid() == 0
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
subprocess.run(['ip', '-6', 'addr', 'add', '2001:db8::2/128', 'dev', 'lo', 'nodad'], check=True)
text = Path(sys.argv[1]).read_text()
echo = subprocess.run(['nft', '--echo', '--json', '--handle', '-f', '-'], input=text, text=True, check=True, capture_output=True).stdout
Path(sys.argv[2]).write_text(echo)
Path(sys.argv[3]).write_text(subprocess.check_output(['nft', '--json', 'list', 'table', 'inet', 'nergal_filter'], text=True))
for source, expected in [('::1', True), ('2001:db8::2', False)]:
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client:
        server.bind(('::1', 19001)); server.settimeout(.25)
        client.bind((source, 0)); client.sendto(b'low-ipv6', ('::1', 19001))
        try:
            actual = server.recv(32) == b'low-ipv6'
        except TimeoutError:
            actual = False
        assert actual == expected
print('PASS: low IPv6 singleton/prefix set member admission and source-miss denial')
