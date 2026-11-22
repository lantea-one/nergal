#!/usr/bin/env python3
"""Disposable-namespace kernel verification for inline address/port sets and IPv4 ICMPv4 parameter-problem."""
import os
import subprocess
import sys
from pathlib import Path


def run(cmd, *, text_in=None):
    return subprocess.run(cmd, input=text_in, capture_output=True, text=True, check=True)


def main():
    candidate_path, echo_out, list_out, host_netns, host_userns = sys.argv[1:6]
    assert os.readlink('/proc/self/ns/net') != host_netns, 'Must run in disposable netns'
    assert os.readlink('/proc/self/ns/user') != host_userns, 'Must run in disposable userns'

    foreign_seed = 'create table inet foreign_fixture\nadd chain inet foreign_fixture input { type filter hook input priority 0; policy accept; }\n'
    run(['nft', '--file', '-'], text_in=foreign_seed)
    foreign_before = run(['nft', '--stateless', 'list', 'table', 'inet', 'foreign_fixture']).stdout

    candidate = Path(candidate_path).read_text(encoding='utf-8')
    run(['nft', '--check', '--file', '-'], text_in=candidate)
    echo_json = run(['nft', '--echo', '--handle', '--json', '--file', '-'], text_in=candidate).stdout
    list_json = run(['nft', '--terse', '--json', 'list', 'table', 'inet', 'nergal_filter']).stdout

    Path(echo_out).write_text(echo_json, encoding='utf-8')
    Path(list_out).write_text(list_json, encoding='utf-8')

    foreign_after = run(['nft', '--stateless', 'list', 'table', 'inet', 'foreign_fixture']).stdout
    assert foreign_after == foreign_before, 'Foreign table mutated'
    print('PASS: inline address/port sets and IPv4 ICMPv4 parameter-problem loaded and preserved foreign tables', flush=True)


if __name__ == '__main__':
    main()
