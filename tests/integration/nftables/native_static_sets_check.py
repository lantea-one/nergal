"""Complete static named-set observations with separate dynamic-meter state and foreign preservation."""
import json
import os
from pathlib import Path
import subprocess
import sys

assert len(sys.argv) == 4
assert os.readlink('/proc/self/ns/user') != sys.argv[2]
assert os.readlink('/proc/self/ns/net') != sys.argv[3]
assert os.getuid() == 0
root = Path(sys.argv[1])


def run(*args, text=None):
    return subprocess.run(args, input=text, text=True, check=True, capture_output=True, timeout=10).stdout


run('nft', '-f', '-', text='create table inet foreign_probe\n')
foreign = run('nft', '--json', 'list', 'table', 'inet', 'foreign_probe')
candidate = (root / 'candidate.nft').read_text()
run('nft', '--check', '-f', '-', text=candidate)
(root / 'echo.json').write_text(run('nft', '--echo', '--json', '--handle', '-f', '-', text=candidate))
for family, table, file in [('inet', 'nergal_filter', 'filter'), ('inet', 'nergal_nat', 'nat'),
                            ('bridge', 'nergal_bridge', 'bridge'), ('inet', 'nergal_aux', 'aux')]:
    complete = run('nft', '--json', 'list', 'table', family, table)
    (root / (file + '.json')).write_text(complete)
    terse = json.loads(run('nft', '--terse', '--json', 'list', 'table', family, table))
    for item in terse['nftables']:
        if 'set' in item and item['set']['name'].startswith('nergal_obj_'):
            assert 'elem' not in item['set'], 'Terse listing unexpectedly retained static contents'
            set_listing = json.loads(run('nft', '--json', 'list', 'set', family, table, item['set']['name']))
            static = next(i['set'] for i in set_listing['nftables'] if 'set' in i)
            assert static['elem'], 'Complete per-set listing lost contents'
assert run('nft', '--json', 'list', 'table', 'inet', 'foreign_probe') == foreign
