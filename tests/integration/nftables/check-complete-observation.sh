#!/usr/bin/env bash
# Native snapshots only in a fresh namespace. Never operates on the host ruleset.
set -euo pipefail
cd "$(dirname "$0")/../../.."
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
runner=(dotnet tests/integration/nftables/bin/Release/net10.0/Nergal.Nftables.Fixture.dll)
"${runner[@]}" router-complete-bundle > "$fixture/candidate.nft"
unshare --user --map-root-user --net python3 - "$fixture" "$(readlink /proc/self/ns/net)" <<'PY'
import pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
assert pathlib.Path('/proc/self/ns/net').readlink().as_posix() != sys.argv[2]
def nft(*args):
    return subprocess.check_output(['/usr/sbin/nft', *args])
nft('--check', '-f', str(root / 'candidate.nft'))
(root / 'bundle-echo.json').write_bytes(nft('--echo', '--handle', '--json', '-f', str(root / 'candidate.nft')))
for family, name in [('inet', 'filter'), ('inet', 'nat'), ('bridge', 'bridge'), ('inet', 'aux')]:
    (root / f'{name}-list.json').write_bytes(nft('--terse', '--json', 'list', 'table', family, f'nergal_{name}'))
PY
"${runner[@]}" verify-complete-bundle "$fixture/bundle-echo.json" "$fixture/filter-list.json" "$fixture/nat-list.json" "$fixture/bridge-list.json" "$fixture/aux-list.json"
printf 'PASS: all four owned tables reconstruct identical complete native fingerprints and candidates\n'
