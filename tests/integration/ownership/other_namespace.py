"""Second fresh network namespace, still inside the wrapper's disposable user namespace."""
import json
import os
from pathlib import Path
import subprocess
import sys

payload = json.load(sys.stdin)
receipt = payload['receipt']
current = int(os.readlink('/proc/self/ns/net').removeprefix('net:[').removesuffix(']'))
assert current != receipt['namespace'], 'Second namespace was not created'
result = subprocess.run(['nft', '--file', '-'], input=payload['candidate'], capture_output=True, text=True, timeout=5)
assert result.returncode == 0, 'Second-namespace candidate failed'
result = subprocess.run(['nft', '--json', 'list', 'table', 'inet', 'nergal_filter'], capture_output=True, text=True, timeout=5)
assert result.returncode == 0, 'Second-namespace observation failed'
envelope = receipt | {'observation': result.stdout, 'currentBoot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                      'currentNamespace': current}
result = subprocess.run(['dotnet', sys.argv[1], 'verify'], input=json.dumps(envelope), capture_output=True, text=True, timeout=10)
assert result.returncode == 1, 'Cross-namespace receipt was accepted'
assert 'context.namespaceChanged' in json.loads(result.stdout)['ErrorCodes'], 'Context rejection missing'
