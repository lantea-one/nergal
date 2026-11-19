"""Second disposable network namespace, sharing only the protected synthetic journal for comparison."""
import json
import subprocess
import sys

payload = json.load(sys.stdin)
result = subprocess.run(['nft', '--file', '-'], input=payload['candidate'], capture_output=True, text=True, timeout=5)
assert result.returncode == 0, 'Second-namespace candidate failed'
result = subprocess.run(['nft', '--json', 'list', 'table', 'inet', 'nergal_filter'], capture_output=True, text=True, timeout=5)
assert result.returncode == 0, 'Second-namespace observation failed'
result = subprocess.run(['dotnet', sys.argv[1], 'verify', payload['state']], input=result.stdout,
                        capture_output=True, text=True, timeout=10)
assert result.returncode == 1, 'Protected receipt was accepted in another namespace'
assert 'context.namespaceChanged' in json.loads(result.stdout)['ErrorCodes'], 'Expected context mismatch missing'
