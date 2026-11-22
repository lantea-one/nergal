"""Recheck one read-only private native source; never apply it or print its contents."""
import hashlib
import json
from pathlib import Path
import subprocess
import time

source = Path('/source.nft')
report = Path('/report/status.json')
previous = None
while True:
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if digest != previous:
        result = subprocess.run(['nft', '--check', '--file', str(source)], capture_output=True, timeout=15)
        # Native diagnostics can contain addresses or other private source text.
        # Store only outcome and content binding; never put native stderr in logs.
        temporary = report.with_suffix('.tmp')
        temporary.write_text(json.dumps({'digest': digest, 'checkOnly': True, 'valid': result.returncode == 0}))
        temporary.replace(report)
        previous = digest
    time.sleep(2)
