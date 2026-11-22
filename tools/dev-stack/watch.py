"""Refresh the local sandbox after source edits, keeping the last successful build available."""
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
STATUS = ROOT / 'artifacts/dev-stack/watch-status.txt'
LOCK = ROOT / 'artifacts/dev-stack/watch.lock'


def fingerprint():
    files = [*ROOT.glob('*.props'), *ROOT.glob('*.targets'), ROOT / 'global.json']
    for root in (ROOT / 'src', ROOT / 'tests', ROOT / 'tools/dev-stack'):
        files.extend(p for p in root.rglob('*') if p.is_file() and not {'bin', 'obj', '__pycache__'} & set(p.parts))
    mapping = ROOT / 'artifacts/dev-stack/source-map.txt'
    if mapping.exists():
        files.extend(Path(s) for s in mapping.read_text().splitlines())
    return tuple(sorted((str(p), p.stat().st_mtime_ns, p.stat().st_size) for p in files if p.exists()))


def main():
    # One supervisor per local stack. Linux flock releases automatically on exit.
    import fcntl
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous = fingerprint()
        STATUS.write_text('Watching; sandbox reflects the last successful refresh.\n')
        while True:
            time.sleep(2)
            changed = fingerprint()
            if changed == previous:
                continue
            STATUS.write_text('Rebuilding; existing sandbox remains available until publish.\n')
            time.sleep(2)
            before = fingerprint()
            with (ROOT / 'artifacts/dev-stack/watch-build.log').open('w') as log:
                result = subprocess.run(['bash', 'tools/dev-stack/up.sh'], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            previous = before
            STATUS.write_text('Updated successfully.\n' if result.returncode == 0 else 'Refresh failed; inspect watch-build.log.\n')


if __name__ == '__main__':
    main()
