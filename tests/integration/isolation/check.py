"""Real distinct service UIDs in a disposable namespace; synthetic filesystem state only."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise AssertionError(message)


require(len(sys.argv) == 4, 'Invoke through check.sh')
assembly, parent_user, parent_net = sys.argv[1:]
require(os.readlink('/proc/self/ns/user') != parent_user, 'User namespace isolation missing')
require(os.readlink('/proc/self/ns/net') != parent_net, 'Network namespace isolation missing')
require(os.getuid() == 0, 'Namespace root required')
# UID 1 must have a real subordinate mapping, not the unmapped overflow identity.
maps = [tuple(map(int, line.split())) for line in Path('/proc/self/uid_map').read_text().splitlines()]
require(any(start <= 1 < start + count for start, _, count in maps), 'A subordinate UID mapping is required')


def probe(mode, state, expected=None):
    result = subprocess.run(['dotnet', assembly, mode, str(state)], capture_output=True, text=True, timeout=10)
    if expected is None:
        require(result.returncode == 0 and result.stdout.strip() == 'OK', f'{mode} failed: {result.stderr}')
    else:
        require(result.returncode != 0 and result.stderr.strip() == expected,
                f'Expected {expected}, got {result.stderr}')


with tempfile.TemporaryDirectory(prefix='nergal-isolation-') as root:
    root = Path(root)
    os.chmod(root, 0o711)  # Browser may traverse the test root, but cannot replace its private children.
    state = root / 'agent'
    state.mkdir(mode=0o700)
    probe('initialize', state)
    database = state / 'journal.db'
    original = database.read_bytes()
    browser_directory = root / 'browser'
    browser_directory.mkdir(mode=0o700)
    os.chown(browser_directory, 1, 1)
    browser_code = Path(__file__).with_name('browser.py').read_text()
    pid = os.fork()
    if pid == 0:
        try:
            try:
                os.setgroups([])
            except PermissionError:
                pass  # Some rootless mappings prohibit setgroups; owner-only modes grant no group access.
            os.setgid(1)
            os.setuid(1)
            # exec discards the parent's address space and any private artifact objects inherited by fork.
            os.execv(sys.executable, [sys.executable, '-c', browser_code, str(root)])
        except BaseException:
            os._exit(1)
    _, status = os.waitpid(pid, 0)
    require(os.waitstatus_to_exitcode(status) == 0, 'Browser UID isolation failed')
    require(database.read_bytes() == original, 'Browser changed journal bytes')
    probe('read', state)
    print('PASS: unprivileged browser UID cannot read/write/unlink/replace agent state', flush=True)

    # Namespace root could override DAC, so the managed store must reject a mismatched owner explicitly.
    os.chown(database, 1, 1)
    probe('read', state, 'path.owner')
    os.chown(database, 0, 0)
    os.chown(state, 1, 1)
    probe('read', state, 'path.owner')
    os.chown(state, 0, 0)
    for suffix in ('-journal', '-wal', '-shm'):
        sidecar = state / ('journal.db' + suffix)
        sidecar.write_bytes(b'foreign sentinel')
        os.chmod(sidecar, 0o600)
        os.chown(sidecar, 1, 1)
        probe('read', state, 'path.owner')
        require(sidecar.read_bytes() == b'foreign sentinel', 'Foreign sidecar was modified')
        sidecar.unlink()
    print('PASS: foreign directory/database/sidecar owners rejected before SQLite open', flush=True)

    alias = root / 'shared-inode'
    os.link(database, alias)
    probe('read', state, 'path.hardLink')
    require(alias.read_bytes() == original, 'Shared inode was modified')
    alias.unlink()
    database.rename(root / 'saved.db')
    os.mkfifo(database, 0o600)
    probe('read', state, 'path.type')
    database.unlink()
    (root / 'saved.db').rename(database)
    require(database.read_bytes() == original, 'Metadata-denied probes changed the database')
    probe('read', state)
    print('PASS: shared inode/FIFO rejected; original journal reopens unchanged', flush=True)
