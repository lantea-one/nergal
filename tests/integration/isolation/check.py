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
    browser_directory = root / 'browser'
    browser_directory.mkdir(mode=0o700)
    os.chown(browser_directory, 1, 1)
    browser_code = Path(__file__).with_name('browser.py').read_text()

    def check_store(name, database_name, initialize, read):
        state = root / name
        state.mkdir(mode=0o700)
        probe(initialize, state)
        database = state / database_name
        original = database.read_bytes()
        pid = os.fork()
        if pid == 0:
            try:
                try:
                    os.setgroups([])
                except PermissionError:
                    pass  # Some rootless mappings prohibit setgroups; owner-only modes grant no group access.
                os.setgid(1)
                os.setuid(1)
                # exec discards all private artifact/credential objects inherited by fork.
                os.execv(sys.executable, [sys.executable, '-c', browser_code, str(root), name, database_name])
            except BaseException:
                os._exit(1)
        _, status = os.waitpid(pid, 0)
        require(os.waitstatus_to_exitcode(status) == 0, 'Browser UID isolation failed')
        require(database.read_bytes() == original, 'Browser changed protected bytes')
        probe(read, state)
        print(f'PASS: unprivileged browser UID cannot read/write/unlink/replace {name} state', flush=True)

        # Namespace root could override DAC: the managed store must explicitly reject a mismatched owner.
        for node in (database, state):
            os.chown(node, 1, 1)
            probe(read, state, 'path.owner')
            os.chown(node, 0, 0)
        for suffix in ('-journal', '-wal', '-shm'):
            sidecar = state / (database_name + suffix)
            sidecar.write_bytes(b'foreign sentinel')
            os.chmod(sidecar, 0o600)
            os.chown(sidecar, 1, 1)
            probe(read, state, 'path.owner')
            require(sidecar.read_bytes() == b'foreign sentinel', 'Foreign sidecar was modified')
            sidecar.unlink()
        print(f'PASS: foreign {name} directory/database/sidecar owners rejected before SQLite open', flush=True)

        alias = root / (name + '-shared-inode')
        os.link(database, alias)
        probe(read, state, 'path.hardLink')
        require(alias.read_bytes() == original, 'Shared inode was modified')
        alias.unlink()
        saved = root / (name + '-saved.db')
        database.rename(saved)
        os.mkfifo(database, 0o600)
        probe(read, state, 'path.type')
        database.unlink()
        saved.rename(database)
        require(database.read_bytes() == original, 'Metadata-denied probes changed protected bytes')
        probe(read, state)
        print(f'PASS: shared inode/FIFO rejected; original {name} store reopens unchanged', flush=True)

    check_store('agent', 'journal.db', 'initialize', 'read')
    check_store('identity', 'accounts.db', 'account-initialize', 'account-read')
