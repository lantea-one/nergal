"""Executed after the role UID/GID drop; contains no private parent-process memory."""
import os
from pathlib import Path
import sys

root = Path(sys.argv[1])
state = root / sys.argv[2]
database = state / sys.argv[3]
replacement = root / 'browser' / 'replacement'
assert os.geteuid() == 1, 'Browser UID drop failed'
cap = next(line for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:'))
assert int(cap.split()[1], 16) == 0, 'Browser retained effective capabilities'
# Establish that this role can write its own state; agent denial is an account boundary.
replacement.write_bytes(b'not permitted in agent state')
assert replacement.read_bytes() == b'not permitted in agent state'
operations = [
    lambda: database.read_bytes(),
    lambda: database.write_bytes(b'not permitted'),
    lambda: (state / 'new-state').write_text('not permitted'),
    lambda: database.unlink(),
    lambda: state.rename(root / 'replaced'),
    lambda: os.replace(replacement, database),
]
for operation in operations:
    try:
        operation()
    except PermissionError:
        continue
    raise AssertionError('Browser filesystem operation unexpectedly succeeded')
