# Controller SQLite backup and restore

Controller schema 5 initializes a fresh database. Each System settings save
appends an immutable version and its audit event in one transaction. The first
record contains the defaults. A submitted form must carry the exact token of the
version it opened. A stale save returns HTTP 409 and displays the current saved
values. Independently changed histories can have the same version number, so
the token is bound to the committed record rather than derived from its number.

## Make a backup

Run the SQLite backup command as the controller database owner. Use a new
directory with permissions 0700 and a destination that does not exist yet.
Replace the two example paths with absolute paths to the controller database
and the backup destination.

```sh
umask 077
sqlite3 -bail -readonly /path/to/controller/controller.db \
  ".backup '/path/to/new-backup-directory/controller.db'"
```

The SQLite backup API produces a consistent database snapshot that includes
committed data in the write-ahead log. The primary database file by itself may
omit recent commits. After the command succeeds and closes the destination,
keep the backup private with file permissions 0600.
See the [SQLite backup documentation](https://www.sqlite.org/backup.html).

## Verify a restore

1. Copy the backup into a separate owner-only directory as `controller.db`.
   Give the file permissions 0600. The directory should contain no other
   controller database or SQLite sidecar files.
2. Check the copy with `sqlite3 -readonly /path/to/restore/controller.db 'PRAGMA quick_check; PRAGMA foreign_key_check;'`.
   Expect `ok` and no foreign-key violations.
3. Start an isolated controller using the restored directory and independently
   configured identity credentials. Leave agent dispatch unavailable in this
   check. Verify the saved settings, revisions, reusable objects, sources and
   controller audit as appropriate to the backup contents.
4. Open System settings, make a test edit on the isolated restore, and verify
   that it creates the next settings version and one audit event. Discard the
   test restore when finished.

This procedure verifies the controller database. Account stores, wrapping keys
and protected agent receipts have independent recovery requirements. Replacing
a running controller's database is a separate operational action. Plan to
reconcile hosted agent state and pending operations before authorizing dispatch
from a restored controller.

The synthetic HTTPS test in [the test guide](testing-and-conformance.md#system-settings-and-controller-backup)
exercises the procedure on the current schema.
