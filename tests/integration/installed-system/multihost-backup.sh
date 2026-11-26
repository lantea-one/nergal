#!/bin/bash

# Sourced after the multihost guest guard. The caller serializes these operations
# and waits for any independently launched agent CLI/watchdog before taking a backup.
# The caller supplies role, media, and backup_disk.
# shellcheck disable=SC2154

_backup_fail() {
    printf 'Installed fixture state: %s\n' "$1" >&2
    return 1
}

_backup_account() {
    case "$role" in
        controller) printf '%s\n' nergal-web ;;
        agent) printf '%s\n' nergal-agent ;;
        *) _backup_fail 'unknown role' ;;
    esac
}

_backup_stop() {
    local account=$1 unit
    local -a units=("$account.service")
    if [[ $account == nergal-agent ]]; then
        units+=(nergal-agent-enroll.service)
        if [[ $(systemctl show --property=LoadState --value nergal-agent-reconcile.service) != not-found ]]; then
            units+=(nergal-agent-reconcile.service)
        fi
    fi
    systemctl stop "${units[@]}" || return 1
    for unit in "${units[@]}"; do
        [[ $(systemctl show --property=ActiveState --value "$unit") == inactive ]] ||
            { _backup_fail 'role unit did not stop'; return 1; }
    done
}

_backup_package_version() {
    local package=$1
    [[ $(dpkg-deb --field "$package" Package) == nergal &&
       $(dpkg-deb --field "$package" Architecture) == amd64 ]] ||
        { _backup_fail 'expected a native Nergal amd64 package'; return 1; }
    dpkg-deb --field "$package" Version
}

_backup_require_installed() {
    local version=$1
    [[ $(dpkg-query -W -f='${Status} ${Version}' nergal) == "install ok installed $version" ]] ||
        _backup_fail 'installed package is not the expected version'
}

_backup_device() {
    local device
    [[ $backup_disk == /dev/disk/by-id/virtio-NERGAL_BACKUP && -L $backup_disk ]] ||
        { _backup_fail 'dedicated virtio backup marker is missing'; return 1; }
    device=$(readlink -e -- "$backup_disk") || return 1
    [[ $device =~ ^/dev/vd[a-z]+$ && -b $device &&
       $(lsblk --noheadings --raw --output TYPE -- "$device") == disk &&
       -z $(lsblk --noheadings --raw --output MOUNTPOINTS -- "$device") &&
       $(udevadm info --query=property --property=ID_SERIAL --value --name="$device") == NERGAL_BACKUP ]] ||
        { _backup_fail 'backup marker does not identify an unused whole virtio disk'; return 1; }
    printf '%s\n' "$device"
}

_backup_transfer() {
    local action=$1 account version device uid gid
    account=$(_backup_account) || return 1
    version=$(_backup_package_version "$media/nergal-upgrade.deb") || return 1
    _backup_require_installed "$version" || return 1
    device=$(_backup_device) || return 1
    uid=$(id -u "$account") && gid=$(id -g "$account") || return 1
    [[ $uid != 0 && $gid != 0 ]] || { _backup_fail 'role must be non-root'; return 1; }
    _backup_stop "$account" || return 1

    # The fixture consumes a private blank raw disk for each role. No filesystem
    # is mounted or created. A header is published only after the payload is synced.
    python3 -B - "$action" "$device" "$role" "$version" "$uid" "$gid" "${account#nergal-}" <<'PY'
import contextlib
import hashlib
import io
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import tarfile
import tempfile

action, device, role, version, uid, gid, component = sys.argv[1:]
uid, gid = int(uid), int(gid)
roots = {"state": Path("/var/lib/nergal") / component, "config": Path("/etc/nergal") / component}
root_metadata = {"state": (uid, gid, 0o700), "config": (0, gid, 0o750)}
# Current same-schema package pair. These IDs and versions come from
# AccountConnectionPolicy/AccountSchema, ControllerStateStore and ApplyJournal.
databases = {
    "state/accounts/accounts.db": (0x4E524741, 8),
    "state/controller/controller.db": (0x4E524743, 6),
} if role == "controller" else {"state/journal.db": (0x4E52474C, 3)}
header_size = 512
max_payload = 64 * 1024 * 1024


def require(valid, diagnostic):
    if not valid:
        raise ValueError(diagnostic)


def validate_member(member):
    parts = member.name.split("/")
    root = parts[0]
    require(root in roots and all(part not in ("", ".", "..") for part in parts),
            "unexpected archive path")
    require(member.type in (tarfile.DIRTYPE, tarfile.REGTYPE) and member.sparse is None,
            "archive contains a link, sparse file or special file")
    if len(parts) == 1:
        metadata = (member.uid, member.gid, stat.S_IMODE(member.mode))
        require(member.isdir() and metadata == root_metadata[root],
                "unexpected archive root owner or mode")
    else:
        owners = {uid} if root == "state" else {0, uid}
        groups = {gid} if root == "state" else {0, gid}
        require(member.uid in owners and member.gid in groups and not member.mode & 0o7022,
                "unexpected archive member owner or mode")
    return member


def validate_archive(archive):
    members = {}
    for member in archive:
        validate_member(member)
        require(member.name not in members, "duplicate archive path")
        members[member.name] = member
    for name in roots:
        require(name in members, "archive is missing a role directory")
    for name in databases:
        require(name in members and members[name].isreg(), "archive is missing a role database")
    for name in members:
        parent, separator, _ = name.rpartition("/")
        require(not separator or (parent in members and members[parent].isdir()),
                "archive parent directory is missing")
    return members


def validate_databases(archive, members):
    for name, (application_id, schema_version) in databases.items():
        # SQLite may need a writable SHM for a read-only WAL connection. Use a
        # private scratch copy so the archived bytes and restored files stay exact.
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / Path(name).name
            for suffix in ("", "-wal", "-shm", "-journal"):
                member = members.get(name + suffix)
                if member is None:
                    continue
                require(member.isreg(), "SQLite database or sidecar has an invalid file type")
                destination = database.with_name(database.name + suffix)
                with archive.extractfile(member) as source, destination.open("xb") as output:
                    shutil.copyfileobj(source, output)

            try:
                with contextlib.closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as db:
                    require(db.execute("PRAGMA application_id").fetchone() == (application_id,) and
                            db.execute("PRAGMA user_version").fetchone() == (schema_version,),
                            f"{database.name}: unexpected application ID or schema version")
                    require(db.execute("PRAGMA quick_check").fetchall() == [("ok",)] and
                            db.execute("PRAGMA foreign_key_check").fetchone() is None,
                            f"{database.name}: SQLite integrity check failed")
            except sqlite3.Error:
                raise ValueError(f"{database.name}: SQLite integrity check failed") from None


def make_archive(output):
    def add_path(archive, path, name):
        metadata = path.lstat()
        directory = stat.S_ISDIR(metadata.st_mode)
        require(directory or (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1),
                "role tree contains a link or special file")
        require(output.tell() + (0 if directory else metadata.st_size) <= max_payload,
                "backup archive exceeds fixture size limit")
        archive.add(path, arcname=name, recursive=False, filter=validate_member)
        if directory:
            for child in sorted(path.iterdir()):
                add_path(archive, child, f"{name}/{child.name}")

    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, path in roots.items():
            require(path.resolve(strict=True) == path, "role path contains a symlink")
            add_path(archive, path, name)
    output.seek(0)
    with tarfile.open(fileobj=output, mode="r:") as archive:
        validate_databases(archive, validate_archive(archive))
    output.seek(0)


def restore_archive(payload):
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:", errorlevel=2) as archive:
        members = validate_archive(archive)
        validate_databases(archive, members)
        for name, path in roots.items():
            require(path.resolve(strict=True) == path, "restore destination contains a symlink")
            metadata = path.stat()
            require(path.is_dir() and
                    (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) == root_metadata[name]
                    and not any(path.iterdir()), "restore requires fresh package directories")

        # Extract on each destination filesystem, then publish the two complete
        # trees. Keep both empty package directories available for error rollback.
        with contextlib.ExitStack() as stack:
            staged = {}
            for name, path in roots.items():
                stage = Path(stack.enter_context(tempfile.TemporaryDirectory(
                    prefix=".nergal-restore-", dir=path.parent)))
                archive.extractall(stage, members=(member for member in members.values()
                                                   if member.name.partition("/")[0] == name),
                                   numeric_owner=True, filter="fully_trusted")
                staged[name] = stage

            moved = []
            published = []
            try:
                for name, path in roots.items():
                    path.rename(staged[name] / "original")
                    moved.append(name)
                    (staged[name] / name).rename(path)
                    published.append(name)
            except OSError:
                for name in reversed(published):
                    roots[name].rename(staged[name] / name)
                for name in reversed(moved):
                    (staged[name] / "original").rename(roots[name])
                raise


def header_for(payload):
    digest = hashlib.sha256(payload).hexdigest()
    text = f"NERGAL-FIXTURE-BACKUP-1\n{role}\n{version}\n{uid}:{gid}\n{len(payload)}\n{digest}\n"
    header = text.encode("ascii")
    require(len(header) <= header_size, "backup header exceeds fixture limit")
    return header.ljust(header_size, b"\0")


try:
    # Linux enforces O_EXCL against mounted filesystems and other block holders.
    access = os.O_RDWR if action == "backup" else os.O_RDONLY
    with os.fdopen(os.open(device, access | os.O_EXCL | os.O_NOFOLLOW),
                   "r+b" if action == "backup" else "rb") as disk:
        require(stat.S_ISBLK(os.fstat(disk.fileno()).st_mode), "backup path is not a block device")
        capacity = os.lseek(disk.fileno(), 0, os.SEEK_END)
        disk.seek(0)
        header = disk.read(header_size)
        if action == "backup":
            require(header == bytes(header_size), "backup disk has a nonblank header")
            with tempfile.TemporaryFile() as output:
                make_archive(output)
                payload = output.read(max_payload + 1)
            require(0 < len(payload) <= min(max_payload, capacity - header_size),
                    "backup archive exceeds fixture disk or size limit")
            disk.write(payload)
            disk.flush()
            os.fsync(disk.fileno())
            disk.seek(0)
            disk.write(header_for(payload))
            disk.flush()
            os.fsync(disk.fileno())
        else:
            fields = header.rstrip(b"\0").splitlines()
            require(len(fields) == 6 and fields[4].isdigit(), "invalid backup header")
            length = int(fields[4])
            require(0 < length <= min(max_payload, capacity - header_size), "invalid backup archive size")
            payload = disk.read(length)
            require(len(payload) == length and header == header_for(payload),
                    "backup role, version, service IDs or digest differ")
            restore_archive(payload)
except ValueError as error:
    sys.exit(f"Installed fixture state: {error}")
except tarfile.TarError:
    sys.exit("Installed fixture state: invalid backup archive")
except OSError as error:
    sys.exit(f"Installed fixture state: filesystem or disk operation failed (errno={error.errno})")
PY
}

backup_state() {
    _backup_transfer backup
}

# Restores only the saved files. The caller handles agent boot reconciliation
# and service activation after validating the restored private state.
restore_state() {
    _backup_transfer restore
}

upgrade_package() {
    local account baseline upgrade unit
    account=$(_backup_account) || return 1
    baseline=$(_backup_package_version "$media/nergal.deb") || return 1
    upgrade=$(_backup_package_version "$media/nergal-upgrade.deb") || return 1
    _backup_require_installed "$baseline" || return 1
    dpkg --compare-versions "$upgrade" gt "$baseline" ||
        { _backup_fail 'upgrade package must have a newer version'; return 1; }
    _backup_stop "$account" || return 1
    dpkg -i "$media/nergal-upgrade.deb" || return 1
    _backup_require_installed "$upgrade" || return 1
    for unit in nergal-web.service nergal-agent.service; do
        [[ $(systemctl show --property=ActiveState --value "$unit") == inactive ]] ||
            { _backup_fail 'upgrade left a role unit running'; return 1; }
    done
}
