"""Offline account CLI conformance, including kernel terminal echo and restoration."""
import os
from pathlib import Path
import pty
import select
import signal
import sqlite3
import subprocess
import tempfile
import termios
import time

ROOT = Path(__file__).resolve().parents[3]
CLI = ["dotnet", str(ROOT / "src/Nergal.Admin/bin/Release/net10.0/nergal-admin.dll")]
SECRET = b"synthetic terminal credential 001"


def invoke(args, expected, data=b""):
    result = subprocess.run(CLI + args, input=data, capture_output=True, timeout=10)
    assert result.returncode == expected
    assert SECRET not in result.stdout + result.stderr
    return result.stderr


def interactive(directory, *, mismatch=False, interrupt=False):
    master, slave = pty.openpty()
    try:
        original = termios.tcgetattr(slave)
        with subprocess.Popen(CLI + ["account", "provision", str(directory), "fixture-admin"],
                              stdin=slave, stdout=slave, stderr=slave) as child:
            transcript = bytearray()
            try:
                def prompt(text):
                    deadline = time.monotonic() + 10
                    while text not in transcript:
                        remaining = deadline - time.monotonic()
                        assert remaining > 0 and select.select([master], [], [], remaining)[0], "Missing terminal prompt"
                        transcript.extend(os.read(master, 4096))
                    assert not termios.tcgetattr(slave)[3] & termios.ECHO, "Password prompt appeared with echo enabled"

                prompt(b"New password: ")
                if interrupt:
                    child.send_signal(signal.SIGTERM)
                else:
                    os.write(master, SECRET + b"\r")
                    prompt(b"Confirm password: ")
                    os.write(master, (b"other synthetic terminal credential" if mismatch else SECRET) + b"\r")
                child.wait(timeout=10)
                while select.select([master], [], [], 0)[0]:
                    transcript.extend(os.read(master, 4096))
                assert SECRET not in transcript and b"other synthetic terminal credential" not in transcript
                assert (child.returncode == 0) == (not mismatch and not interrupt)
                assert termios.tcgetattr(slave) == original, "Terminal mode was not fully restored"
            finally:
                if child.poll() is None:
                    child.kill()
    finally:
        os.close(master)
        os.close(slave)


def exercise(directory):
    args = ["account", "provision", str(directory), "fixture-admin"]
    assert b"account.databaseMissing" in invoke(args + ["--password-stdin"], 1, SECRET)
    assert not list(directory.iterdir())
    invoke(["account", "init", str(directory)], 0)
    assert b"account.exists" in invoke(["account", "init", str(directory)], 1)
    assert b"password.inputMode" in invoke(args, 2, SECRET)
    assert b"password.invalidInput" in invoke(args + ["--password-stdin"], 1, SECRET + b"\nsecond\n")
    assert b"password.bounds" in invoke(args + ["--password-stdin"], 1, b"short\n")
    interactive(directory, mismatch=True)
    interactive(directory, interrupt=True)
    with sqlite3.connect(directory / "accounts.db") as db:
        assert db.execute("SELECT COUNT(*) FROM AspNetUsers").fetchone() == (0,)
    interactive(directory)
    assert b"account.exists" in invoke(args + ["--password-stdin"], 1, SECRET)
    assert SECRET not in (directory / "accounts.db").read_bytes()
    print("PASS: explicit one-time initialization, denied provisioning, exact pipe framing, no terminal echo and mode restoration")


def controller_upgrade(directory):
    """Only an explicit offline invocation upgrades legacy state; unknown versions remain untouched."""
    directory.mkdir(mode=0o700)
    invoke(["controller", "init", str(directory)], 0)
    with sqlite3.connect(directory / "controller.db") as db:
        db.execute("DROP TABLE native_sources")
        db.execute("PRAGMA user_version=1")
    invoke(["controller", "upgrade", str(directory)], 0)
    invoke(["controller", "upgrade", str(directory)], 0)
    with sqlite3.connect(directory / "controller.db") as db:
        assert db.execute("PRAGMA user_version").fetchone() == (2,)
        assert db.execute("SELECT count(*) FROM native_sources").fetchone() == (0,)
        db.execute("PRAGMA user_version=99")
    assert b"controller.upgradeUnsupported" in invoke(["controller", "upgrade", str(directory)], 1)
    with sqlite3.connect(directory / "controller.db") as db:
        assert db.execute("PRAGMA user_version").fetchone() == (99,)
    print("PASS: explicit idempotent controller schema upgrade and unknown-version denial")


if __name__ == "__main__":
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="nergal-provision-") as root:
        exercise(Path(root))
        controller_upgrade(Path(root) / "controller")
