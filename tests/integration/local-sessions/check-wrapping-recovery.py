"""Check credential rotation and offline session recovery over loopback HTTPS."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from check import host, provision


def generate_replacement(directory):
    key = directory / "replacement.key"
    certificate = directory / "replacement.crt"
    bundle = directory / "replacement.pfx"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "1",
        "-subj", "/CN=synthetic-replacement", "-keyout", key, "-out", certificate,
    ], check=True, stderr=subprocess.DEVNULL)
    subprocess.run([
        "openssl", "pkcs12", "-export", "-inkey", key, "-in", certificate,
        "-out", bundle, "-passout", "pass:",
    ], check=True)
    key.unlink()
    return bundle


def check_rotation(root):
    original = root / "original"
    original.mkdir(mode=0o700)
    tls = provision(original)
    with host(original, tls) as browser:
        browser.login()
        browser.request("/session", 200)
        cookies = browser.cookies.copy()

    def key_contents(directory):
        return {entry.name: entry.read_bytes() for entry in (directory / "keys").iterdir()}

    original_keys = key_contents(original)
    assert original_keys, "the initial session must persist an encrypted key"
    replacement = generate_replacement(original)
    rotated = {"LocalSessions__CertificateFile": str(replacement)}
    try:
        with host(original, tls, rotated):
            raise AssertionError("The host listened without the historical credential")
    except AssertionError as error:
        if str(error) != "Session host refused startup":
            raise

    rotated["LocalSessions__RetainedCertificateFiles__0"] = str(original / "wrapping.pfx")
    with host(original, tls, rotated) as browser:
        browser.cookies.update(cookies)
        browser.request("/session", 200)
    assert key_contents(original) == original_keys

    # Copy while the service is stopped, and restart using only the recovered paths.
    recovered = root / "recovered"
    recovered.mkdir(mode=0o700)
    for name in ("accounts", "keys"):
        shutil.copytree(original / name, recovered / name)
    for name in ("tls.crt", "tls.key", "wrapping.pfx", "replacement.pfx"):
        shutil.copy2(original / name, recovered / name)
    shutil.rmtree(original)
    with host(recovered, tls, {
        "LocalSessions__CertificateFile": str(recovered / "replacement.pfx"),
        "LocalSessions__RetainedCertificateFiles__0": str(recovered / "wrapping.pfx"),
    }) as browser:
        browser.cookies.update(cookies)
        browser.request("/session", 200)
    assert key_contents(recovered) == original_keys


if __name__ == "__main__":
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="nergal-wrapping-recovery-") as directory:
        check_rotation(Path(directory))
    print("PASS: wrapping credential rotation, missing-history refusal, and offline account/key-ring recovery")
