"""Exercise installed controller OIDC using the synthetic issuer on the guest fixture ISO."""
import argparse
import contextlib
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import time


MEDIA = Path(__file__).resolve().parent
MATERIAL = Path("/etc/nergal/web/oidc-fixture")
ANCHOR = Path("/usr/local/share/ca-certificates/nergal-multihost-oidc-fixture.crt")
PASSWORD = Path("/run/nergal-ops/password")
WEB_CERT = Path("/etc/nergal/web/tls.crt")
ISSUER_ADDRESS = ("127.0.0.2", 9444)
ISSUER = "https://127.0.0.2:9444"
CALLBACK = "https://127.0.0.1:8443/signin-oidc"
CLIENT = "fixture-client"
CONNECTION = "/manage/identity/connection"


def require_guest():
    """Confine all credentials, trust changes and listeners to the fixture guest."""
    if not __debug__ or os.geteuid() != 0:
        raise SystemExit("Run as root inside the fixture guest with Python assertions enabled.")
    vm = subprocess.run(["systemd-detect-virt", "--vm"], capture_output=True, text=True)
    media_mount = subprocess.check_output(
        ["findmnt", "-n", "-o", "FSTYPE,OPTIONS", "--target", str(MEDIA)], text=True
    ).split()
    if (vm.stdout.strip() not in {"kvm", "qemu"} or len(media_mount) != 2
            or media_mount[0] != "iso9660" or "ro" not in media_mount[1].split(",")):
        raise SystemExit("Expected the disposable QEMU/KVM guest and its read-only fixture ISO.")
    if (socket.gethostname() != "nergal-installed-test" or not Path("/run/nergal-installed-fixture").is_file()
            or (MEDIA / "role").read_text().strip() != "controller"):
        raise SystemExit("Expected the installed controller fixture and its controller media.")


def load_helpers():
    spec = importlib.util.spec_from_file_location("fixture_oidc", MEDIA / "reuse/oidc/check.py")
    oidc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oidc)
    return oidc


def generate_material():
    """Publish the complete issuer identity together so a retry uses the same material."""
    with tempfile.TemporaryDirectory(prefix=".oidc-fixture-", dir=MATERIAL.parent) as directory:
        stage = Path(directory)
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "365",
            "-subj", "/CN=nergal-oidc-fixture.invalid", "-addext", "subjectAltName=IP:127.0.0.2",
            "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth",
            "-keyout", stage / "tls.key", "-out", stage / "issuer.crt",
        ], check=True, stderr=subprocess.DEVNULL)
        subprocess.run([
            "openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072",
            "-out", stage / "signing.key",
        ], check=True, stderr=subprocess.DEVNULL)
        (stage / "client-secret").write_text(secrets.token_urlsafe(32), encoding="ascii")
        stage.rename(MATERIAL)


def check_material():
    for name in (".", "issuer.crt", "tls.key", "signing.key", "client-secret"):
        path = MATERIAL / name
        info = path.lstat()
        expected_type = stat.S_ISDIR if path == MATERIAL else stat.S_ISREG
        if not expected_type(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise RuntimeError(f"Expected root-owned private issuer material at {path}")


def install_trust():
    # Debian's bundle and public anchor must remain readable by the installed Web service.
    certificate = (MATERIAL / "issuer.crt").read_bytes()
    if ANCHOR.is_symlink():
        raise RuntimeError("Unexpected symlink at fixture trust anchor")
    if ANCHOR.exists():
        if ANCHOR.read_bytes() != certificate:
            raise RuntimeError("Installed fixture trust anchor differs from the saved issuer certificate")
    else:
        with ANCHOR.open("xb") as anchor:
            anchor.write(certificate)
            os.fchmod(anchor.fileno(), 0o644)
    subprocess.run(["update-ca-certificates"], check=True, umask=0o022)


@contextlib.contextmanager
def provider(oidc, secret):
    key = MATERIAL / "signing.key"
    modulus = subprocess.check_output(["openssl", "rsa", "-in", key, "-noout", "-modulus"], text=True)
    with http.server.ThreadingHTTPServer(ISSUER_ADDRESS, oidc.Issuer) as server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(MATERIAL / "issuer.crt", MATERIAL / "tls.key")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.jwk = {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "fixture-key",
                      "e": "AQAB", "n": oidc.encode(bytes.fromhex(modulus.split("=")[1]))}
        server.issuer, server.callback, server.client, server.secret = ISSUER, CALLBACK, CLIENT, secret
        server.signing_key = key
        server.codes, server.overrides, server.repeated_claims = {}, {}, []
        server.token_requests = server.userinfo_requests = 0
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join()


def wait_for_web(tls):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        with contextlib.closing(http.client.HTTPSConnection("127.0.0.1", 8443, context=tls, timeout=3)) as web:
            try:
                web.request("GET", "/healthz")
                status = web.getresponse().status
            except (ConnectionRefusedError, ConnectionResetError, TimeoutError, http.client.RemoteDisconnected):
                pass
            else:
                if status == 200:
                    return
                if status != 503:
                    raise RuntimeError(f"Controller readiness returned HTTP {status}")
        time.sleep(0.5)
    raise RuntimeError("Controller HTTPS readiness timed out")


def local_login(oidc, browser):
    rp = oidc.RelyingParty(browser)
    password = PASSWORD.read_text().rstrip("\r\n")
    rp.request("/login", 302, {"username": "fixture-admin", "password": password,
                               "__RequestVerificationToken": rp.token("/login")})
    assert "fixture-admin" in rp.request("/session", 200)[0], "Expected the local fixture Administrator"
    return rp


def configure(oidc, browser, secret):
    admin = local_login(oidc, browser)
    page = admin.request(CONNECTION, 200)[0]
    if "No UI-managed connection has been saved" in page:
        anonymous = oidc.RelyingParty(browser)
        anonymous.request("/login/oidc", 404, {"__RequestVerificationToken": anonymous.token("/login")})
        fields = {
            "version": "0", "enabled": "true", "issuer": ISSUER, "clientId": CLIENT,
            "callbackUri": CALLBACK, "groupClaim": "groups", "administratorGroups": "fixture-admins",
            "auditorGroups": "fixture-auditors", "clientSecret": secret, "confirm": "replace-trust",
            "mfaAssuranceMode": "Deny", "mfaAssuranceClaim": "", "mfaAssuranceValue": "",
            "__RequestVerificationToken": admin.token(CONNECTION),
        }
        _, location = admin.request(CONNECTION + "/save", 302, fields)
        assert location == CONNECTION, "Unexpected connection save redirect"
    # A retry after a completed save must reuse the existing generation.
    admin.request("/logout", 302, {"__RequestVerificationToken": admin.token("/session")})


def verify(oidc, browser, secret):
    cert = MATERIAL / "issuer.crt"
    with provider(oidc, secret) as op:
        external = oidc.RelyingParty(browser)
        external.exchange(op, cert, 302, destination="/manage")
        actor = json.loads(external.request("/controller/audit", 200)[0])
        assert actor["actorId"] == f"oidc:{len(ISSUER)}:{ISSUER}:synthetic-external-subject", "Wrong external identity"
        assert actor["role"] == "nergal:administrator", "Wrong role from signed groups"
        replay = oidc.RelyingParty(browser)
        replay.cookies.update(external.cookies)
        external.request("/logout", 302, {"__RequestVerificationToken": external.token("/session")})
        replay.request("/controller/audit", 401)

        op.overrides = {"groups": ["Fixture-Admins"]}
        denied = oidc.RelyingParty(browser)
        denied.exchange(op, cert, 401)
        denied.request("/session", 401)
        denied.request("/controller/audit", 401)
        assert op.token_requests == 2 and not op.codes, "Expected two redeemed authorization codes"
        assert op.userinfo_requests == 0, "Unexpected UserInfo request"

    # A fresh local sign-in must work while the configured issuer is offline.
    local = local_login(oidc, browser)
    actor = json.loads(local.request("/controller/audit", 200)[0])
    assert actor["actorId"].startswith("local:") and actor["role"] == "nergal:administrator"
    page = local.request(CONNECTION, 200)[0]
    assert 'name="version" value="1"' in page and "A secret is stored." in page, "Expected the saved UI generation"
    assert ISSUER in page and CALLBACK in page and CLIENT in page and secret not in page
    local.request("/logout", 302, {"__RequestVerificationToken": local.token("/session")})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["configure", "trust", "verify"])
    phase = parser.parse_args().phase
    require_guest()
    os.umask(0o077)
    if phase == "configure" and not MATERIAL.exists():
        generate_material()
    check_material()
    if phase in {"configure", "trust"}:
        install_trust()
    if phase == "trust":
        print("Installed the restored guest fixture issuer trust anchor")
        return
    oidc = load_helpers()
    browser = oidc.sessions.Browser({"https": 8443}, ssl.create_default_context(cafile=WEB_CERT))
    wait_for_web(browser.tls)
    secret = (MATERIAL / "client-secret").read_text(encoding="ascii")
    if phase == "configure":
        configure(oidc, browser, secret)
    verify(oidc, browser, secret)
    print("PASS: installed UI-managed OIDC, signed group authorization and denial, offline-issuer local fallback")


if __name__ == "__main__":
    main()
