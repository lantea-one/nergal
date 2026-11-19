"""Exercise the real Keycloak distribution against the opt-in OIDC host in disposable namespaces."""
import hashlib
from html.parser import HTMLParser
import http.cookiejar
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from urllib.parse import urlencode, urljoin, urlsplit
from types import SimpleNamespace

VERSION = "26.8.2"
DIGEST = "dd124787283918bc597628887168333465ee2a811a389e0003569e52be7e487f"
module_path = Path(__file__).resolve().with_name("check.py")
spec = importlib.util.spec_from_file_location("oidc_fixture", module_path)
oidc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oidc)


class Forms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "form":
            self.current = (fields.get("action"), {})
            self.forms.append(self.current)
        elif tag == "input" and self.current and fields.get("name"):
            self.current[1][fields["name"]] = fields.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


def port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.2", 0))
        return reservation.getsockname()[1]


def check(archive, root):
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != DIGEST:
            raise ValueError("Unexpected upstream distribution digest")
    with tarfile.open(archive) as package:
        package.extractall(root, filter="data")
    installation = root / ("keycloak-" + VERSION)
    cert, key = root / "idp.crt", root / "idp.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "1", "-subj", "/CN=fixture-issuer",
                    "-addext", "subjectAltName=IP:127.0.0.2", "-keyout", key, "-out", cert], check=True, stderr=subprocess.DEVNULL)
    op = SimpleNamespace()
    server_port = port()
    origin = f"https://127.0.0.2:{server_port}"
    op.issuer, op.client, op.secret = origin + "/realms/fixture", "fixture-controller", secrets.token_urlsafe(32)
    settings = oidc.host_settings(op, cert)
    password = secrets.token_urlsafe(32)
    realm = {
        "realm": "fixture", "enabled": True, "groups": [{"name": "fixture-admins"}],
        "clients": [{"clientId": op.client, "enabled": True, "protocol": "openid-connect", "publicClient": False,
                     "secret": op.secret, "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
                     "redirectUris": [op.callback], "attributes": {"pkce.code.challenge.method": "S256"},
                     "protocolMappers": [{"name": "fixture-groups", "protocol": "openid-connect",
                                          "protocolMapper": "oidc-group-membership-mapper",
                                          "config": {"claim.name": "groups", "full.path": "false", "id.token.claim": "true"}}]}],
        "users": [{"username": name, "firstName": "Synthetic", "lastName": "Fixture", "email": name + "@example.invalid",
                   "emailVerified": True, "enabled": True, "groups": groups,
                   "credentials": [{"type": "password", "value": password, "temporary": False}]}
                  for name, groups in (("member", ["/fixture-admins"]), ("outsider", []))]}
    imports = installation / "data/import"
    imports.mkdir(parents=True, exist_ok=True)
    (imports / "fixture-realm.json").write_text(json.dumps(realm))
    env = {"PATH": os.environ["PATH"], "HOME": str(root), "LANG": "C.UTF-8",
           "JAVA_OPTS_APPEND": "-Duser.home=" + str(root)}
    if os.environ.get("JAVA_HOME"):
        env["JAVA_HOME"] = os.environ["JAVA_HOME"]
    context = ssl.create_default_context(cafile=str(cert))

    class LocalRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            assert origin == urlsplit(newurl).scheme + "://" + urlsplit(newurl).netloc
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    def client():
        return urllib.request.build_opener(urllib.request.ProxyHandler({}), LocalRedirect(),
                                           urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                           urllib.request.HTTPSHandler(context=context))

    args = [str(installation / "bin/kc.sh"), "start-dev", "--import-realm", "--http-enabled=false",
            "--http-host=127.0.0.2", "--https-port=" + str(server_port), "--hostname=" + origin,
            "--https-certificate-file=" + str(cert), "--https-certificate-key-file=" + str(key)]
    with tempfile.TemporaryFile() as log:
        server = subprocess.Popen(args, cwd=installation, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            deadline = time.monotonic() + 120
            while True:
                try:
                    with client().open(op.issuer + "/.well-known/openid-configuration", timeout=2) as response:
                        if json.load(response)["issuer"] == op.issuer:
                            break
                except (OSError, TimeoutError):
                    pass
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise AssertionError("Disposable Keycloak failed to become ready")
                time.sleep(0.2)
            profile = root / "controller"
            profile.mkdir(mode=0o700)
            tls = oidc.sessions.provision(profile)
            with oidc.sessions.host(profile, tls, settings) as host:
                for name, expected in (("outsider", 401), ("member", 302)):
                    rp = oidc.RelyingParty(host)
                    _, location = rp.request("/login/oidc", 302, {"__RequestVerificationToken": rp.token("/login")})
                    assert location.startswith(origin + "/")
                    browser = client()
                    with browser.open(location, timeout=10) as page:
                        forms = Forms()
                        forms.feed(page.read().decode())
                        action, fields = next(f for f in forms.forms if "password" in f[1])
                        action = urljoin(page.url, action)
                    assert action.startswith(origin + "/")
                    fields.update(username=name, password=password)
                    with browser.open(action, urlencode(fields).encode(), timeout=10) as page:
                        forms = Forms()
                        forms.feed(page.read().decode())
                        # Include the named submit control, as a user pressing
                        # Continue on the form-post fallback page would do.
                        callback, fields = next(f for f in forms.forms if "code" in f[1])
                    assert callback == op.callback
                    rp.request("/signin-oidc", expected, fields)
                    rp.request("/session", 200 if expected == 302 else 401)
            print("PASS: Keycloak " + VERSION + " signed group grants the member access and denies the outsider")
        finally:
            if server.poll() is None:
                os.killpg(server.pid, signal.SIGTERM)
            try:
                server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(server.pid, signal.SIGKILL)
                server.wait()


if __name__ == "__main__":
    if len(sys.argv) != 4 or os.readlink("/proc/self/ns/user") == sys.argv[2] or os.readlink("/proc/self/ns/net") == sys.argv[3]:
        raise SystemExit("Use a fresh user and network namespace")
    uid_map = [list(map(int, line.split())) for line in Path("/proc/self/uid_map").read_text().splitlines()]
    if os.getuid() != 0 or not any(start == 0 and outside != 0 and count == 1 for start, outside, count in uid_map):
        raise SystemExit("An unprivileged single-UID mapping is required")
    os.umask(0o077)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    with tempfile.TemporaryDirectory(prefix="nergal-keycloak-test-") as root:
        check(Path(sys.argv[1]), Path(root))
