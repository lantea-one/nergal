"""Exercise the real Kestrel session boundary using disposable application accounts and keys."""
import contextlib
import http.client
from html.parser import HTMLParser
import os
from pathlib import Path
import re
import sqlite3
import ssl
import subprocess
import tempfile
import time
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[3]
WEB = ROOT / "src/Nergal.Web"
DLL = WEB / "bin/Release/net10.0/Nergal.Web.dll"
PROBE = ROOT / "tests/integration/isolation/bin/Release/net10.0/Nergal.Isolation.Fixture.dll"
ADMIN = "__Host-nergal-admin"
CSRF = "__Host-nergal-csrf"
PASSWORD = "synthetic account fixture password 0001"


class Token(HTMLParser):
    value = None

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "input" and fields.get("name") == "__RequestVerificationToken":
            self.value = fields["value"]


class Browser:
    def __init__(self, ports, tls):
        self.ports = ports
        self.tls = tls
        self.cookies = {}

    def request(self, path, expected, fields=None, plain=False, headers=None):
        connection = (http.client.HTTPConnection("127.0.0.1", self.ports["http"], timeout=10)
                      if plain else http.client.HTTPSConnection("127.0.0.1", self.ports["https"],
                                                                context=self.tls, timeout=10))
        values = dict(headers or {})
        if not plain:
            values["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if fields is not None:
            values["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            connection.request("GET" if fields is None else "POST", path,
                               None if fields is None else urlencode(fields), values)
            response = connection.getresponse()
            body = response.read().decode()
            assert response.status == expected, f"{path}: expected {expected}, received {response.status}"
            for name, value in response.getheaders():
                if name.lower() == "set-cookie":
                    pair, *attributes = value.split("; ")
                    key, cookie = pair.split("=", 1)
                    assert key in (ADMIN, CSRF)
                    attrs = {item.lower() for item in attributes}
                    assert {"path=/", "secure", "httponly", "samesite=strict"} <= attrs
                    assert not any(a.startswith("domain=") for a in attrs)
                    if key == ADMIN and cookie:
                        assert not any(a.startswith(("max-age=", "expires=")) for a in attrs)
                    self.cookies[key] = cookie
            if expected == 302:
                assert response.getheader("Location") in ("/login", "/session")
            assert PASSWORD not in body
            return body
        finally:
            connection.close()

    def token(self, path):
        parser = Token()
        parser.feed(self.request(path, 200))
        assert parser.value
        return parser.value

    def login(self, password=PASSWORD, expected=302):
        self.request("/login", expected, {"username": "fixture-admin", "password": password,
                                         "__RequestVerificationToken": self.token("/login")})


@contextlib.contextmanager
def host(temp, tls, settings=None, *, executable="dotnet", dll=DLL, drop=None):
    env = {k: v for k, v in os.environ.items()
           if not k.lower().startswith(("aspnetcore_", "kestrel__", "localsessions__", "agentstatus__", "logging__"))}
    env.update({
        "HOME": str(temp / "profile"),
        "XDG_DATA_HOME": str(temp / "profile"),
        "ASPNETCORE_URLS": "http://127.0.0.1:0;https://127.0.0.1:0",
        "Kestrel__Certificates__Default__Path": str(temp / "tls.crt"),
        "Kestrel__Certificates__Default__KeyPath": str(temp / "tls.key"),
        "LocalSessions__Enabled": "true", "LocalSessions__AccountDirectory": str(temp / "accounts"),
        "LocalSessions__KeyDirectory": str(temp / "keys"), "LocalSessions__CertificateFile": str(temp / "wrapping.pfx"),
        "Logging__LogLevel__Microsoft.Hosting.Lifetime": "Information",
    })
    env.update(settings or {})
    with tempfile.TemporaryFile(mode="w+b") as log:
        process = subprocess.Popen([executable, str(dll)], cwd=dll.parent, env=env, preexec_fn=drop, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                text = os.pread(log.fileno(), 100_000, 0).decode(errors="replace")
                ports = dict(re.findall(r"Now listening on: (https?)://127\.0\.0\.1:(\d+)", text))
                if len(ports) == 2:
                    yield Browser({k: int(v) for k, v in ports.items()}, tls)
                    break
                if process.poll() is not None:
                    raise AssertionError("Session host refused startup")
                time.sleep(0.05)
            else:
                raise AssertionError("Session host readiness timed out")
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
            assert PASSWORD.encode() not in os.pread(log.fileno(), 1_000_000, 0)


def provision(temp):
    for directory in ("accounts", "keys", "profile"):
        (temp / directory).mkdir(mode=0o700)
    subprocess.run(["dotnet", PROBE, "account-initialize", temp / "accounts"], check=True)
    # Independent TLS and wrapping credentials. No machine certificate store.
    for name in ("tls", "wrapping"):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "1",
                        "-subj", "/CN=synthetic-fixture", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-keyout", temp / f"{name}.key", "-out", temp / f"{name}.crt"],
                       check=True, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "pkcs12", "-export", "-inkey", temp / "wrapping.key",
                    "-in", temp / "wrapping.crt", "-out", temp / "wrapping.pfx", "-passout", "pass:"], check=True)
    return ssl.create_default_context(cafile=str(temp / "tls.crt"))


def exercise(temp):
    tls = provision(temp)
    with host(temp, tls) as browser:
        assert 'href="/login"' in browser.request("/", 200)
        browser.request("/login", 400, plain=True, headers={"X-Forwarded-Proto": "https"})
        browser.request("/session", 401)
        browser.request("/login?returnUrl=https%3A%2F%2Fexample.invalid", 200)
        fields = {"username": "fixture-admin", "password": PASSWORD, "__RequestVerificationToken": browser.token("/login")}
        browser.request("/login", 400, [*fields.items(), ("username", "fixture-admin")])
        browser.request("/login", 413, {**fields, "password": "x" * 9000})
        browser.request("/login", 400, {"username": "fixture-admin", "password": PASSWORD})
        browser.request("/login?returnUrl=https%3A%2F%2Fexample.invalid", 302, fields)
        session = browser.cookies[ADMIN]
        browser.request("/logout", 400, {})
        assert 'href="/agent/status"' not in browser.request("/session", 200)
        browser.request("/agent/status", 404)
        browser.cookies[ADMIN] = "invalid-ticket"
        browser.request("/session", 401)
    with host(temp, tls) as browser:
        browser.cookies[ADMIN] = session
        browser.request("/session", 200)
        browser.request("/logout", 302, {"__RequestVerificationToken": browser.token("/session")})
        browser.cookies[ADMIN] = session
        browser.request("/session", 401)
        for _ in range(5):
            browser.login("synthetic incorrect fixture password", 401)
        browser.login(expected=401)
        with sqlite3.connect(temp / "accounts/accounts.db") as db:
            assert db.execute("SELECT LockoutEnd IS NOT NULL FROM AspNetUsers").fetchone() == (1,)
        for _ in range(4):
            browser.login(expected=401)
        browser.login(expected=429)
    assert not list((temp / "profile").rglob("key-*.xml")), "Unexpected profile key persistence"
    print("PASS: HTTPS, cookie attributes, CSRF, durable sessions, revocation, lockout and request rate limits")


if __name__ == "__main__":
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="nergal-sessions-") as directory:
        exercise(Path(directory))
