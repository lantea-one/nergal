"""Exercise the real Kestrel session boundary using disposable application accounts and keys."""
import contextlib
import http.client
import hashlib
from html.parser import HTMLParser
import json
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
ADMIN_TOOL = ROOT / "src/Nergal.Admin/bin/Release/net10.0/nergal-admin.dll"
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
           if not k.lower().startswith(("aspnetcore_", "kestrel__", "localsessions__", "agentstatus__", "controllerstate__", "oidc__", "logging__"))}
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
            content = os.pread(log.fileno(), 1_000_000, 0)
            assert PASSWORD.encode() not in content
            if "Oidc__ClientSecret" in env:
                assert env["Oidc__ClientSecret"].encode() not in content


def provision(temp):
    for directory in ("accounts", "keys", "profile"):
        (temp / directory).mkdir(mode=0o700)
    subprocess.run(["dotnet", ADMIN_TOOL, "account", "init", temp / "accounts"], check=True)
    subprocess.run(["dotnet", ADMIN_TOOL, "account", "provision", temp / "accounts", "fixture-admin", "--password-stdin"],
                   input=PASSWORD.encode() + b"\n", check=True)
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
    ctrl_state = temp / "controller-state"
    ctrl_state.mkdir(mode=0o700)
    subprocess.run(["dotnet", ADMIN_TOOL, "controller", "init", ctrl_state], check=True)
    sources = temp / "sources"
    sources.mkdir(mode=0o700)
    source = 'include "/unresolved-synthetic.conf"\ntable inet synthetic { chain forward { counter accept } }\n'
    source_path = sources / "synthetic.conf"
    source_path.write_text(source)
    source_digest = hashlib.sha256(source.encode()).hexdigest()
    report_path = "/manage/sources/review?digest=" + source_digest
    with host(temp, tls, {"ControllerState__Enabled": "true", "ControllerState__Directory": str(ctrl_state),
                          "NativeSources__Directory": str(sources)}) as browser:
        browser.request("/manage/sources", 401)
        browser.request(report_path, 401)
        assert 'href="/login"' in browser.request("/", 200)
        browser.request("/login", 400, plain=True, headers={"X-Forwarded-Proto": "https"})
        browser.request("/session", 401)
        browser.request("/login?returnUrl=https%3A%2F%2Fexample.invalid", 200)
        fields = {"username": "fixture-admin", "password": PASSWORD, "__RequestVerificationToken": browser.token("/login")}
        browser.request("/login", 400, [*fields.items(), ("username", "fixture-admin")])
        browser.request("/login", 413, {**fields, "password": "x" * 9000})
        browser.request("/login", 400, {"username": "fixture-admin", "password": PASSWORD})
        browser.request("/login?returnUrl=https%3A%2F%2Fexample.invalid", 302, fields)
        source_html = browser.request("/manage/sources", 200)
        assert 'href="' + report_path + '"' in source_html, "Report must be a real routed download link"
        assert "Conversion blocked" in source_html
        source_path.write_text("changed after startup")
        report = json.loads(browser.request(report_path, 200))
        assert report["sourceSha256"] == source_digest and report["schemaVersion"] == 1
        assert report["review"]["canConvert"] is False and report["review"]["tableDeclarations"] == 1
        assert {"gap.counters", "source.includes"} <= {s["code"] for s in report["review"]["signals"]}
        assert "text" not in report and "candidate" not in report
        browser.request("/manage/sources/review?digest=..%2F..%2Fetc%2Fpasswd", 404)
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

    auditor_accounts = temp / "auditor-accounts"
    auditor_accounts.mkdir(mode=0o700)
    subprocess.run(["dotnet", ADMIN_TOOL, "account", "init", auditor_accounts], check=True)
    subprocess.run(["dotnet", ADMIN_TOOL, "account", "provision", auditor_accounts, "fixture-auditor", "--role", "auditor", "--password-stdin"],
                   input=PASSWORD.encode() + b"\n", check=True)
    auditor_settings = {
        "NativeSources__Directory": str(sources),
        "LocalSessions__AccountDirectory": str(auditor_accounts),
        "ControllerState__Enabled": "true",
        "ControllerState__Directory": str(ctrl_state),
    }
    with host(temp, tls, auditor_settings) as auditor_browser:
        auditor_browser.request("/controller/audit", 401)
        auditor_browser.request("/login", 302, {
            "username": "fixture-auditor",
            "password": PASSWORD,
            "__RequestVerificationToken": auditor_browser.token("/login"),
        })
        audit_payload = json.loads(auditor_browser.request("/controller/audit", 200))
        assert audit_payload["role"] == "nergal:auditor"
        assert audit_payload["actorId"].startswith("local:")
        assert json.loads(auditor_browser.request("/controller/hosts", 200))["hosts"] == []
        auditor_browser.request("/controller/hosts", 403, {
            "name": "denied-host",
            "transportKind": "tls",
            "endpoint": "192.0.2.50:8443",
            "pinnedServerThumbprint": "a" * 64,
            "__RequestVerificationToken": auditor_browser.token("/session"),
        })
        assert "Register agent host" not in auditor_browser.request("/manage", 200)
        assert "Save policy revision" not in auditor_browser.request("/manage/policies", 200)
        preview_html = auditor_browser.request("/manage/policies/preview", 200, {
            "bundleJson": json.dumps({
                "schemaVersion": 1,
                "filter": {"schemaVersion": 1, "inputDefaultVerdict": "drop", "rules": []}
            }),
            "__RequestVerificationToken": auditor_browser.token("/manage/policies"),
        })
        assert "create table inet nergal_filter" in preview_html
        auditor_browser.request("/manage/policies/save", 403, {
            "bundleJson": json.dumps({
                "schemaVersion": 1,
                "filter": {"schemaVersion": 1, "inputDefaultVerdict": "drop", "rules": []}
            }),
            "__RequestVerificationToken": auditor_browser.token("/manage/policies"),
        })
        auditor_browser.request("/manage/sources", 403)
        auditor_browser.request(report_path, 403)
        assert "Append-only audit log" in auditor_browser.request("/manage/audit", 200)

    print("PASS: routed source-bound migration downloads, immutable startup snapshots, and anonymous/auditor denial")
    print("PASS: HTTPS, cookie attributes, CSRF, durable sessions, revocation, lockout, RBAC auditor boundaries and request rate limits")


if __name__ == "__main__":
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="nergal-sessions-") as directory:
        exercise(Path(directory))
