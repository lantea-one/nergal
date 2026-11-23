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

    def request(self, path, expected, fields=None, plain=False, headers=None, raw=None):
        connection = (http.client.HTTPConnection("127.0.0.1", self.ports["http"], timeout=10)
                      if plain else http.client.HTTPSConnection("127.0.0.1", self.ports["https"],
                                                                context=self.tls, timeout=10))
        values = dict(headers or {})
        if not plain:
            values["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if fields is not None:
            values["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            connection.request("POST" if fields is not None or raw is not None else "GET", path,
                               raw if raw is not None else None if fields is None else urlencode(fields), values)
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
            self.last_headers = {k.lower(): v for k, v in response.getheaders()}
            self.location = response.getheader("Location")
            if expected == 302:
                assert self.location in ("/login", "/session") or self.location.startswith(("/manage/sources?sourceId=", "/manage/objects?objectId=", "/manage/policies?revision="))
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
           if not k.lower().startswith(("aspnetcore_", "kestrel__", "localsessions__", "agentstatus__", "controllerstate__", "oidc__", "logging__", "nativesources__"))}
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
    report_path = "/manage/sources/review?sourceId=00000000-0000-0000-0000-000000000000"
    controller_settings = {"ControllerState__Enabled": "true", "ControllerState__Directory": str(ctrl_state),
                           "NativeSources__Directory": str(sources)}
    with host(temp, tls, controller_settings) as browser:
        browser.request("/manage/policies/rules/state", 401, {"bundleJson": "{}"})
        browser.request("/manage/policies/rules/conditions", 401, {"bundleJson": "{}"})
        browser.request("/manage/policies/nat/postrouting", 401, {"bundleJson": "{}"})
        browser.request("/manage/policies/objects", 401, {"bundleJson": "{}"})
        browser.request("/manage/objects", 401)
        browser.request("/manage/objects/save", 401, {"name": "denied"})
        browser.request("/manage/sources", 401)
        browser.request(report_path, 401)
        browser.request("/manage/sources/download?sourceId=00000000-0000-0000-0000-000000000000", 401)
        browser.request("/manage/sources/import", 401, {"name": "denied"})
        browser.request("/manage/sources/stage", 401, {"name": "denied"})
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
        assert "No imported snapshots yet" in source_html and "Operator-staged sources" in source_html
        browser.request("/manage/sources/stage", 400, {"name": "synthetic", "digest": source_digest})
        browser.request("/manage/sources/stage", 302, {"name": "synthetic", "digest": source_digest,
                        "__RequestVerificationToken": browser.token("/manage/sources")})
        source_id = browser.location.split("sourceId=")[1]
        report_path = "/manage/sources/review?sourceId=" + source_id
        download_path = "/manage/sources/download?sourceId=" + source_id
        source_html = browser.request("/manage/sources?sourceId=" + source_id, 200)
        assert 'href="' + report_path + '"' in source_html and "Conversion blocked" in source_html
        source_path.write_text("changed after startup")
        report = json.loads(browser.request(report_path, 200))
        assert report["sourceSha256"] == source_digest and report["schemaVersion"] == 1
        assert report["review"]["canConvert"] is False and report["review"]["tableDeclarations"] == 1
        assert {"gap.counters", "source.includes"} <= {s["code"] for s in report["review"]["signals"]}
        assert "text" not in report and "candidate" not in report
        assert browser.request(download_path, 200).encode() == source.encode()
        assert browser.last_headers["content-type"] == "application/octet-stream"
        assert browser.last_headers["content-disposition"].startswith("attachment; filename=nftables.conf")
        assert "no-store" in {v.strip() for v in browser.last_headers["cache-control"].split(",")}
        browser.request("/manage/sources/stage", 404, {"name": "../../etc/passwd", "digest": source_digest,
                        "__RequestVerificationToken": browser.token("/manage/sources")})

        def upload(name, payload, expected=302, csrf=True, extra=(), extra_file=False):
            boundary = "nergal-synthetic-boundary"
            fields = {"name": name}
            if csrf:
                fields["__RequestVerificationToken"] = browser.token("/manage/sources")
            parts = []
            for key, value in [*fields.items(), *extra]:
                parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n').encode())
            header = (f'--{boundary}\r\nContent-Disposition: form-data; name="sourceFile"; filename="../../untrusted.conf"\r\nContent-Type: text/plain\r\n\r\n').encode()
            parts.extend([header, payload, b'\r\n'])
            if extra_file:
                parts.extend([header, b'accept\r\n'])
            parts.append((f'--{boundary}--\r\n').encode())
            return browser.request("/manage/sources/import", expected, raw=b''.join(parts),
                                   headers={"Content-Type": "multipart/form-data; boundary=" + boundary})

        upload("missing token", b'accept', 400, csrf=False)
        upload("invalid encoding", b'\xff', 400)
        upload("unknown field", b'accept', 400, extra=[("unknown", "x")])
        upload("ambiguous name", b'accept', 400, extra=[("name", "other")])
        upload("multiple files", b'accept', 400, extra_file=True)
        upload("invalid size", b'a' * 524_289, 400)
        upload("oversized request", b'a' * 600_001, 413)
        upload("../invalid name", b'accept', 400)
        exact = b'\xef\xbb\xbf# synthetic <script>alert(1)</script>\r\ntable inet sample { }\r\n'
        exact += b'#' + b'x' * (524_288 - len(exact) - 2) + b'\n'
        assert len(exact) == 524_288
        upload("Uploaded snapshot", exact)
        upload_id = browser.location.split("sourceId=")[1]
        with sqlite3.connect(ctrl_state / "controller.db") as db:
            assert db.execute("SELECT name FROM native_sources WHERE id=?", (upload_id,)).fetchone() == ("Uploaded snapshot",)
        assert browser.request("/manage/sources/download?sourceId=" + upload_id, 200).encode() == exact
        html = browser.request("/manage/sources?sourceId=" + upload_id, 200)
        assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
        with sqlite3.connect(ctrl_state / "controller.db") as db:
            assert db.execute("SELECT count(*) FROM native_sources").fetchone() == (2,)
            assert db.execute("SELECT count(*) FROM audit_log WHERE action='source.import'").fetchone() == (2,)
        from objects import check_objects
        object_path = check_objects(browser, ctrl_state)
        from policy_objects import check_policy_objects
        check_policy_objects(browser, ctrl_state)
        from rule_states import check_rule_states
        check_rule_states(browser, ctrl_state)
        from router_forms import check_router_forms
        check_router_forms(browser, ctrl_state)
        session = browser.cookies[ADMIN]
        browser.request("/logout", 400, {})
        assert 'href="/agent/status"' not in browser.request("/session", 200)
        browser.request("/agent/status", 404)
        browser.cookies[ADMIN] = "invalid-ticket"
        browser.request("/session", 401)
    # A normal installation needs no operator source directory after ingestion.
    database_only_settings = {k: v for k, v in controller_settings.items() if k != "NativeSources__Directory"}
    with host(temp, tls, database_only_settings) as browser:
        browser.cookies[ADMIN] = session
        assert browser.request(download_path, 200).encode() == source.encode()
        database_only_html = browser.request("/manage/sources?sourceId=" + source_id, 200)
        assert "Operator-staged sources" not in database_only_html
        assert "synthetic" in database_only_html and "immutable database content" in database_only_html
        assert 'data-local-time datetime="' in database_only_html and 'Stored UTC:' in database_only_html
        assert "Imported (local time)" in database_only_html and "browser time zone" in database_only_html
        assert "New library version" in browser.request(object_path, 200)
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
        assert "Auditor access is read-only" in auditor_browser.request("/manage/objects", 200)
        assert 'action="/manage/objects/save"' not in auditor_browser.request(object_path, 200)
        auditor_browser.request("/manage/objects/save", 403, {"name": "denied", "__RequestVerificationToken": auditor_browser.token("/session")})
        auditor_browser.request("/manage/policies/rules/state", 403, {"bundleJson": "{}", "__RequestVerificationToken": auditor_browser.token("/session")})
        for path in ("/manage/policies/rules/conditions", "/manage/policies/nat/postrouting"):
            auditor_browser.request(path, 403, {"bundleJson": "{}", "__RequestVerificationToken": auditor_browser.token("/session")})
        auditor_browser.request("/manage/policies/objects", 403, {"bundleJson": "{}", "__RequestVerificationToken": auditor_browser.token("/session")})
        auditor_browser.request("/manage/sources", 403)
        auditor_browser.request(report_path, 403)
        auditor_browser.request(download_path, 403)
        auditor_browser.request("/manage/sources/stage", 403, {"name": "synthetic", "digest": source_digest,
                                "__RequestVerificationToken": auditor_browser.token("/session")})
        auditor_browser.request("/manage/sources/import", 403, {"name": "denied", "__RequestVerificationToken": auditor_browser.token("/session")})
        assert "Append-only audit log" in auditor_browser.request("/manage/audit", 200)

    print("PASS: database source ingestion, exact original downloads, restart persistence, XSS/CSRF/UTF-8/size denial and anonymous/auditor boundaries")
    print("PASS: HTTPS, cookie attributes, CSRF, durable sessions, revocation, lockout, RBAC auditor boundaries and request rate limits")


if __name__ == "__main__":
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="nergal-sessions-") as directory:
        exercise(Path(directory))
