"""Probe the installed controller over HTTPS and the packaged agent control socket."""
from html.parser import HTMLParser
from http.cookiejar import CookieJar
import json
from pathlib import Path
import socket
import ssl
import struct
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import (
    build_opener,
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, target):
        return None


class LoginForm(HTMLParser):
    token = None

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "input" and fields.get("name") == "__RequestVerificationToken":
            self.token = fields.get("value")


def https(assets_only=False, remote_pin=None):
    context = ssl.create_default_context(cafile="/etc/nergal/web/tls.crt")
    browser = build_opener(HTTPSHandler(context=context), HTTPCookieProcessor(CookieJar()), NoRedirect())

    def request(path, expected, data=None, headers=None):
        try:
            outgoing = Request("https://127.0.0.1:8443" + path, data, headers or {})
            result = browser.open(outgoing, timeout=8)
        except HTTPError as error:
            result = error
        with result:
            assert result.code == expected, f"{path}: expected {expected}, received {result.code}"
            return result.read().decode()

    if assets_only:
        assert request("/css/nergal.css", 200), "Packaged stylesheet was empty"
        print("Installed controller served the packaged stylesheet over HTTPS")
        return

    deadline = time.monotonic() + 60
    while True:
        try:
            request("/healthz", 200)
            break
        except URLError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)

    request("/manage", 401)
    form = LoginForm()
    form.feed(request("/login", 200))
    assert form.token, "Missing login antiforgery token"
    password = Path("/run/nergal-fixture-password").read_text().strip()
    request("/login", 302, urlencode({
        "username": "fixture-admin",
        "password": password,
        "__RequestVerificationToken": form.token,
    }).encode())
    request("/manage", 200)
    if remote_pin is not None:
        form = LoginForm()
        form.feed(request("/session", 200))
        assert form.token, "Missing authenticated antiforgery token"
        headers = {"Content-Type": "application/json", "RequestVerificationToken": form.token}
        for name, pin, outcome, revision in (
            ("fixture-peer", remote_pin, "matched", "1"),
            ("fixture-wrong-pin", "0" * 64, "unavailable", None),
        ):
            host = json.loads(request("/controller/hosts", 201, json.dumps({
                "name": name, "transportKind": "tls", "endpoint": "192.0.2.10:9443",
                "pinnedServerThumbprint": pin,
            }).encode(), headers))
            status = json.loads(request(f"/controller/apply/status?hostId={host['id']}", 200))
            assert (status["outcome"], status["revision"]) == (outcome, revision), status
        print("Installed controller matched the pinned mTLS agent; the wrong pin disclosed no revision")


def agent(expected, server_uid):
    request = b'{"schemaVersion":1,"command":"status"}'
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(10)
        client.connect("/run/nergal/control.sock")
        _, peer_uid, _ = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        assert peer_uid == server_uid, "Control socket had an unexpected server UID"
        try:
            client.sendall(struct.pack(">I", len(request)) + request)
            client.shutdown(socket.SHUT_WR)
        except (BrokenPipeError, ConnectionResetError):
            assert expected == "denied", "Authorized status connection closed"
        with client.makefile("rb") as stream:
            size, = struct.unpack(">I", stream.read(4))
            assert 1 <= size <= 262144, "Status frame exceeded the size bound"
            reply = json.loads(stream.read(size))
    wanted = {"schemaVersion": 1, "outcome": expected}
    if expected == "matched":
        wanted["revision"] = "1"
    assert reply == wanted, f"Unexpected installed agent status: {reply}"


if sys.argv[1:] == ["https"]:
    https()
elif sys.argv[1:] == ["assets"]:
    https(assets_only=True)
elif len(sys.argv) == 3 and sys.argv[1] == "remote":
    https(remote_pin=sys.argv[2])
else:
    outcome, uid = sys.argv[1:]
    agent(outcome, int(uid))
