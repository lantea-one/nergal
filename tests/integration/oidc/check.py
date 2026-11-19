"""Real HTTPS authorization-code/PKCE exchange with a disposable synthetic issuer."""
import base64
import contextlib
import hashlib
import hmac
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit

spec = importlib.util.spec_from_file_location("local_sessions", Path(__file__).resolve().parents[1] / "local-sessions/check.py")
sessions = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sessions)


def encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def compact(value):
    return encode(json.dumps(value, separators=(",", ":")).encode())


class Issuer(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Correlation, code, nonce and tokens never go in fixture output.

    def respond(self, value, status=200):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        op = self.server
        if self.path == "/.well-known/openid-configuration":
            self.respond({"issuer": op.issuer, "authorization_endpoint": op.issuer + "/authorize",
                          "token_endpoint": op.issuer + "/token", "jwks_uri": op.issuer + "/keys",
                          "response_types_supported": ["code"], "subject_types_supported": ["public"],
                          "id_token_signing_alg_values_supported": ["RS256"]})
        elif self.path == "/keys":
            self.respond({"keys": [op.jwk]})
        elif urlsplit(self.path).path == "/authorize":
            query = parse_qs(urlsplit(self.path).query)
            valid = (query.get("response_type") == ["code"] and query.get("response_mode") == ["form_post"]
                     and query.get("client_id") == [op.client] and query.get("redirect_uri") == [op.callback]
                     and query.get("code_challenge_method") == ["S256"] and all(k in query for k in ("state", "nonce", "code_challenge")))
            if not valid:
                self.respond({}, 400)
                return
            code = secrets.token_urlsafe(24)
            op.codes[code] = (query["nonce"][0], query["code_challenge"][0])
            self.respond({"code": code, "state": query["state"][0]})
        else:
            self.respond({}, 404)

    def do_POST(self):
        op = self.server
        form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        code = form.get("code", [""])[0]
        authorization = op.codes.pop(code, None)
        valid = (self.path == "/token" and authorization and form.get("grant_type") == ["authorization_code"]
                 and form.get("client_id") == [op.client] and form.get("client_secret") == [op.secret]
                 and form.get("redirect_uri") == [op.callback] and "code_verifier" in form
                 and hmac.compare_digest(encode(hashlib.sha256(form["code_verifier"][0].encode()).digest()), authorization[1]))
        if not valid:
            self.respond({"error": "invalid_grant"}, 400)
            return
        now = int(time.time())
        claims = {"iss": op.issuer, "sub": "synthetic-external-subject", "aud": op.client, "iat": now,
                  "exp": now + 3600, "nonce": authorization[0], "groups": ["fixture-admins"], **op.overrides}
        signed = compact({"alg": "RS256", "typ": "JWT", "kid": "fixture-key"}) + "." + compact(claims)
        signature = subprocess.check_output(["openssl", "dgst", "-sha256", "-sign", op.signing_key], input=signed.encode())
        self.respond({"id_token": signed + "." + encode(signature), "access_token": "synthetic-unused", "token_type": "Bearer"})


@contextlib.contextmanager
def provider(temp):
    key, cert = temp / "issuer.key", temp / "issuer.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "1", "-subj", "/CN=synthetic-idp",
                    "-addext", "subjectAltName=IP:127.0.0.2", "-keyout", key, "-out", cert], check=True, stderr=subprocess.DEVNULL)
    modulus = subprocess.check_output(["openssl", "rsa", "-in", key, "-noout", "-modulus"], text=True).strip().split("=")[1]
    with http.server.ThreadingHTTPServer(("127.0.0.2", 0), Issuer) as server:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        server.issuer = f"https://127.0.0.2:{server.server_port}"
        server.jwk = {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "fixture-key", "e": "AQAB", "n": encode(bytes.fromhex(modulus))}
        server.signing_key, server.client, server.secret = key, "fixture-client", secrets.token_urlsafe(32)
        server.codes, server.overrides = {}, {}
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server, cert
        finally:
            server.shutdown()
            thread.join(timeout=5)


class RelyingParty:
    def __init__(self, browser):
        self.browser = browser
        self.cookies = {}

    def request(self, path, expected, fields=None):
        browser = self.browser
        connection = http.client.HTTPSConnection("127.0.0.1", browser.ports["https"], context=browser.tls, timeout=10)
        headers = {"Cookie": "; ".join(k + "=" + v for k, v in self.cookies.items())}
        if fields is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            connection.request("GET" if fields is None else "POST", path, None if fields is None else urlencode(fields), headers)
            response = connection.getresponse()
            body = response.read().decode()
            assert response.status == expected, f"{path}: expected {expected}, received {response.status}"
            for name, value in response.getheaders():
                if name.lower() == "set-cookie":
                    pair, *attributes = value.split("; ")
                    key, cookie = pair.split("=", 1)
                    if cookie:
                        self.cookies[key] = cookie
                    else:
                        self.cookies.pop(key, None)
                    if key == "__Host-nergal-federated" and cookie:
                        attrs = {a.lower() for a in attributes}
                        assert {"path=/", "httponly", "secure", "samesite=strict"} <= attrs
                        assert not any(a.startswith(("domain=", "expires=", "max-age=")) for a in attrs)
            return body, response.getheader("Location")
        finally:
            connection.close()

    def token(self, path):
        parser = sessions.Token()
        parser.feed(self.request(path, 200)[0])
        assert parser.value
        return parser.value

    def exchange(self, op, cert, expected, alter_form=None):
        _, location = self.request("/login/oidc", 302, {"__RequestVerificationToken": self.token("/login")})
        parts = urlsplit(location)
        assert parts.scheme + "://" + parts.netloc == op.issuer
        # The IdP receives no RP cookies or password.
        with contextlib.closing(http.client.HTTPSConnection(parts.hostname, parts.port, context=ssl.create_default_context(cafile=str(cert)))) as idp:
            idp.request("GET", parts.path + "?" + parts.query)
            response = idp.getresponse()
            assert response.status == 200
            form = json.load(response)
        if alter_form:
            alter_form(form)
        _, destination = self.request("/signin-oidc", expected, form)
        if expected == 302:
            assert destination == "/session"



def host_settings(op, cert):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    op.callback = f"https://127.0.0.1:{port}/signin-oidc"
    return {"Oidc__Enabled": "true", "Oidc__Issuer": op.issuer, "Oidc__ClientId": op.client,
                "Oidc__ClientSecret": op.secret, "Oidc__GroupClaim": "groups", "Oidc__AdministratorGroups__0": "fixture-admins",
                "Oidc__CallbackUri": op.callback, "SSL_CERT_FILE": str(cert), "NO_PROXY": "127.0.0.1,127.0.0.2",
                "ASPNETCORE_URLS": f"http://127.0.0.1:0;https://127.0.0.1:{port}"}


def exercise(temp):
    tls = sessions.provision(temp)
    with provider(temp) as (op, cert):
        settings = host_settings(op, cert)
        with sessions.host(temp, tls, settings) as browser:
            rp = RelyingParty(browser)
            rp.request("/login/oidc", 400, {})
            for override in ({"groups": ["Fixture-Admins"]}, {"aud": "another-client"}, {"iss": op.issuer + "/other"},
                             {"nonce": "different"}, {"iat": int(time.time()) - 901}):
                op.overrides = override
                rp.exchange(op, cert, 401)
                rp.request("/session", 401)
            op.overrides = {}
            op.signing_key = temp / "tls.key"
            rp.exchange(op, cert, 401)
            op.signing_key = temp / "issuer.key"
            rp.exchange(op, cert, 401, lambda form: form.update(state="invalid-state"))
            rp.exchange(op, cert, 401, lambda form: form.update(access_token="unexpected-response"))
            # A fixed-window login budget applies to both forms. Use a new host
            # below to exercise success independently of the denial-case budget.
        with sessions.host(temp, tls, settings) as browser:
            rp = RelyingParty(browser)
            rp.exchange(op, cert, 302)
            assert "synthetic-external-subject" in rp.request("/session", 200)[0]
            other = RelyingParty(browser)
            other.exchange(op, cert, 302)
            independent = other.cookies["__Host-nergal-federated"]
            cookie = rp.cookies["__Host-nergal-federated"]
            rp.request("/logout", 302, {"__RequestVerificationToken": rp.token("/session")})
            rp.cookies["__Host-nergal-federated"] = cookie
            rp.request("/session", 401)
            other.request("/session", 200)
            # Local login remains independently usable on the OIDC-enabled host.
            rp.request("/login", 302, {"username": "fixture-admin", "password": sessions.PASSWORD,
                                      "__RequestVerificationToken": rp.token("/login")})
            assert "fixture-admin" in rp.request("/session", 200)[0]
        with sessions.host(temp, tls, settings) as browser:
            replay = RelyingParty(browser)
            replay.cookies["__Host-nergal-federated"] = independent
            replay.request("/session", 401)
    print("PASS: real discovery, code/PKCE exchange, signed group authorization, issuer/audience/nonce/age denial, logout replay and independent local login")


if __name__ == "__main__":
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="nergal-oidc-") as directory:
        exercise(Path(directory))
