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
import sqlite3
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
                          "userinfo_endpoint": op.issuer + "/userinfo",
                          "response_types_supported": ["code"], "subject_types_supported": ["public"],
                          "id_token_signing_alg_values_supported": ["RS256"]})
        elif self.path == "/keys":
            self.respond({"keys": [op.jwk]})
        elif self.path == "/userinfo":
            op.userinfo_requests += 1
            self.respond({"sub": "synthetic-external-subject", "amr": ["mfa"]})
        elif urlsplit(self.path).path == "/authorize":
            query = parse_qs(urlsplit(self.path).query)
            valid = (query.get("response_type") == ["code"] and query.get("response_mode") == ["form_post"]
                     and set(query.get("scope", [""])[0].split()) == {"openid", "profile", "email"}
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
        op.token_requests += 1
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
        encoded_claims = json.dumps(claims, separators=(",", ":"))
        for name, value in op.repeated_claims:
            encoded_claims = encoded_claims[:-1] + "," + json.dumps(name) + ":" + json.dumps(value) + "}"
        signed = compact({"alg": "RS256", "typ": "JWT", "kid": "fixture-key"}) + "." + encode(encoded_claims.encode())
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
        server.token_requests = 0
        server.userinfo_requests = 0
        server.repeated_claims = []
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

    def request(self, path, expected, fields=None, method=None):
        browser = self.browser
        connection = http.client.HTTPSConnection("127.0.0.1", browser.ports["https"], context=browser.tls, timeout=10)
        headers = {"Cookie": "; ".join(k + "=" + v for k, v in self.cookies.items())}
        if fields is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        verb = method or ("GET" if fields is None else "POST")
        try:
            connection.request(verb, path, None if fields is None else urlencode(fields), headers)
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

    def authorize(self, op, cert, token_path="/login"):
        _, location = self.request("/login/oidc", 302, {"__RequestVerificationToken": self.token(token_path)})
        parts = urlsplit(location)
        assert parts.scheme + "://" + parts.netloc == op.issuer
        # The IdP receives no RP cookies or password.
        with contextlib.closing(http.client.HTTPSConnection(parts.hostname, parts.port, context=ssl.create_default_context(cafile=str(cert)))) as idp:
            idp.request("GET", parts.path + "?" + parts.query)
            response = idp.getresponse()
            assert response.status == 200
            return json.load(response)

    def exchange(self, op, cert, expected, alter_form=None, destination="/session"):
        form = self.authorize(op, cert)
        if alter_form:
            alter_form(form)
        _, actual_destination = self.request("/signin-oidc", expected, form)
        if expected == 302:
            assert actual_destination == destination



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
                rp.exchange(op, cert, 401, lambda form: form.update(groups="fixture-admins"))
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
            rp.exchange(op, cert, 302, lambda form: form.update(continue_button="Continue", groups="untrusted-form-value"))
            assert "synthetic-external-subject" in rp.request("/session", 200)[0]
            external_profile = rp.request("/profile", 200)[0]
            assert "Identity provider" in external_profile and 'action="/profile/password"' not in external_profile
            _, profile_destination = rp.request("/profile/save", 302, {
                "version": "0", "displayName": "External <script>profile</script>",
                "givenName": "Local given", "familyName": "Local family", "email": "local@example.test",
                "__RequestVerificationToken": rp.token("/profile"),
            })
            assert profile_destination == "/profile"
            saved_profile = rp.request("/profile", 200)[0]
            assert "External &lt;script&gt;profile&lt;/script&gt;" in saved_profile
            assert "synthetic-external-subject" in saved_profile
            assert "<script>profile</script>" not in saved_profile
            assert all(value in saved_profile for value in ["Local given", "Local family", "local@example.test"])
            other = RelyingParty(browser)
            other.exchange(op, cert, 302)
            independent = other.cookies["__Host-nergal-federated"]
            local_mapping_admin = RelyingParty(browser)
            local_mapping_admin.request("/login", 302, {"username": "fixture-admin", "password": sessions.PASSWORD,
                "__RequestVerificationToken": local_mapping_admin.token("/login")})
            mapping_page = "/manage/identity/profiles"
            mapping = {"issuer": op.issuer, "version": "0", "enabled": "true", "displayNameClaim": "name",
                       "givenNameClaim": "given_name", "familyNameClaim": "family_name", "emailClaim": "email"}
            local_mapping_admin.request(mapping_page + "/save", 302, {**mapping,
                "__RequestVerificationToken": local_mapping_admin.token(mapping_page)})
            op.overrides = {"name": "Provider <script>display</script>", "given_name": "Provider given",
                            "family_name": "Provider family", "email": "provider@example.test", "email_verified": True}
            mapped = RelyingParty(browser)
            mapped.exchange(op, cert, 302)
            defaults = mapped.request("/profile", 200)[0]
            assert "Provider &lt;script&gt;display&lt;/script&gt;" in defaults and "<script>display</script>" not in defaults
            assert all(v in defaults for v in ["Provider given", "Provider family", "provider@example.test", "mapping version 1"])
            assert 'value="Local given"' in defaults and 'value="local@example.test"' in defaults
            database = temp / "accounts" / "accounts.db"
            with sqlite3.connect(database) as db:
                assert db.execute('SELECT count(*) FROM OidcProfileObservation').fetchone()[0] == 1
                events = db.execute("SELECT count(*) FROM IdentityAudit WHERE Action='profile.providerRefreshed'").fetchone()[0]
            # Signature validation alone must not persist metadata before nonce validation.
            op.overrides["nonce"] = "invalid-after-signature"
            RelyingParty(browser).exchange(op, cert, 401)
            with sqlite3.connect(database) as db:
                assert db.execute("SELECT count(*) FROM IdentityAudit WHERE Action='profile.providerRefreshed'").fetchone()[0] == events
            op.overrides.pop("nonce")
            # A mapping change retires defaults immediately; a new signed exchange refreshes just provider fields.
            local_mapping_admin.request(mapping_page + "/save", 302, {**mapping, "version": "1", "displayNameClaim": "nickname",
                "__RequestVerificationToken": local_mapping_admin.token(mapping_page)})
            assert "No current provider defaults" in mapped.request("/profile", 200)[0]
            op.overrides["nickname"] = "Refreshed provider name"
            mapped.request("/logout", 302, {"__RequestVerificationToken": mapped.token("/profile")})
            mapped.exchange(op, cert, 302)
            refreshed = mapped.request("/profile", 200)[0]
            assert "Refreshed provider name" in refreshed and "mapping version 2" in refreshed
            assert 'value="External &lt;script&gt;profile&lt;/script&gt;"' in refreshed
            op.overrides["email"] = ["invalid-array-value"]
            missing_optional = RelyingParty(browser)
            missing_optional.exchange(op, cert, 302)
            optional_page = missing_optional.request("/profile", 200)[0]
            assert "The provider supplied an invalid profile email address." in optional_page
            assert 'value="local@example.test"' in optional_page and "invalid-array-value" not in optional_page
            op.overrides["email"] = "provider@example.test"
            with sqlite3.connect(database) as db:
                db.execute("CREATE TRIGGER fixture_profile_audit_fail BEFORE INSERT ON IdentityAudit BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END")
                prior = db.execute('SELECT ObservedUtc FROM OidcProfileObservation').fetchone()[0]
            failed_storage = RelyingParty(browser)
            failed_storage.exchange(op, cert, 503)
            failed_storage.request("/session", 401)
            with sqlite3.connect(database) as db:
                assert db.execute('SELECT ObservedUtc FROM OidcProfileObservation').fetchone()[0] == prior
                db.execute('DROP TRIGGER fixture_profile_audit_fail')
            op.overrides = {}
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

        ctrl_dir = temp / "oidc-controller-state"
        ctrl_dir.mkdir(mode=0o700)
        subprocess.run(["dotnet", sessions.ADMIN_TOOL, "controller", "init", ctrl_dir], check=True)
        rbac_settings = {
            **host_settings(op, cert),
            "Oidc__AuditorGroups__0": "fixture-auditors",
            "ControllerState__Enabled": "true",
            "ControllerState__Directory": str(ctrl_dir),
        }
        with sessions.host(temp, tls, rbac_settings) as browser:
            anon = RelyingParty(browser)
            anon.request("/controller/audit", 401)

            op.overrides = {"sub": "oidc-auditor-sub", "groups": ["fixture-auditors"]}
            auditor_rp = RelyingParty(browser)
            auditor_rp.exchange(op, cert, 302, destination="/manage")
            audit_view = json.loads(auditor_rp.request("/controller/audit", 200)[0])
            assert audit_view["role"] == "nergal:auditor"
            assert audit_view["actorId"] == f"oidc:{len(op.issuer)}:{op.issuer}:oidc-auditor-sub"
            auditor_rp.request("/controller/hosts", 200)
            auditor_rp.request("/controller/hosts", 403, {
                "name": "auditor-blocked",
                "transportKind": "tls",
                "endpoint": "192.0.2.20:8443",
                "pinnedServerThumbprint": "b" * 64,
                "__RequestVerificationToken": auditor_rp.token("/session"),
            })

            op.overrides = {"sub": "oidc-admin-sub", "groups": ["fixture-admins"]}
            admin_rp = RelyingParty(browser)
            admin_rp.exchange(op, cert, 302, destination="/manage")
            admin_csrf = admin_rp.token("/session")
            admin_rp.request("/controller/hosts", 400, {
                "name": "missing-csrf",
                "transportKind": "tls",
                "endpoint": "192.0.2.21:8443",
                "pinnedServerThumbprint": "c" * 64,
            })
            created_tls = json.loads(admin_rp.request("/controller/hosts", 201, {
                "name": "edge-gw",
                "transportKind": "tls",
                "endpoint": "192.0.2.21:8443",
                "pinnedServerThumbprint": "c" * 64,
                "__RequestVerificationToken": admin_csrf,
            })[0])

            local_admin = RelyingParty(browser)
            local_admin.request("/login", 302, {
                "username": "fixture-admin",
                "password": sessions.PASSWORD,
                "__RequestVerificationToken": local_admin.token("/login"),
            })
            local_csrf = local_admin.token("/session")
            local_admin.request("/controller/hosts", 201, {
                "name": "local-agent",
                "transportKind": "unix",
                "endpoint": "/run/nergal/control.sock",
                "expectedServerUserId": "100",
                "__RequestVerificationToken": local_csrf,
            })

            auditor_rp.request(f"/controller/hosts/{created_tls['id']}", 403, {
                "__RequestVerificationToken": auditor_rp.token("/session"),
            }, method="DELETE")
            admin_rp.request(f"/controller/hosts/{created_tls['id']}", 204, {
                "__RequestVerificationToken": admin_csrf,
            }, method="DELETE")

            entries = json.loads(auditor_rp.request("/controller/audit", 200)[0])["entries"]
            actions = [(e["action"], e["target"], e["actorId"], e["actorRole"]) for e in entries]
            assert ("host.register", "edge-gw", f"oidc:{len(op.issuer)}:{op.issuer}:oidc-admin-sub", "nergal:administrator") in actions
            assert ("host.delete", "edge-gw", f"oidc:{len(op.issuer)}:{op.issuer}:oidc-admin-sub", "nergal:administrator") in actions
            assert any(a == "host.register" and t == "local-agent" and act.startswith("local:") and r == "nergal:administrator"
                       for a, t, act, r in actions)

            bundle_v1 = json.dumps({
                "schemaVersion": 1,
                "filter": {"schemaVersion": 1, "inputDefaultVerdict": "drop", "rules": []},
            })
            bundle_v2 = json.dumps({
                "schemaVersion": 1,
                "filter": {
                    "schemaVersion": 2,
                    "inputDefaultVerdict": "drop",
                    "forwardDefaultVerdict": "drop",
                    "outputDefaultVerdict": "accept",
                    "rules": [
                        {"family": "ipv4", "protocol": "tcp", "destinationPort": 443, "verdict": "accept", "chain": "input"}
                    ],
                },
            })

            auditor_rp.request("/manage", 200)
            assert "Save policy revision" not in auditor_rp.request("/manage/policies", 200)[0]
            auditor_rp.request("/manage/policies/save", 403, {
                "bundleJson": bundle_v1,
                "__RequestVerificationToken": auditor_rp.token("/manage/policies"),
            })

            _, rev1_loc = admin_rp.request("/manage/policies/save", 302, {
                "bundleJson": bundle_v1,
                "summary": "Rev 1 baseline",
                "__RequestVerificationToken": admin_rp.token("/manage/policies"),
            })
            assert rev1_loc == "/manage/policies?revision=1"
            admin_rp.request("/manage/policies/save", 400, {
                "bundleJson": "{invalid",
                "__RequestVerificationToken": admin_rp.token("/manage/policies"),
            })

            _, rev2_loc = local_admin.request("/manage/policies/save", 302, {
                "bundleJson": bundle_v2,
                "summary": "Rev 2 https",
                "compareToRevision": "1",
                "__RequestVerificationToken": local_admin.token("/manage/policies"),
            })
            assert rev2_loc == "/manage/policies?revision=2"

            diff_page = auditor_rp.request("/manage/policies?revision=2&compareTo=1", 200)[0]
            assert "tcp dport 443 accept" in diff_page
            audit_page = auditor_rp.request("/manage/audit", 200)[0]
            assert "Rev 2 https" in audit_page and "policy.save" in audit_page

    print("PASS: signed profile defaults, per-field local overrides, mapping retirement/refresh, nonce non-persistence and audit-failure sign-in denial")
    print("PASS: real discovery, code/PKCE exchange, signed group/role authorization, issuer/audience/nonce/age denial, logout replay, independent local login and audit attribution")


if __name__ == "__main__":
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="nergal-oidc-") as directory:
        exercise(Path(directory))

    from connection_settings import exercise_connections
    with tempfile.TemporaryDirectory(prefix="nergal-oidc-connection-") as directory:
        exercise_connections(Path(directory), sessions, provider, host_settings, RelyingParty)

    from bootstrap_switch import exercise_bootstrap_switch
    with tempfile.TemporaryDirectory(prefix="nergal-oidc-switch-") as directory:
        exercise_bootstrap_switch(Path(directory), sessions, provider, host_settings, RelyingParty)

    from mfa_assurance import exercise_assurance
    with tempfile.TemporaryDirectory(prefix="nergal-oidc-assurance-") as directory:
        exercise_assurance(Path(directory), sessions, provider, host_settings, RelyingParty)
