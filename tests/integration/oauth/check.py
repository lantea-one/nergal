"""Exercise managed OAuth sign-in with real HTTPS and synthetic, loopback-only endpoints."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
import base64
import hashlib
import hmac
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
from urllib.parse import parse_qs, unquote_plus, urlencode, urlsplit

integration = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(integration / "local-sessions"))
sys.path.insert(0, str(integration / "oidc"))
from identity_https import Browser, CSRF, Forms, forms_in, oidc, sessions
from mfa_assurance import authenticate_local, enroll_totp


SETTINGS = "/manage/identity/oauth"
SAVE = SETTINGS + "/save"
START = "/login/oauth"
CALLBACK = "/signin-oauth"
COOKIE = "__Host-nergal-oauth"
CORRELATION = COOKIE + "-correlation"
PROFILE = "/profile"
PROFILE_SAVE = PROFILE + "/save"
POLICY = "/manage/identity/mfa"
ADMINS = "fixture-admins"
AUDITORS = "fixture-auditors"
SCOPE = "profile groups"
SUBJECT = "account.id"
GROUPS = "access.groups"


def profile(**overrides):
    return {SUBJECT: "fixture-person", GROUPS: [ADMINS], "full.name": "Provider <Fixture>",
            "first_name": "Provider given", "last_name": "Provider family", "mail": "provider@example.test",
            "unmapped": "synthetic-unmapped-oauth-payload",
            **overrides}


class Provider(http.server.BaseHTTPRequestHandler):
    """Offer only authorization, token redemption and an authenticated current-user object."""

    def log_message(self, *_):
        pass

    def respond(self, status, body=b"", **headers):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers.items():
            self.send_header(name.replace("_", "-"), value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def respond_json(self, payload):
        self.respond(200, payload, Content_Type="application/json", Cache_Control="no-store")

    def do_GET(self):
        if self.path.startswith("/authorize?"):
            self.authorize()
        elif self.path == "/me":
            self.current_user()
        else:
            self.respond(404)

    def authorize(self):
        op = self.server
        query = parse_qs(urlsplit(self.path).query, strict_parsing=True)
        fixed = {"client_id": [op.client], "redirect_uri": [op.callback], "response_type": ["code"],
                 "code_challenge_method": ["S256"], "scope": [SCOPE]}
        if (set(query) != set(fixed) | {"state", "code_challenge"}
                or any(query[name] != value for name, value in fixed.items())
                or any(len(query[name]) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{43}", query[name][0])
                       for name in ("state", "code_challenge")) or self.headers.get("Cookie")
                or self.headers.get("Authorization")):
            self.respond(400)
            return
        code = "oauth-fixture-code-" + secrets.token_urlsafe()
        with op.lock:
            op.sensitive.append(code)
            op.codes[code] = (query["code_challenge"][0], op.next_profile)
        self.respond(302, Location=op.callback + "?" + urlencode({"code": code, "state": query["state"][0]}))

    def do_POST(self):
        op = self.server
        if self.path != "/token":
            self.respond(404)
            return
        with op.lock:
            op.token_requests += 1
        # Decode the two RFC 6749 form components separately, including reserved characters.
        authorization = self.headers.get("Authorization", "")
        try:
            assert authorization.startswith("Basic ")
            encoded_client, encoded_secret = base64.b64decode(authorization[6:], validate=True).decode("ascii").split(":", 1)
            authorized = (hmac.compare_digest(unquote_plus(encoded_client).encode(), op.client.encode())
                          and hmac.compare_digest(unquote_plus(encoded_secret).encode(), op.secret.encode()))
        except (AssertionError, ValueError):
            authorized = False

        form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode("ascii"), strict_parsing=True)
        if (not authorized or self.headers.get("Cookie") or self.headers.get_content_type() !=
                "application/x-www-form-urlencoded" or set(form) != {"grant_type", "redirect_uri", "code", "code_verifier"}
                or form["grant_type"] != ["authorization_code"] or form["redirect_uri"] != [op.callback]
                or len(form["code"]) != 1 or len(form["code_verifier"]) != 1
                or not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", form["code_verifier"][0])):
            self.respond(400)
            return

        verifier = form["code_verifier"][0]
        challenge = oidc.encode(hashlib.sha256(verifier.encode("ascii")).digest())
        with op.lock:
            code = form["code"][0]
            grant = op.codes.get(code)
            if grant is not None and hmac.compare_digest(challenge, grant[0]):
                del op.codes[code]
                access = "oauth-fixture-access-" + secrets.token_urlsafe()
                refresh = "oauth-fixture-refresh-" + secrets.token_urlsafe()
                op.tokens[access] = grant[1]
                op.sensitive.extend((verifier, access, refresh))
            else:
                grant = None
        if grant is None:
            self.respond(400)
            return
        if op.pause_redemption:
            op.redemption_reached.set()
            if not op.release_redemption.wait(timeout=5):
                self.respond(503)
                return
        try:
            self.respond_json(json.dumps({"access_token": access, "refresh_token": refresh,
                                          "token_type": "Bearer", "expires_in": 120}).encode())
        except (BrokenPipeError, ssl.SSLEOFError):
            if not op.pause_redemption:
                raise

    def current_user(self):
        op = self.server
        authorization = self.headers.get("Authorization", "")
        with op.lock:
            op.profile_requests += 1
            payload = op.tokens.pop(authorization.removeprefix("Bearer "), None) if authorization.startswith("Bearer ") else None
        if payload is None or self.headers.get("Cookie"):
            self.respond(401)
            return
        self.respond_json(payload)


@contextmanager
def provider(temp):
    key, cert = temp / "oauth.key", temp / "oauth.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "1",
                    "-subj", "/CN=synthetic-oauth", "-addext", "subjectAltName=IP:127.0.0.2",
                    "-keyout", key, "-out", cert], check=True, stderr=subprocess.DEVNULL)
    with http.server.ThreadingHTTPServer(("127.0.0.2", 0), Provider) as server:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        server.client_tls = ssl.create_default_context(cafile=str(cert))
        server.origin = f"https://127.0.0.2:{server.server_port}"
        server.client = "synthetic client:+"
        server.secret = "synthetic OAuth secret:+/" + secrets.token_urlsafe()
        server.sensitive = [server.secret, "synthetic-unmapped-oauth-payload"]
        server.codes, server.tokens = {}, {}
        server.token_requests = server.profile_requests = 0
        server.lock = threading.Lock()
        server.pause_redemption = False
        server.redemption_reached = threading.Event()
        server.release_redemption = threading.Event()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server, cert
        finally:
            server.release_redemption.set()
            server.shutdown()
            thread.join(timeout=5)


class OAuthBrowser(Browser):
    def __init__(self, host, op):
        super().__init__(host)
        self.op = op

    def request(self, path, expected, fields=None, method=None):
        try:
            body = super().request(path, expected, fields, method)
        except AssertionError as error:
            if path.startswith(CALLBACK + "?"):
                raise AssertionError(str(error).replace(path, CALLBACK)) from None
            raise
        with self.op.lock:
            values = tuple(self.op.sensitive)
        places = (body, self.location or "", *self.cookies.values())
        assert not any(value in place for value in values for place in places), "OAuth material exposed to the browser"
        return body

    def authorize(self, payload):
        op = self.op
        with op.lock:
            op.next_profile = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.post(START, self.form("/login", START), 302)
        assert CORRELATION in self.cookies and COOKIE not in self.cookies
        location = urlsplit(self.location)
        assert f"{location.scheme}://{location.netloc}{location.path}" == op.origin + "/authorize"
        with closing(http.client.HTTPSConnection("127.0.0.2", op.server_port, context=op.client_tls, timeout=10)) as connection:
            connection.request("GET", "/authorize?" + location.query)
            response = connection.getresponse()
            response.read()
            assert response.status == 302, "Provider rejected the authorization-code and PKCE request"
            callback = urlsplit(response.getheader("Location"))
        assert f"{callback.scheme}://{callback.netloc}{callback.path}" == op.callback
        return CALLBACK + "?" + callback.query

    def complete(self, callback, expected):
        self.request(callback, expected)
        if expected == 302:
            assert self.location == "/session" and COOKIE in self.cookies and CORRELATION in self.cookies
            self.request("/session", 200)
        else:
            assert COOKIE not in self.cookies, "Denied callback issued an OAuth session"
            self.assert_anonymous()

    def exchange(self, payload, expected=302):
        self.complete(self.authorize(payload), expected)


class ConnectionForms(Forms):
    """Read the two group textareas and check the explicit trust replacement control."""

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if self.current is not None and tag == "textarea":
            self.add_field(fields["name"], "")
        if self.current is not None and tag == "input" and fields.get("name") == "confirm":
            attrs = [*attrs, ("checked", "checked")]
        super().handle_starttag(tag, attrs)


def connection_form(admin, op, **settings):
    parser = ConnectionForms()
    parser.feed(admin.request(SETTINGS, 200))
    parser.close()
    form = parser.forms[SAVE]
    inputs = dict(authorizationEndpoint=op.origin + "/authorize", tokenEndpoint=op.origin + "/token",
                  profileEndpoint=op.origin + "/me", callbackUri=op.callback, clientId=op.client, scope=SCOPE,
                  subjectField=SUBJECT, groupField=GROUPS, administratorGroups=ADMINS, auditorGroups=AUDITORS,
                  displayName="full.name", givenName="first_name", familyName="last_name", email="mail")
    assert form.keys() == inputs.keys() | {CSRF, "version", "enabled", "clientSecret", "trustProviderMfa", "confirm"}
    assert form[CSRF] and form["confirm"] == "replace-trust"
    return {**form, **inputs, **settings}


def read_db(database, sql, parameters=()):
    with closing(sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)) as db:
        return db.execute(sql, parameters).fetchall()


def observations(database):
    return (read_db(database, "SELECT * FROM OAuthProfileObservation ORDER BY ActorId"),
            read_db(database, "SELECT * FROM IdentityAudit WHERE Action='oauth.signedIn' ORDER BY Sequence"))


def check_browser_flow(host, op, database):
    admin = OAuthBrowser(host, op)
    anonymous = OAuthBrowser(host, op)
    assert START not in forms_in(anonymous.request("/login", 200))
    anonymous.request(SETTINGS, 401)
    admin.login()
    form = connection_form(admin, op, enabled="true", clientSecret=op.secret)
    assert form["version"] == "0" and form["trustProviderMfa"] == "false"
    for field in (CSRF, "scope", "confirm"):
        admin.post(SAVE, {name: value for name, value in form.items() if name != field}, 400)
    admin.post(SAVE, {**form, "confirm": ""}, 400)
    admin.post(SAVE, {("unexpected" if name == "scope" else name): value for name, value in form.items()}, 400)
    admin.post(SAVE, [(name, value) for name, value in form.items() if name != "scope"] + [("enabled", "false")], 400)
    admin.post(SAVE, {**form, "tokenEndpoint": op.origin.replace("https:", "http:") + "/token"}, 400)
    assert read_db(database, "SELECT Id FROM OAuthConnection") == []
    admin.post(SAVE, form, 302, destination=SETTINGS)
    stale = admin.post(SAVE, {**form, "trustProviderMfa": "true", "auditorGroups": "stale-proposal"}, 400)
    assert "These connection settings changed." in stale
    redisplayed = forms_in(stale)[SAVE]
    assert redisplayed["version"] == "1" and redisplayed["trustProviderMfa"] == "false"
    assert AUDITORS in stale and "stale-proposal" not in stale
    version, protected = read_db(database, "SELECT Version, ProtectedSecret FROM OAuthConnection")[0]
    assert version == 1 and protected and protected != op.secret
    assert (op.token_requests, op.profile_requests) == (0, 0), "Saving settings contacted the OAuth backchannel"
    assert protected not in admin.request(SETTINGS, 200)
    assert admin.form(SETTINGS, SAVE)["clientSecret"] == "", "Settings rendered the saved secret"

    login = OAuthBrowser(host, op)
    login.post(START, {"version": "1"}, 400)
    callback = login.authorize(profile())
    original = dict(login.cookies)
    anonymous.complete(callback, 401)
    wrong_state = urlencode({"state": "x" * 43})
    code = parse_qs(urlsplit(callback).query)["code"][0]
    login.complete(CALLBACK + "?" + urlencode({"code": code}) + "&" + wrong_state, 401)
    login.complete(callback + "&code=duplicate", 401)
    assert (op.token_requests, op.profile_requests) == (0, 0), "Uncorrelated callback reached the provider"

    # Hold the real backchannel open while the same callback and browser cookie
    # race a second request. The second must fail before the provider sees it.
    replay = OAuthBrowser(host, op)
    replay.cookies.update(original)
    op.pause_redemption = True
    with ThreadPoolExecutor(max_workers=1) as executor:
        success = executor.submit(login.complete, callback, 302)
        try:
            assert op.redemption_reached.wait(timeout=5), "Valid callback did not reach token redemption"
            replay.complete(callback, 401)
            assert (op.token_requests, op.profile_requests) == (1, 0), "Replay reached the token endpoint"
        finally:
            op.release_redemption.set()
        success.result(timeout=10)
    op.pause_redemption = False
    replay.complete(callback, 401)
    assert (op.token_requests, op.profile_requests) == (1, 1)

    page = login.request(PROFILE, 200)
    fields = forms_in(page)[PROFILE_SAVE]
    assert "<dt>Role</dt><dd>Administrator</dd>" in page
    assert fields["displayName"] == "" and fields["email"] == "", "Provider defaults populated local override inputs"
    assert "<dt>Display name</dt><dd>Provider &lt;Fixture&gt;</dd>" in page
    assert "<dt>Profile email</dt><dd>provider@example.test</dd>" in page
    login.request(SETTINGS, 403)
    # Use a token from the OAuth browser so the local-Administrator check, rather
    # than antiforgery validation, is responsible for denying the provider Administrator.
    login.post(SAVE, {**form, CSRF: fields[CSRF], "version": "1", "clientSecret": ""}, 403)
    login.post(PROFILE_SAVE, {**fields, "displayName": "Local override", "givenName": "", "familyName": "", "email": ""},
               302, destination=PROFILE)

    refreshed = OAuthBrowser(host, op)
    refreshed.exchange(profile(**{"full.name": "Refreshed provider name", "first_name": "Refreshed given"}))
    page = refreshed.request(PROFILE, 200)
    fields = forms_in(page)[PROFILE_SAVE]
    assert fields["displayName"] == "Local override" and fields["givenName"] == ""
    assert "<dt>Given name</dt><dd>Refreshed given</dd>" in page
    assert "Current OAuth profile endpoint defaults" in page
    assert "<dt>Display name</dt><dd>Refreshed provider name</dd>" in page, "Provider provenance was not rendered"
    actor, provider_name = read_db(database, "SELECT ActorId, DisplayName FROM OAuthProfileObservation")[0]
    assert actor.startswith("oauth:") and provider_name == "Refreshed provider name"
    assert read_db(database, "SELECT DisplayName, GivenName, Email FROM LocalProfile WHERE ActorId=?", (actor,)) == [
        ("Local override", "", "")]

    auditor = OAuthBrowser(host, op)
    auditor.exchange(profile(**{SUBJECT: "fixture-auditor", GROUPS: [AUDITORS]}))
    assert "<dt>Role</dt><dd>Auditor</dd>" in auditor.request(PROFILE, 200)
    auditor.request(SETTINGS, 403)

    ticket = auditor.cookies[COOKIE]
    auditor.post("/logout", auditor.form(PROFILE, "/logout"), 302, destination="/login")
    assert COOKIE not in auditor.cookies
    auditor.cookies[COOKIE] = ticket
    auditor.assert_anonymous()

    pending = OAuthBrowser(host, op)
    old_callback = pending.authorize(profile())
    stale_start = OAuthBrowser(host, op)
    old_start = stale_start.form("/login", START)
    config = connection_form(admin, op, email="new.mail")
    assert config["version"] == "1" and config["clientSecret"] == ""
    admin.post(SAVE, config, 302, destination=SETTINGS)
    old_token_count = op.token_requests
    pending.complete(old_callback, 401)
    stale_start.post(START, old_start, 401)
    assert op.token_requests == old_token_count, "Retired OAuth generation attempted code redemption"
    login.assert_anonymous()
    refreshed.assert_anonymous()
    admin.request("/session", 200)
    assert read_db(database, "SELECT Version, ProtectedSecret FROM OAuthConnection") == [(2, protected)]

    current = OAuthBrowser(host, op)
    current.exchange(profile(**{"new.mail": "remapped@example.test"}))
    assert "<dt>Profile email</dt><dd>remapped@example.test</dd>" in current.request(PROFILE, 200)


def check_denials(host, op, database):
    before = observations(database)
    denials = (
        ("case-mismatched group", profile(**{GROUPS: [ADMINS.upper()]})),
        ("non-exact group", profile(**{GROUPS: [ADMINS + "-extra"]})),
        ("ambiguous role", profile(**{GROUPS: [ADMINS, AUDITORS]})),
        ("duplicate group", profile(**{GROUPS: [ADMINS, ADMINS]})),
        ("invalid subject", profile(**{SUBJECT: 42})),
        ("duplicate subject member", json.dumps(profile()).encode()[:-1] + b', "account.id":"other-account"}'),
    )
    for label, payload in denials:
        token_requests, profile_requests = op.token_requests, op.profile_requests
        try:
            OAuthBrowser(host, op).exchange(payload, 401)
        except AssertionError as error:
            raise AssertionError(f"{label}: {error}") from None
        assert (op.token_requests, op.profile_requests) == (token_requests + 1, profile_requests + 1), label
    assert observations(database) == before, "Denied identities changed provider observations or sign-in audit"

    # A failure to append the sign-in audit must also roll back the profile refresh.
    with closing(sqlite3.connect(database)) as db:
        db.execute("CREATE TRIGGER fixture_oauth_audit_failure BEFORE INSERT ON IdentityAudit "
                   "WHEN NEW.Action='oauth.signedIn' BEGIN SELECT RAISE(ABORT, 'fixture write failure'); END")
        try:
            OAuthBrowser(host, op).exchange(profile(**{"full.name": "Uncommitted profile"}), 503)
            assert observations(database) == before, "A failed audit left an OAuth profile change behind"
        finally:
            db.execute("DROP TRIGGER fixture_oauth_audit_failure")


def check_mfa(host, op, database):
    admin = OAuthBrowser(host, op)
    admin.login()
    seed, enrollment_step = enroll_totp(admin)
    step = authenticate_local(admin, seed, enrollment_step)
    policy_form = admin.form(POLICY, POLICY + "/save")
    pending = OAuthBrowser(host, op)
    callback = pending.authorize(profile(amr=["mfa"], **{"full.name": "Untrusted MFA profile"}))
    before = observations(database)
    admin.post(POLICY + "/save", {**policy_form, "requirement": "Administrators"}, 302, destination=POLICY)
    pending.complete(callback, 401)
    OAuthBrowser(host, op).exchange(profile(amr=["mfa"]), 401)
    assert observations(database) == before, "Untrusted MFA claims changed profile observations or sign-in audit"
    auditor = OAuthBrowser(host, op)
    auditor.exchange(profile(**{SUBJECT: "fixture-auditor", GROUPS: [AUDITORS]}))
    assert "<dt>Role</dt><dd>Auditor</dd>" in auditor.request(PROFILE, 200)

    authenticate_local(admin, seed, step)
    config = connection_form(admin, op, email="new.mail")
    assert config["trustProviderMfa"] == "false"
    admin.post(SAVE, {**config, "trustProviderMfa": "true"}, 302, destination=SETTINGS)
    trusted = OAuthBrowser(host, op)
    trusted.exchange(profile())
    assert trusted.form(PROFILE, PROFILE_SAVE)["displayName"] == "Local override"
    auditor.assert_anonymous()


def check_superseded_callback(host, op, database):
    pending = OAuthBrowser(host, op)
    callback = pending.authorize(profile(**{"full.name": "Superseded OAuth profile"}))
    local = OAuthBrowser(host, op)
    local.cookies.update(pending.cookies)
    before = observations(database)
    profiles = op.profile_requests
    op.redemption_reached.clear()
    op.release_redemption.clear()
    op.pause_redemption = True
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            completion = executor.submit(pending.complete, callback, 401)
            try:
                assert op.redemption_reached.wait(timeout=5), "OAuth callback did not start redemption"
                local.login()
                local.request("/session", 200)
            finally:
                op.release_redemption.set()
            completion.result(timeout=10)
        assert COOKIE not in pending.cookies
        assert observations(database) == before and op.profile_requests == profiles
    finally:
        op.pause_redemption = False


def exercise(temp):
    tls = sessions.provision(temp)
    database = temp / "accounts" / "accounts.db"
    with provider(temp) as (op, cert):
        settings = {"Oidc__Enabled": "false", "SSL_CERT_FILE": str(cert), "NO_PROXY": "127.0.0.1,127.0.0.2"}
        with sessions.host(temp, tls, settings) as host:
            port = host.ports["https"]
            op.callback = f"https://127.0.0.1:{port}{CALLBACK}"
            check_browser_flow(host, op, database)
        # Reuse the exact registered callback and store. Each host lifetime
        # exercises the production sign-in rate limiter with its own budget.
        settings["ASPNETCORE_URLS"] = f"http://127.0.0.1:0;https://127.0.0.1:{port}"
        with sessions.host(temp, tls, settings) as host:
            check_denials(host, op, database)
            check_superseded_callback(host, op, database)
        with sessions.host(temp, tls, settings) as host:
            check_mfa(host, op, database)
        private_files = (path for directory in ("accounts", "keys", "profile")
                         for path in (temp / directory).rglob("*") if path.is_file())
        raw_state = [path.read_bytes() for path in private_files]
        with closing(sqlite3.connect(database)) as db:
            logical = "\n".join(db.iterdump())
        for value in op.sensitive:
            assert value not in logical and all(value.encode() not in data for data in raw_state), (
                "OAuth credential, token or unmapped profile value persisted in application state")
    print("PASS: managed OAuth forms, TLS code/PKCE and Bearer profile, exact roles, override provenance, "
          "correlation and replay, trust retirement, logout, MFA policy, atomic audit and SQLite secret isolation")


if __name__ == "__main__":
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="nergal-oauth-web-") as directory:
        exercise(Path(directory))
