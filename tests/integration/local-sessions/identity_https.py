"""Form and browser helpers for isolated HTTPS identity checks."""
from html.parser import HTMLParser
import base64
import hmac
import importlib.util
from pathlib import Path
import re
import time


oidc_check = Path(__file__).resolve().parents[1] / "oidc" / "check.py"
spec = importlib.util.spec_from_file_location("oidc_check", oidc_check)
oidc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oidc)
sessions = oidc.sessions
CSRF = "__RequestVerificationToken"
CHALLENGE = "/login/mfa"
CONTINUATION = "__Host-nergal-mfa"
ENROLLMENT = "/profile/mfa"
ENROLL = ENROLLMENT + "/begin"
ACTIVATE = ENROLLMENT + "/confirm"
STEP_SECONDS = 30


class Forms(HTMLParser):
    """Read inputs from the exact form under test, since a page can have several."""

    def __init__(self):
        super().__init__()
        self.forms = {}
        self.current = None
        self.selection = None

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "form":
            self.current = None
            self.selection = None
            if fields.get("method", "").lower() == "post" and "action" in fields:
                action = fields["action"]
                assert action not in self.forms, f"Duplicate POST form for {action}"
                self.current = self.forms[action] = {}
        elif tag == "input" and self.current is not None and "name" in fields:
            if fields.get("type") in ("submit", "reset", "button"):
                return
            if "disabled" in fields or (fields.get("type") in ("checkbox", "radio") and "checked" not in fields):
                return
            name = fields["name"]
            self.add_field(name, fields.get("value", ""))
        elif tag == "select" and self.current is not None and "name" in fields and "disabled" not in fields:
            assert "multiple" not in fields, "Fixture expected a single-valued select"
            self.selection = (fields["name"], None)
        elif tag == "option" and self.selection is not None and "disabled" not in fields:
            name, value = self.selection
            if value is None or "selected" in fields:
                self.selection = (name, fields["value"])

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None
        elif tag == "select" and self.selection is not None:
            name, value = self.selection
            if value is not None:
                self.add_field(name, value)
            self.selection = None

    def add_field(self, name, value):
        assert name not in self.current, f"Duplicate form field {name}"
        self.current[name] = value


def forms_in(page):
    parser = Forms()
    parser.feed(page)
    parser.close()
    return parser.forms


class Browser(oidc.RelyingParty):
    """Reuse the HTTPS cookie jar across local, pending and LDAP tickets."""

    def __init__(self, host, *, secrets=()):
        super().__init__(host)
        self.secrets = (sessions.PASSWORD, *secrets)

    def request(self, path, expected, fields=None, method=None):
        body, location = super().request(path, expected, fields, method)
        assert all(value not in body for value in self.secrets), f"{path} disclosed a fixture password"
        self.location = location
        return body

    def token(self, path):
        parser = sessions.Token()
        parser.feed(self.request(path, 200))
        assert parser.value, f"{path} did not render an antiforgery token"
        return parser.value

    def form(self, page, action):
        forms = forms_in(self.request(page, 200))
        assert action in forms, f"{page} did not render POST form {action}"
        assert forms[action].get(CSRF), f"{action} did not render an antiforgery token"
        return forms[action]

    def post(self, action, fields, expected, *, destination=None):
        body = self.request(action, expected, fields)
        if destination is not None:
            assert self.location == destination, f"{action} did not redirect to {destination}"
        return body

    def login(self, expected=302, *, destination="/session"):
        fields = self.form("/login", "/login")
        return self.post("/login", {**fields, "username": "fixture-admin", "password": sessions.PASSWORD},
                         expected, destination=destination)

    def assert_anonymous(self):
        self.request("/session", 401)
        self.request("/profile", 401)

    def assert_pending(self):
        assert CONTINUATION in self.cookies, "First factor did not issue a browser continuation"
        self.assert_anonymous()


def code_at(seed, step):
    digest = hmac.digest(seed, step.to_bytes(8, "big"), "sha1")
    offset = digest[-1] & 15
    truncated = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{truncated % 1_000_000:06d}"


def early_step(after=-1):
    """Leave room for live requests and advance past any previously accepted step."""
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        step, elapsed = divmod(time.time(), STEP_SECONDS)
        if step > after and elapsed < 12:
            return int(step)
        time.sleep(0.1)
    raise AssertionError("No fresh TOTP time step became available")


def enroll_totp(browser):
    enrollment = browser.post(ENROLL, browser.form(ENROLLMENT, ENROLL), 200)
    keys = re.findall(r"<code>([A-Z2-7]{32})</code>", enrollment)
    assert len(keys) == 1, "Expected one manual authenticator key in the enrollment response"
    seed = base64.b32decode(keys[0])
    activation = forms_in(enrollment)[ACTIVATE]
    step = early_step()
    browser.post(ACTIVATE, {**activation, "code": code_at(seed, step)}, 302, destination="/login")
    browser.assert_anonymous()
    return seed, step
