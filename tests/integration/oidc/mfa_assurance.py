"""Exercise role-based MFA assurance through the real OIDC and identity endpoints."""
from pathlib import Path
import re
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "local-sessions"))
from identity_https import Browser, CHALLENGE, code_at, early_step, enroll_totp


CONNECTION = "/manage/identity/connection"
POLICY = "/manage/identity/mfa"
MAPPING = "/manage/identity/profiles"
COOKIE = "__Host-nergal-federated"


def authenticate_local(admin, seed, previous_step):
    admin.login(destination=CHALLENGE)
    form = admin.form(CHALLENGE, CHALLENGE)
    step = early_step(after=previous_step)
    admin.post(CHALLENGE, {**form, "code": code_at(seed, step)}, 302, destination="/session")
    return step


def exercise_assurance(temp, sessions, provider, host_settings, RelyingParty):
    tls = sessions.provision(temp)
    database = temp / "accounts" / "accounts.db"
    with provider(temp) as (op, cert):
        settings = {key: value for key, value in host_settings(op, cert).items() if not key.startswith("Oidc__")}
        with sessions.host(temp, tls, settings) as host:
            admin = Browser(host, secrets=(op.secret,))
            admin.login()

            def save_connection(version, mode, claim="", value=""):
                admin.post(CONNECTION + "/save", {
                    "__RequestVerificationToken": admin.token(CONNECTION), "version": str(version), "enabled": "true",
                    "issuer": op.issuer, "clientId": op.client, "callbackUri": op.callback, "groupClaim": "groups",
                    "administratorGroups": "fixture-admins", "auditorGroups": "fixture-auditors",
                    "clientSecret": op.secret if version == 0 else "", "confirm": "replace-trust",
                    "mfaAssuranceMode": mode, "mfaAssuranceClaim": claim, "mfaAssuranceValue": value,
                }, 302, destination=CONNECTION)

            def set_requirement(requirement):
                admin.post(POLICY + "/save", {**admin.form(POLICY, POLICY + "/save"), "requirement": requirement},
                           302, destination=POLICY)

            def exchange(expected, overrides=None, alter_form=None):
                op.overrides = overrides or {}
                browser = RelyingParty(host)
                browser.exchange(op, cert, expected, alter_form=alter_form)
                if expected == 401:
                    assert COOKIE not in browser.cookies
                    browser.request("/session", 401)
                    browser.request("/profile", 401)
                return browser

            def profile_refreshes():
                with sqlite3.connect(database) as db:
                    return db.execute("SELECT count(*) FROM IdentityAudit WHERE Action='profile.providerRefreshed'").fetchone()[0]

            admin.post(MAPPING + "/save", {
                "__RequestVerificationToken": admin.token(MAPPING), "issuer": op.issuer, "version": "0", "enabled": "true",
                "displayNameClaim": "name", "givenNameClaim": "", "familyNameClaim": "", "emailClaim": "",
            }, 302, destination=MAPPING)
            save_connection(0, "Deny")
            optional = exchange(302, {"name": "Optional MFA profile"})
            assert "Optional MFA profile" in optional.request("/profile", 200)[0]
            seed, step = enroll_totp(admin)
            step = authenticate_local(admin, seed, step)

            # Policy becomes required after the authorization request starts. The callback sees the newer policy.
            refreshes = profile_refreshes()
            exchange(401, {"amr": "mfa", "name": "Denied profile"},
                     alter_form=lambda _: set_requirement("Administrators"))
            optional.request("/session", 401)
            assert profile_refreshes() == refreshes
            exchange(302, {"groups": ["fixture-auditors"]}).request("/session", 200)

            step = authenticate_local(admin, seed, step)
            save_connection(1, "SignedClaim", "amr", "mfa")
            with sqlite3.connect(database) as db:
                assert db.execute("SELECT MfaAssuranceMode, MfaAssuranceClaim, MfaAssuranceValue FROM OidcConnection").fetchone() == (2, "amr", "mfa")

        # Each phase gets a fresh process-wide sign-in limit while exercising
        # the real limiter and connection state within that process.
        with sessions.host(temp, tls, settings) as host:
            refreshes = profile_refreshes()
            exchange(401, {"nergal.oidc-mfa-assured": "true", "name": "Denied profile"},
                     alter_form=lambda form: form.update(amr="mfa"))
            for evidence in (True, "MFA", ["mfa", 1], ["mfa", "mfa"], {"method": "mfa"}):
                exchange(401, {"amr": evidence, "name": "Denied profile"})
            op.repeated_claims = [("amr", "mfa")]
            exchange(401, {"amr": "password", "name": "Denied profile"})
            op.repeated_claims = []
            assert op.userinfo_requests == 0 and profile_refreshes() == refreshes

            exchange(302, {"amr": "mfa"}).request("/session", 200)
            assured = exchange(302, {"amr": ["password", "mfa"], "name": "Assured profile"})
            assert "Assured profile" in assured.request("/profile", 200)[0]
            exchange(302, {"groups": ["fixture-auditors"], "amr": ["mfa", 1]}).request("/session", 200)

        with sessions.host(temp, tls, settings) as host:
            admin = Browser(host, secrets=(op.secret,))
            step = authenticate_local(admin, seed, step)
            assured = exchange(302, {"amr": "mfa"})
            token_requests = op.token_requests
            exchange(401, {"amr": "mfa"}, alter_form=lambda _: save_connection(2, "ProviderBypass"))
            assert op.token_requests == token_requests
            assured.request("/session", 401)
            bypass = exchange(302)
            bypass.request("/session", 200)
            stale_ticket = bypass.cookies[COOKIE]
            save_connection(3, "SignedClaim", "amr", "mfa")
            bypass.request("/session", 401)
            # A partial restore cannot reactivate the previous bypass or its ticket.
            with sqlite3.connect(database) as db:
                db.execute("UPDATE OidcConnection SET Version=3, MfaAssuranceMode=1, "
                           "MfaAssuranceClaim='', MfaAssuranceValue=''")
            bypass.cookies[COOKIE] = stale_ticket
            bypass.request("/session", 401)
            admin.request("/session", 200)
            admin.request("/login/oidc", 404, {})
            with sqlite3.connect(database) as db:
                db.execute("UPDATE OidcConnection SET Version=4, MfaAssuranceMode=2, "
                           "MfaAssuranceClaim='amr', MfaAssuranceValue='mfa'")

            # Tightening the role policy retires both optional and already assured sessions.
            auditor = exchange(302, {"groups": ["fixture-auditors"]})
            assured = exchange(302, {"amr": "mfa"})
            set_requirement("All")
            auditor.request("/session", 401)
            assured.request("/session", 401)
            exchange(401, {"groups": ["fixture-auditors"]})
            exchange(302, {"groups": ["fixture-auditors"], "amr": "mfa"}).request("/session", 200)

        # Even with valid operator bootstrap configured, a broken managed secret
        # disables OIDC while leaving local login and recovery independently usable.
        with sqlite3.connect(database) as db:
            db.execute("UPDATE OidcConnection SET ProtectedSecret='unreadable-fixture-secret'")
        with sessions.host(temp, tls, host_settings(op, cert)) as host:
            admin = Browser(host, secrets=(op.secret,))
            assert "Sign in with identity provider" not in admin.request("/login", 200)
            admin.request("/login/recovery", 200)
            admin.request("/login/oidc", 404, {"__RequestVerificationToken": admin.token("/login")})
            authenticate_local(admin, seed, step)
            admin.request("/session", 200)
            issue = POLICY + "/recovery"
            with sqlite3.connect(database) as db:
                actor = "local:" + db.execute("SELECT Id FROM AspNetUsers WHERE UserName='fixture-admin'").fetchone()[0]
            issued = admin.post(issue, {**admin.form(issue, issue), "actorId": actor}, 200)
            match = re.search(r'<code class="text-break">([0-9A-Fa-f]{64})</code>', issued)
            assert match, "Local recovery authorization was unavailable"
            pending = Browser(host, secrets=(op.secret, match[1]))
            begin = "/login/recovery/local"
            pending.post(begin, {**pending.form("/login/recovery", begin), "authorization": match[1],
                                 "username": "fixture-admin", "password": sessions.PASSWORD}, 200)
            assert "__Host-nergal-recovery" in pending.cookies
            pending.assert_anonymous()

    print("PASS: signed OIDC assurance, explicit bypass, profile and session retirement, partial restore denial and isolated local fallback")
