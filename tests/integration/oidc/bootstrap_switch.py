"""Retire a local ticket on OIDC initiation and bind the challenge to its bootstrap host start."""
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "local-sessions"))
from identity_https import Browser, CHALLENGE, code_at, enroll_totp, forms_in


def exercise_bootstrap_switch(temp, sessions, provider, host_settings, RelyingParty):
    tls = sessions.provision(temp)
    replacement_dir = temp / "replacement"
    replacement_dir.mkdir(mode=0o700)
    database = temp / "accounts/accounts.db"
    with provider(temp) as (original, cert), provider(replacement_dir) as (replacement, new_cert):
        settings = host_settings(original, cert)
        with sessions.host(temp, tls, settings) as host:
            browser = RelyingParty(host)
            browser.request("/login", 302, {"username": "fixture-admin", "password": sessions.PASSWORD,
                            "__RequestVerificationToken": browser.token("/login")})
            copied = RelyingParty(host)
            copied.cookies[sessions.ADMIN] = browser.cookies[sessions.ADMIN]
            browser.request("/login/oidc", 400, {})
            copied.request("/session", 200)

            with sqlite3.connect(database) as db:
                db.execute("CREATE TRIGGER reject_signout BEFORE INSERT ON IdentityAudit "
                           "WHEN NEW.Action = 'account.signedOut' BEGIN SELECT RAISE(ABORT, 'fixture failure'); END")
            _, location = browser.request("/login/oidc", 503, {"__RequestVerificationToken": browser.token("/session")})
            assert location is None
            copied.request("/session", 200)
            with sqlite3.connect(database) as db:
                db.execute("DROP TRIGGER reject_signout")

            form = browser.authorize(original, cert, token_path="/session")
            assert sessions.ADMIN not in browser.cookies
            copied.request("/session", 401)
            with sqlite3.connect(database) as db:
                assert db.execute("SELECT count(*) FROM IdentityAudit WHERE Action='account.signedOut'").fetchone() == (1,)

        # Keep the callback address, correlation cookies and protected key ring across restart.
        # The synthetic issuer omits optional response 'iss', so it cannot mask the state binding.
        replacement.callback = original.callback
        changed = {**settings, "Oidc__Issuer": replacement.issuer, "Oidc__ClientId": replacement.client,
                   "Oidc__ClientSecret": replacement.secret, "SSL_CERT_FILE": str(new_cert)}
        with sessions.host(temp, tls, changed) as host:
            pending = RelyingParty(host)
            pending.cookies.update(browser.cookies)
            pending.request("/signin-oidc", 401, form)
            assert original.token_requests == 0 and replacement.token_requests == 0
            pending.request("/session", 401)
            pending.exchange(replacement, new_cert, 302)
            pending.request("/session", 200)
            assert replacement.token_requests == 1

            local = Browser(host)
            local.login()
            seed, step = enroll_totp(local)
            copied = RelyingParty(host)
            copied.cookies["__Host-nergal-federated"] = pending.cookies["__Host-nergal-federated"]
            _, challenge = pending.request("/login", 302, {"username": "fixture-admin", "password": sessions.PASSWORD,
                                           "__RequestVerificationToken": pending.token("/session")})
            assert challenge == CHALLENGE and "__Host-nergal-federated" not in pending.cookies
            copied.request("/session", 401)
            pending.request("/session", 401)
            completion = forms_in(pending.request(CHALLENGE, 200)[0])[CHALLENGE]
            _, destination = pending.request(CHALLENGE, 302, {**completion, "code": code_at(seed, step + 1)})
            assert destination == "/session" and sessions.ADMIN in pending.cookies
            pending.request("/session", 200)

    print("PASS: OIDC initiation revokes the local ticket atomically with sign-out audit, "
          "and a bootstrap restart rejects pending state before redemption")
