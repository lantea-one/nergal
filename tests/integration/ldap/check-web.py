"""Exercise explicit LDAP sign-in and per-field profiles over the disposable HTTPS host."""
from html import escape
import os
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "local-sessions"))
from identity_https import (Browser, CHALLENGE, CONTINUATION, CSRF, code_at, early_step,
                            enroll_totp, forms_in, oidc, sessions)
from session_switch import exercise_local_switch


CONNECTION = "/manage/identity/ldap"
SAVE_CONNECTION = CONNECTION + "/save"
LDAP_LOGIN = "/login/ldap"
LDAP_VERSION = "version"
LDAP_COOKIE = "__Host-nergal-ldap"
DENIED_MESSAGE = "Sign-in failed. Verify your credentials and try again."
BIND_PASSWORD = "fixture-reader-password"
USER_PASSWORD = "fixture-user-password"
WRONG_PASSWORD = "synthetic incorrect directory password"
BASE = "dc=example,dc=test"
PROFILE = "/profile"
SAVE_PROFILE = "/profile/save"
PROFILE_FIELDS = ("displayName", "givenName", "familyName", "email")
PROFILE_LABELS = ("Display name", "Given name", "Family name", "Profile email")
EMPTY_FIELDS = ("", "", "", "")
DEFAULTS = ("Fixture Administrator", "Fixture", "Administrator", "administrator@example.test")
OVERRIDES = ("Local <fixture> name", "", "", "local-override@example.test")


def client(host):
    return Browser(host, secrets=(BIND_PASSWORD, USER_PASSWORD, WRONG_PASSWORD))


def ldap_form(browser, username="administrator", password=USER_PASSWORD):
    return {**browser.form("/login", LDAP_LOGIN), "username": username, "password": password}


def sign_in(browser, username="administrator"):
    browser.post(LDAP_LOGIN, ldap_form(browser, username), 302, destination="/session")
    assert LDAP_COOKIE in browser.cookies and sessions.ADMIN not in browser.cookies, "LDAP used the wrong cookie"
    browser.request("/session", 200)


def profile(browser, role, defaults, overrides=EMPTY_FIELDS):
    page = browser.request(PROFILE, 200)
    assert f"<dt>Role</dt><dd>{role}</dd>" in page, "Unexpected LDAP profile role"
    assert "<dt>Authentication</dt><dd>LDAP</dd>" in page
    fields = forms_in(page)[SAVE_PROFILE]
    assert tuple(fields[name] for name in PROFILE_FIELDS) == overrides, "Unexpected personal override fields"
    for label, value in zip(PROFILE_LABELS, defaults):
        assert f"<dt>{label}</dt><dd>{escape(value or 'Not supplied')}</dd>" in page, f"Unexpected LDAP default for {label}"
    assert f'aria-label="My profile for {escape(overrides[0] or defaults[0])}"' in page
    return page


def profile_with_overrides(browser):
    page = profile(browser, "Administrator", DEFAULTS, OVERRIDES)
    assert "Local &lt;fixture&gt; name" in page and "Local <fixture> name" not in page


def logout_and_deny_replay(host, browser):
    replay = client(host)
    replay.cookies.update(browser.cookies)
    browser.post("/logout", browser.form("/session", "/logout"), 302, destination="/login")
    browser.assert_anonymous()
    replay.assert_anonymous()


def connection_values(port):
    return {
        "enabled": "true",
        "serverUri": f"ldaps://directory.example.test:{port}",
        "dialIp": "127.0.0.1",
        "userBaseDn": f"ou=people,{BASE}",
        "searchBindDn": f"cn=reader,{BASE}",
        "loginAttribute": "uid",
        "administratorGroupDn": f"cn=administrators,ou=roles,{BASE}",
        "auditorGroupDn": f"cn=auditors,ou=roles,{BASE}",
        "displayNameAttribute": "displayName",
        "givenNameAttribute": "givenName",
        "familyNameAttribute": "sn",
        "emailAttribute": "mail",
        "searchPassword": BIND_PASSWORD,
        "confirm": "replace-trust",
    }


def connection_state(database):
    with sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True) as db:
        return db.execute("SELECT Version, Enabled, ProtectedSecret FROM LdapConnection").fetchone()


def observations(database):
    with sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True) as db:
        return db.execute("""
            SELECT ActorId, ConnectionGeneration, DisplayName, GivenName, FamilyName, Email, ObservedUtc
            FROM LdapProfileObservation ORDER BY ActorId
            """).fetchall()


def require_ldap_mfa(host, browser, database):
    seed, enrollment_step = enroll_totp(browser)
    before = observations(database)
    stale = client(host)
    stale.post(LDAP_LOGIN, ldap_form(stale), 302, destination=CHALLENGE)
    stale_form = stale.form(CHALLENGE, CHALLENGE)
    stale.assert_pending()

    # Change trust after the directory bind. Completion must retire the old
    # proof without consuming the code or changing the last profile observation.
    manager = client(host)
    manager.login()
    retained = {**manager.form(CONNECTION, SAVE_CONNECTION), "confirm": "replace-trust"}
    manager.post(SAVE_CONNECTION, retained, 302, destination=CONNECTION)
    step = early_step(after=enrollment_step)
    code = code_at(seed, step)
    stale.post(CHALLENGE, {**stale_form, "code": code}, 401)
    stale.assert_anonymous()
    assert observations(database) == before, "Retired LDAP proof refreshed provider metadata"

    pending = client(host)
    pending.post(LDAP_LOGIN, ldap_form(pending), 302, destination=CHALLENGE)
    assert LDAP_COOKIE not in pending.cookies and sessions.ADMIN not in pending.cookies
    pending.assert_pending()
    assert observations(database) == before, "Pending LDAP proof refreshed provider metadata before MFA"
    form = pending.form(CHALLENGE, CHALLENGE)
    # Fail the final audit in the disposable account database. The same proof
    # and code must remain usable after the transaction rolls back.
    with sqlite3.connect(database) as db:
        db.execute("""
            CREATE TRIGGER fixture_ldap_sign_in_failure BEFORE INSERT ON IdentityAudit
            WHEN NEW.Action = 'ldap.signedIn'
            BEGIN SELECT RAISE(ABORT, 'synthetic LDAP audit failure'); END
            """)
    try:
        challenge = {**form, "code": code}
        failure = pending.post(CHALLENGE, challenge, 503)
        assert "synthetic LDAP audit failure" not in failure
        pending.assert_pending()
        assert observations(database) == before, "Failed MFA audit committed provider metadata"
    finally:
        with sqlite3.connect(database) as db:
            db.execute("DROP TRIGGER fixture_ldap_sign_in_failure")
    pending.post(CHALLENGE, challenge, 302, destination="/session")
    assert LDAP_COOKIE in pending.cookies and CONTINUATION not in pending.cookies
    profile_with_overrides(pending)
    assert observations(database) != before, "Completed LDAP MFA did not refresh provider metadata"

    pre_logout = client(host)
    pre_logout.post(LDAP_LOGIN, ldap_form(pre_logout), 302, destination=CHALLENGE)
    pre_logout_form = pre_logout.form(CHALLENGE, CHALLENGE)
    logout_and_deny_replay(host, pending)
    pre_logout.post(CHALLENGE, {**pre_logout_form, "code": code_at(seed, step + 1)}, 401)
    pre_logout.assert_anonymous()


def exercise(temp, port, trust):
    tls = sessions.provision(temp)
    database = temp / "accounts/accounts.db"
    values = connection_values(port)
    with sessions.host(temp, tls, trust) as host:
        admin = client(host)
        assert LDAP_LOGIN not in forms_in(admin.request("/login", 200)), "LDAP appeared before activation"
        admin.login()
        settings = admin.form(CONNECTION, SAVE_CONNECTION)
        proposal = {**settings, **values}
        admin.request(SAVE_CONNECTION, 400, {name: value for name, value in proposal.items() if name != CSRF})
        assert connection_state(database) is None, "CSRF denial saved LDAP trust"
        admin.post(SAVE_CONNECTION, proposal, 302, destination=CONNECTION)
        version, enabled, protected = connection_state(database)
        assert (version, enabled) == (1, 1)
        assert protected and BIND_PASSWORD not in protected, "Bind secret persisted in clear text"

        stale = client(host)
        old_form = ldap_form(stale)
        assert old_form[LDAP_VERSION] == "1", "LDAP login did not render the current generation"
        ldap_admin = client(host)
        sign_in(ldap_admin)
        ldap_admin.request(CONNECTION, 403)
        ldap_admin.request("/manage/users", 200)
        profile(ldap_admin, "Administrator", DEFAULTS)
        original = observations(database)
        assert len(original) == 1 and original[0][1:-1] == (1, *DEFAULTS), "LDAP defaults were not persisted"
        form = ldap_admin.form(PROFILE, SAVE_PROFILE)
        ldap_admin.post(SAVE_PROFILE, {**form, **dict(zip(PROFILE_FIELDS, OVERRIDES))}, 302, destination=PROFILE)
        profile_with_overrides(ldap_admin)
        assert observations(database) == original, "A local override mutated its provider observation"

        # A version-only edit retires proofs and leaves the directory/actor identity intact.
        retained = {**admin.form(CONNECTION, SAVE_CONNECTION), "confirm": "replace-trust"}
        admin.post(SAVE_CONNECTION, retained, 302, destination=CONNECTION)
        assert connection_state(database) == (2, 1, protected), "Blank save did not retain the bind secret"
        ldap_admin.assert_anonymous()
        assert DENIED_MESSAGE in stale.post(LDAP_LOGIN, old_form, 401)
        stale.assert_anonymous()

        invalid = client(host)
        current = ldap_form(invalid, password=WRONG_PASSWORD)
        assert current[LDAP_VERSION] == "2", "LDAP login rendered a retired generation"
        local_form = invalid.form("/login", "/login")
        invalid.post("/login", {**local_form, "username": "administrator", "password": USER_PASSWORD}, 401)
        invalid.assert_anonymous()
        invalid.request(LDAP_LOGIN, 400, {name: value for name, value in current.items() if name != CSRF})
        assert DENIED_MESSAGE in invalid.post(LDAP_LOGIN, current, 401)
        invalid.assert_anonymous()
        assert DENIED_MESSAGE in invalid.post(LDAP_LOGIN, ldap_form(invalid, "ambiguous"), 401)
        invalid.assert_anonymous()
        assert observations(database) == original, "A denied LDAP attempt persisted a provider observation"

        auditor = client(host)
        sign_in(auditor, "auditor")
        profile(auditor, "Auditor", ("Fixture Auditor", "", "Auditor", ""))
        auditor.request(CONNECTION, 403)
        auditor.request("/manage/users", 403)
        logout_and_deny_replay(host, auditor)
        admin.request("/session", 200)
        persisted = observations(database)

    with sessions.host(temp, tls, trust) as host:
        assert observations(database) == persisted, "LDAP observations were lost across restart"
        ldap_admin = client(host)
        sign_in(ldap_admin)
        profile_with_overrides(ldap_admin)
        refreshed = next(row for row in observations(database) if row[0] == original[0][0])
        assert refreshed[1:-1] == (2, *DEFAULTS), "New generation changed the actor or lost its defaults"
        logout_and_deny_replay(host, ldap_admin)
        sign_in(ldap_admin)
        profile_with_overrides(ldap_admin)
        require_ldap_mfa(host, ldap_admin, database)

        admin = client(host)
        admin.login()
        disabled = {**admin.form(CONNECTION, SAVE_CONNECTION), "confirm": "replace-trust"}
        disabled.pop("enabled")
        admin.post(SAVE_CONNECTION, disabled, 302, destination=CONNECTION)
        assert connection_state(database) == (4, 0, protected)
        recovery = client(host)
        assert LDAP_LOGIN not in forms_in(recovery.request("/login", 200)), "Disabled LDAP remained advertised"
        recovery.login()
        recovery.request("/session", 200)

        # Reserve a loopback port without listening so the configured directory is unreachable.
        with socket.socket() as unavailable:
            unavailable.bind(("127.0.0.1", 0))
            absent_port = unavailable.getsockname()[1]
            recovery.post(SAVE_CONNECTION, {**recovery.form(CONNECTION, SAVE_CONNECTION),
                          **connection_values(absent_port)}, 302, destination=CONNECTION)
            absent_peer = client(host)
            assert DENIED_MESSAGE in absent_peer.post(LDAP_LOGIN, ldap_form(absent_peer), 401)
            absent_peer.assert_anonymous()
            absent_peer.login()
            absent_peer.request("/session", 200)
    print("PASS: explicit LDAPS sign-in, stale/invalid denial, profile persistence after restart and re-sign-in, "
          "LDAP authenticator enrollment and challenge, role isolation, outage recovery and logout replay denial")
    check_oidc_switch(temp, tls, port, trust)



class DisplacedLdapBrowser(oidc.RelyingParty):
    """Emulates a same-site challenge followed by a cross-site form-post callback."""

    def token(self, path):
        return super().token("/session" if path == "/login" else path)

    def request(self, path, expected, fields=None, method=None):
        if path == "/signin-oidc":
            self.cookies.pop(LDAP_COOKIE, None)
        return super().request(path, expected, fields, method)


def check_oidc_switch(temp, tls, port, trust):
    with oidc.provider(temp) as (provider, certificate):
        bundle = temp / "directory-and-oidc-ca.pem"
        bundle.write_bytes(Path(trust["SSL_CERT_FILE"]).read_bytes() + certificate.read_bytes())
        settings = {**trust, **oidc.host_settings(provider, certificate), "SSL_CERT_FILE": str(bundle),
                    "Oidc__AuditorGroups__0": "fixture-auditors"}
        provider.overrides = {"groups": ["fixture-auditors"]}
        with sessions.host(temp, tls, settings) as host:
            admin = client(host)
            admin.login()
            admin.post(SAVE_CONNECTION, {**admin.form(CONNECTION, SAVE_CONNECTION),
                                         **connection_values(port)}, 302, destination=CONNECTION)
            exercise_local_switch(host, admin, USER_PASSWORD)

            ldap_admin = client(host)
            sign_in(ldap_admin)
            replay = client(host)
            replay.cookies.update(ldap_admin.cookies)
            switched = DisplacedLdapBrowser(host)
            switched.cookies.update(ldap_admin.cookies)
            switched.exchange(provider, certificate, 302)
            assert LDAP_COOKIE not in switched.cookies
            switched.request("/manage/users", 403)
            replay.assert_anonymous()

    print("PASS: local-to-LDAP and LDAP-to-OIDC switches retire the displaced authority")

def main():
    try:
        port = int(os.environ["NERGAL_LDAP_FIXTURE_PORT"])
        trust = {key: os.environ[key] for key in ("SSL_CERT_FILE", "SSL_CERT_DIR")}
    except (KeyError, ValueError):
        raise SystemExit("Run with the disposable LDAP port, CA file and empty certificate directory.")
    if not (1024 <= port <= 65535 and Path(trust["SSL_CERT_FILE"]).is_file()
            and Path(trust["SSL_CERT_DIR"]).is_dir() and not any(Path(trust["SSL_CERT_DIR"]).iterdir())):
        raise SystemExit("Expected the disposable LDAP port, CA file and empty certificate directory.")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="nergal-ldap-web-") as directory:
        exercise(Path(directory), port, trust)


if __name__ == "__main__":
    main()
