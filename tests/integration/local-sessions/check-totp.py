"""Exercise real password and TOTP forms against a disposable Kestrel HTTPS host."""
import base64
import os
from pathlib import Path
import tempfile
import time

from identity_https import (Browser, CHALLENGE, CONTINUATION, ENROLL, ENROLLMENT, STEP_SECONDS,
                            code_at, early_step, enroll_totp, sessions)


def pending(host):
    browser = Browser(host)
    browser.login(destination=CHALLENGE)
    assert sessions.ADMIN not in browser.cookies, "First factor issued a local session ticket"
    browser.assert_pending()
    return browser


def exercise(temp):
    tls = sessions.provision(temp)
    with sessions.host(temp, tls) as host:
        Browser(host).request(ENROLLMENT, 401)
        enrollment_browser = Browser(host)
        enrollment_browser.login()

        # A valid password at the Unicode scalar limit must fit the encoded form.
        long_password = "\U0001f6e1" * 128
        enrollment_browser.post("/manage/users/create",
                                {"__RequestVerificationToken": enrollment_browser.token("/manage/users"),
                                 "userName": "fixture-unicode", "password": long_password, "role": "nergal:auditor"}, 302)
        unicode_user = Browser(host, secrets=(long_password,))
        unicode_user.post("/login", {**unicode_user.form("/login", "/login"),
                                     "username": "fixture-unicode", "password": long_password}, 302, destination="/session")
        unicode_user.request("/session", 200)

        enrollment_browser.request(ENROLL, 400, {})
        seed, enrollment_step = enroll_totp(enrollment_browser)
        no_proof = Browser(host)
        no_proof.request(CHALLENGE, 302)
        assert no_proof.location == "/login"
        browser = pending(host)
        browser.request(CHALLENGE, 400, {"code": "123456"})
        browser.assert_anonymous()

        step = early_step(after=enrollment_step)
        valid = {code_at(seed, step + offset) for offset in (-1, 0, 1)}
        stale = next(code_at(seed, step - offset) for offset in range(4, 9) if code_at(seed, step - offset) not in valid)
        wrong = next(f"{value:06d}" for value in range(834100, 834110) if f"{value:06d}" not in valid)
        for denial in (wrong, stale):
            denied = pending(host)
            denied.post(CHALLENGE, {**denied.form(CHALLENGE, CHALLENGE), "code": denial}, 401)
            denied.assert_anonymous()
            assert sessions.ADMIN not in denied.cookies

        browser = pending(host)
        form = browser.form(CHALLENGE, CHALLENGE)
        step = early_step(after=enrollment_step)
        current = code_at(seed, step)
        old_continuation = Browser(host)
        old_continuation.cookies.update(browser.cookies)
        browser.post(CHALLENGE, {**form, "code": current}, 302, destination="/session")
        assert CONTINUATION not in browser.cookies and sessions.ADMIN in browser.cookies
        browser.request("/session", 200)
        browser.request("/profile", 200)
        assert base64.b32encode(seed).decode() not in browser.request(ENROLLMENT, 200), "Enrolled seed was rendered again"
        old_continuation.post(CHALLENGE, {**form, "code": current}, 401)
        old_continuation.assert_anonymous()

        # Start another password proof in the same accepted time window. This detects
        # code reuse independently from replaying the consumed continuation above.
        replay = pending(host)
        replay_form = replay.form(CHALLENGE, CHALLENGE)
        assert int(time.time()) // STEP_SECONDS == step, "Fixture missed the TOTP replay window"
        replay.post(CHALLENGE, {**replay_form, "code": current}, 401)
        replay.assert_anonymous()
        browser.request("/session", 200)
    print("PASS: TOTP enrollment over HTTPS, pending authorization denial, bad/stale code denial, "
          "successful completion and denial of continuation and code replay")


if __name__ == "__main__":
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="nergal-totp-web-") as directory:
        exercise(Path(directory))
