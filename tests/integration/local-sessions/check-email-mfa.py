"""Exercise email verification and replay-safe sign-in through real SMTP STARTTLS."""
import os
from pathlib import Path
import re
import tempfile

from identity_https import Browser, CHALLENGE, CONTINUATION, sessions
from mfa_mail import relay


SETTINGS = "/manage/identity/email-delivery"
SAVE = SETTINGS + "/save"
ENROLLMENT = "/profile/mfa/email"
BEGIN = ENROLLMENT + "/begin"
CONFIRM = ENROLLMENT + "/confirm"
ADDRESS = "factor@example.test"
PROFILE_ADDRESS = "profile-only@example.test"


def save_relay(admin, server):
    form = admin.form(SETTINGS, SAVE)
    values = {**form, "enabled": "true", "host": "127.0.0.1", "port": str(server.server_address[1]),
              "fromAddress": "relay@example.test", "userName": "", "password": ""}
    admin.post(SAVE, values, 302, destination=SETTINGS)


def sign_in(browser, expected, destination=None):
    return browser.post("/login", {**browser.form("/login", "/login"),
                         "username": "fixture-mail-user", "password": sessions.PASSWORD},
                        expected, destination=destination)


def delivered_code(server):
    recipient, message = server.messages.get(timeout=8)
    assert recipient == f"TO:<{ADDRESS}>", "SMTP destination did not match the independently supplied address"
    assert message["To"] == ADDRESS and PROFILE_ADDRESS not in str(message)
    code = re.search(r"\b[0-9]{6}\b", message.get_content())
    assert code, "The relay did not receive a verification code"
    return code.group()


def exercise(directory):
    tls = sessions.provision(directory)
    with relay(directory) as (server, certificate):
        with sessions.host(directory, tls, {"SSL_CERT_FILE": str(certificate)}) as host:
            admin = Browser(host)
            admin.login()
            save_relay(admin, server)
            admin.post("/manage/users/create",
                       {"__RequestVerificationToken": admin.token("/manage/users"), "userName": "fixture-mail-user",
                        "password": sessions.PASSWORD, "role": "nergal:auditor"}, 302)
            user = Browser(host)
            sign_in(user, 302, "/session")
            profile = user.form("/profile", "/profile/save")
            user.post("/profile/save", {**profile, "email": PROFILE_ADDRESS}, 302, destination="/profile")
            assert server.messages.empty(), "Saving profile email sent a factor code"

            page = user.post(BEGIN, {**user.form(ENROLLMENT, BEGIN), "address": ADDRESS}, 200)
            from identity_https import forms_in
            enrollment = forms_in(page)[CONFIRM]
            code = delivered_code(server)
            user.post(CONFIRM, {**enrollment, "code": code}, 302, destination="/login")
            user.assert_anonymous()

            verified = Browser(host)
            sign_in(verified, 302, CHALLENGE)
            verified.assert_pending()
            assert sessions.ADMIN not in verified.cookies
            form = verified.form(CHALLENGE, CHALLENGE)
            code = delivered_code(server)
            wrong = "000000" if code != "000000" else "000001"
            verified.post(CHALLENGE, {**form, "code": wrong}, 401)
            verified.assert_pending()
            replay = Browser(host)
            replay.cookies.update(verified.cookies)
            verified.post(CHALLENGE, {**form, "code": code}, 302, destination="/session")
            assert CONTINUATION not in verified.cookies
            verified.request("/session", 200)
            replay.post(CHALLENGE, {**form, "code": code}, 401)
            replay.assert_anonymous()
            assert server.plaintext_commands.empty()

            unavailable = directory / "no-starttls"
            unavailable.mkdir(mode=0o700)
            with relay(unavailable, starttls=False) as (plain, _):
                save_relay(admin, plain)
                denied = Browser(host)
                sign_in(denied, 401)
                denied.assert_anonymous()
                assert CONTINUATION not in denied.cookies
                assert plain.messages.empty() and plain.plaintext_commands.empty()
                independent = Browser(host)
                independent.login()
                independent.request("/session", 200)
    print("PASS: SMTP STARTTLS, independent address verification, email MFA, replay denial and local recovery during relay failure")


if __name__ == "__main__":
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="nergal-email-mfa-") as root:
        exercise(Path(root))
