"""Exercise Administrator and offline authenticator recovery over disposable HTTPS."""
import base64
import os
from pathlib import Path
import pty
import re
import select
import subprocess
import tempfile

from identity_https import (Browser, CHALLENGE, CONTINUATION, CSRF,
                            code_at, early_step, enroll_totp, forms_in, sessions)


POLICY = "/manage/identity/mfa"
SAVE_POLICY = POLICY + "/save"
ISSUE = POLICY + "/recovery"
RECOVERY = "/login/recovery"
BEGIN = RECOVERY + "/local"
CONFIRM = RECOVERY + "/confirm"
RECOVERY_COOKIE = "__Host-nergal-recovery"
ADMIN = "fixture-admin"
RECIPIENT = "fixture-recovery-recipient"
RECIPIENT_PASSWORD = "synthetic recovery recipient password 0002"
GRANT = r"[0-9A-Fa-f]{64}"


def browser_for(host):
    return Browser(host, secrets=(RECIPIENT_PASSWORD,))


def password_step(browser, username, password, expected, *, destination=None):
    form = browser.form("/login", "/login")
    browser.post("/login", {**form, "username": username, "password": password}, expected,
                 destination=destination)


def sign_in_with_totp(browser, username, password, seed, *, after):
    password_step(browser, username, password, 302, destination=CHALLENGE)
    browser.assert_pending()
    assert sessions.ADMIN not in browser.cookies, "Only the password step completed"
    form = browser.form(CHALLENGE, CHALLENGE)
    step = early_step(after=after)
    browser.post(CHALLENGE, {**form, "code": code_at(seed, step)}, 302, destination="/session")
    assert CONTINUATION not in browser.cookies and sessions.ADMIN in browser.cookies
    assert f"<strong>{username}</strong>" in browser.request("/session", 200), "Signed in as the wrong actor"
    return step


def assert_recovery_only(browser, *, pending):
    assert (RECOVERY_COOKIE in browser.cookies) == pending, "Unexpected recovery cookie state"
    assert sessions.ADMIN not in browser.cookies and CONTINUATION not in browser.cookies, "Recovery issued a sign-in cookie"
    browser.assert_anonymous()


def submit_grant(browser, grant, username, password, expected):
    form = browser.form(RECOVERY, BEGIN)
    page = browser.post(BEGIN, {**form, "authorization": grant, "username": username, "password": password}, expected)
    assert grant not in page, "Recovery response echoed the authorization"
    return page


def recover(browser, grant, username, password):
    setup = submit_grant(browser, grant, username, password, 200)
    assert_recovery_only(browser, pending=True)
    keys = re.findall(r"<code>([A-Z2-7]{32})</code>", setup)
    assert len(keys) == 1, "Expected exactly one replacement setup key"
    seed = base64.b32decode(keys[0])
    forms = forms_in(setup)
    assert CONFIRM in forms and forms[CONFIRM].get(CSRF), "Recovery confirmation form is missing"
    step = early_step()
    browser.post(CONFIRM, {**forms[CONFIRM], "code": code_at(seed, step)}, 302, destination="/login")
    assert_recovery_only(browser, pending=False)
    return seed, step


def recipient_id(page, username):
    match = re.search(r'<option value="local:([0-9a-f-]{36})">' + re.escape(username) + r"</option>", page)
    assert match, f"Recovery form did not list {username}"
    return match.group(1)


def online_recovery(host):
    admin = browser_for(host)
    admin.login()
    create = admin.form("/manage/users", "/manage/users/create")
    admin.post("/manage/users/create", {**create, "userName": RECIPIENT, "password": RECIPIENT_PASSWORD,
                                        "role": "nergal:auditor"}, 302, destination="/manage/users")
    seed, step = enroll_totp(admin)
    admin = browser_for(host)
    step = sign_in_with_totp(admin, ADMIN, sessions.PASSWORD, seed, after=step)
    admin.post(SAVE_POLICY, {**admin.form(POLICY, SAVE_POLICY), "requirement": "All"}, 302, destination=POLICY)

    # A correct password for an unenrolled recipient cannot enter the application or start ordinary MFA.
    recipient = browser_for(host)
    password_step(recipient, RECIPIENT, RECIPIENT_PASSWORD, 401)
    assert_recovery_only(recipient, pending=False)
    recipient.request(ISSUE, 401)

    admin = browser_for(host)
    sign_in_with_totp(admin, ADMIN, sessions.PASSWORD, seed, after=step)
    page = admin.request(ISSUE, 200)
    admin_id = recipient_id(page, ADMIN)
    target_id = recipient_id(page, RECIPIENT)
    forms = forms_in(page)
    assert ISSUE in forms and forms[ISSUE].get(CSRF), "Recovery issuance form is missing"
    issued = admin.post(ISSUE, {**forms[ISSUE], "actorId": "local:" + target_id}, 200)
    grants = re.findall(r'<code class="text-break">(' + GRANT + r")</code>", issued)
    assert len(grants) == 1, "Administrator issuance did not render exactly one grant"
    grant = grants[0]

    # Valid credentials for the Administrator still cannot use the Auditor's grant.
    other_actor = browser_for(host)
    submit_grant(other_actor, grant, ADMIN, sessions.PASSWORD, 401)
    assert_recovery_only(other_actor, pending=False)

    replacement, activated = recover(recipient, grant, RECIPIENT, RECIPIENT_PASSWORD)
    replay = browser_for(host)
    submit_grant(replay, grant, RECIPIENT, RECIPIENT_PASSWORD, 401)
    assert_recovery_only(replay, pending=False)
    sign_in_with_totp(recipient, RECIPIENT, RECIPIENT_PASSWORD, replacement, after=activated)
    recipient.request(ISSUE, 403)
    return admin_id, target_id


def terminal_recover(command, expected):
    """Give stdout a real terminal while keeping the authorization out of fixture logs."""
    master, slave = pty.openpty()
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=slave, stderr=subprocess.PIPE, timeout=10)
        transcript = bytearray()
        while select.select([master], [], [], 0)[0]:
            transcript.extend(os.read(master, 4096))
        assert result.returncode == expected, f"Offline recovery returned {result.returncode}, expected {expected}"
        return transcript.decode(), result.stderr
    finally:
        os.close(slave)
        os.close(master)


def issue_offline(directory, admin_id, target_id):
    command = ["dotnet", str(sessions.ADMIN_TOOL), "account", "recover", str(directory / "accounts")]
    redirected = subprocess.run(command + [admin_id], stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
    assert redirected.returncode == 2 and redirected.stderr.strip() == b"recovery.terminalAndAccountRequired"
    assert not redirected.stdout, "Offline recovery printed a grant to redirected stdout"

    denied, diagnostic = terminal_recover(command + [target_id], 1)
    assert not denied and diagnostic.strip() == b"recovery.denied", "Offline recovery must deny the Auditor"
    issued, diagnostic = terminal_recover(command + [admin_id], 0)
    grants = re.findall(r"^" + GRANT + r"$", issued.replace("\r\n", "\n"), re.MULTILINE)
    assert len(grants) == 1 and not diagnostic, "Offline recovery did not render one grant on the terminal"
    return grants[0]


def exercise(directory):
    tls = sessions.provision(directory)
    with sessions.host(directory, tls) as host:
        admin_id, target_id = online_recovery(host)

    # The bootstrap user is the only Administrator. The operator uses the private store with the web host down.
    grant = issue_offline(directory, admin_id, target_id)
    with sessions.host(directory, tls) as host:
        admin = browser_for(host)
        replacement, activated = recover(admin, grant, ADMIN, sessions.PASSWORD)
        sign_in_with_totp(admin, ADMIN, sessions.PASSWORD, replacement, after=activated)

    print("PASS: enforced MFA, actor-bound recovery, confirmation without a session, grant replay denial, "
          "ordinary MFA with the replacement authenticator, and offline recovery of the only Administrator")


if __name__ == "__main__":
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="nergal-recovery-web-") as root:
        exercise(Path(root))
