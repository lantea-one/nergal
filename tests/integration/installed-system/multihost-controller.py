"""Assert the installed controller's browser and authenticated remote status contracts."""

from contextlib import closing
from http.client import HTTPSConnection
import json
from pathlib import Path
import runpy
import sqlite3
import ssl
import sys
import time


sys.path.insert(0, str(Path(__file__).resolve().parent / "reuse/local-sessions"))
from check import Browser


SETTINGS = runpy.run_path(str(Path(__file__).resolve().parent / "reuse/local-sessions/check-settings.py"))
TITLE = "Installed M7 recovery fixture"
POLICY_SUMMARY = "Preserve this reviewed fixture policy"
ORIGINAL_HOST = "fixture-original"
ENDPOINT = "192.0.2.2:9443"


def browser_session():
    tls = ssl.create_default_context(cafile="/etc/nergal/web/tls.crt")
    browser = Browser({"https": 8443}, tls)
    deadline = time.monotonic() + 30
    while True:
        try:
            browser.request("/healthz", 200)
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)
    browser.login(Path("/run/nergal-ops/password").read_text().strip())
    return browser


def mutate(browser, method, path, value, code):
    token = browser.token("/session")
    cookies = "; ".join(f"{name}={value}" for name, value in browser.cookies.items())
    with closing(HTTPSConnection("127.0.0.1", 8443, context=browser.tls, timeout=10)) as connection:
        connection.request(method, path, None if value is None else json.dumps(value), {
            "Content-Type": "application/json", "Cookie": cookies, "RequestVerificationToken": token,
        })
        response = connection.getresponse()
        body = response.read()
        assert response.status == code, f"{method} {path}: expected {code}, received {response.status}"
        return json.loads(body) if body else None


def probe(browser, host_id, expected, revision):
    path = f"/controller/apply/status?hostId={host_id}"
    status = json.loads(browser.request(path, 200))
    assert status["outcome"] == expected and status["revision"] == revision, status
    print(f"Controller observed {expected} with revision {revision}")


def save_state(browser):
    fields = SETTINGS["settings_fields"](browser)
    SETTINGS["post"](browser, {**fields, "applicationName": TITLE}, 302)
    desired = {"schemaVersion": 1, "filter": {
        "schemaVersion": 2, "inputDefaultVerdict": "accept", "forwardDefaultVerdict": "drop",
        "outputDefaultVerdict": "accept", "rules": [
            {"family": "ipv6", "protocol": "udp", "verdict": "drop", "chain": "input", "connectionStates": []},
        ],
    }}
    browser.request("/manage/policies/save", 302, {
        "bundleJson": json.dumps(desired), "summary": POLICY_SUMMARY,
        "__RequestVerificationToken": browser.token("/manage/policies"),
    })
    assert browser.location == "/manage/policies?revision=1"


def verify_persisted_state(browser, host_id, expected_pin):
    assert SETTINGS["settings_fields"](browser)["applicationName"] == TITLE
    hosts = json.loads(browser.request("/controller/hosts", 200))["hosts"]
    host, = hosts
    assert host["id"] == host_id and host["pinnedServerThumbprint"] == expected_pin
    audit = json.loads(browser.request("/controller/audit", 200))["entries"]
    assert any(event["action"] == "settings.update" for event in audit)
    assert any(event["target"] == ORIGINAL_HOST and event["action"] == "host.delete" for event in audit)
    policy, = json.loads(browser.request("/controller/policies", 200))["revisions"]
    assert policy["revision"] == "1" and policy["summary"] == POLICY_SUMMARY
    with closing(sqlite3.connect("file:/var/lib/nergal/web/controller/controller.db?mode=ro", uri=True)) as db:
        row = db.execute("SELECT reported_revision, observed_at_utc FROM host_observations WHERE host_id = ?",
                         (host_id,)).fetchone()
        assert row is not None and row[0] == "2" and row[1], "Missing previously saved authenticated observation"
    probe(browser, host_id, "matched", "2")
    print(f"POLICY_DIGEST={policy['candidateDigest']}")
    print("Controller verified settings, reviewed policy, stable host registration, audit and retained remote observation")


if __name__ == "__main__":
    command, *arguments = sys.argv[1:]
    browser = browser_session()
    if command == "register":
        name, pin = arguments
        host = mutate(browser, "POST", "/controller/hosts", {
            "name": name, "transportKind": "tls", "endpoint": ENDPOINT, "pinnedServerThumbprint": pin,
        }, 201)
        print(f"HOST_ID={host['id']}")
    elif command == "probe":
        host_id, expected, revision = arguments
        probe(browser, host_id, expected, None if revision == "none" else revision)
    elif command == "retire":
        host_id, = arguments
        mutate(browser, "DELETE", f"/controller/hosts/{host_id}", None, 204)
    elif command == "save":
        save_state(browser)
    elif command == "verify":
        verify_persisted_state(browser, *arguments)
    else:
        raise SystemExit("Unknown controller phase")
