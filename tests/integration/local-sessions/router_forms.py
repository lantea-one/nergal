"""HTTPS guided router forms reject malformed requests and preserve immutable rule intent."""
import json
import sqlite3
from policy_objects import Draft


def check_router_forms(browser, directory):
    with sqlite3.connect(directory / "controller.db") as db:
        original = db.execute("SELECT policy_json FROM policy_revisions WHERE revision=2").fetchone()[0]
    token = browser.token("/manage/policies")
    conditions = {"bundleJson": original, "ruleIndex": "0", "sourceMacs": "02:00:00:00:00:01",
                  "negateSourceMac": "true", "negateSource": "true", "rateLimitKey": "sourceAddress"}
    path = "/manage/policies/rules/conditions"
    browser.request(path, 400, conditions)  # CSRF is required independently of role.
    conditions["__RequestVerificationToken"] = token
    for bad in ({"ruleIndex": "oops"}, {"ruleIndex": "-1"}, {"extra": "x"}, {"negateSource": "false"},
                {"sourceMacs": "invalid"}, {"rateLimitKey": "unknown"}, {"negateInputInterface": "true"}):
        browser.request(path, 400, {**conditions, **bad})
    browser.request(path, 400, [*conditions.items(), ("negateSource", "true")])
    html = browser.request(path, 200, conditions)
    parsed = Draft(); parsed.feed(html)
    changed = json.loads(parsed.value)
    before = json.loads(original)["filter"]["rules"][0]
    after = changed["filter"]["rules"][0]
    assert after == {**before, "sourceMac": "02:00:00:00:00:01", "negateSourceMac": True, "negateSource": True}
    assert after["enabled"] is False and after["sourceObject"] == before["sourceObject"]
    assert "MAC &amp; negation" in html and 'name="rateLimitKey"' in html
    postrouting = {"bundleJson": parsed.value, "family": "ipv4", "action": "return", "source": "192.0.2.0/24",
                   "destination": "203.0.113.0/24", "negateDestination": "true", "inputInterface": "lan0", "outputInterface": "wan0",
                   "protocol": "tcp", "destinationPorts": "443,9001", "__RequestVerificationToken": token}
    path = "/manage/policies/nat/postrouting"
    for bad in ({"ruleIndex": ""}, {"ruleIndex": "-1"}, {"action": "unknown"}, {"translatedAddress": "198.51.100.1"},
                {"protocol": "any"}, {"negateOutputInterface": "False"}, {"extra": "x"}):
        browser.request(path, 400, {**postrouting, **bad})
    browser.request(path, 400, [*postrouting.items(), ("action", "masquerade")])
    result = browser.request(path, 200, postrouting)
    draft = Draft(); draft.feed(result)
    bundle = json.loads(draft.value)
    rule = bundle["nat"]["snatRules"][-1]
    assert rule["action"] == "return" and rule["inputInterface"] == "lan0" and rule["destinationPorts"] == [443, 9001]
    assert 'name="action"' in result and "Return — translation exemption" in result
    # Edit the same entry, rather than appending another. Blank translation remains explicit.
    html = browser.request(path, 200, {**postrouting, "bundleJson": draft.value, "ruleIndex": str(len(bundle["nat"]["snatRules"]) - 1), "action": "masquerade"})
    edited = Draft(); edited.feed(html)
    updated = json.loads(edited.value)
    assert len(updated["nat"]["snatRules"]) == len(bundle["nat"]["snatRules"])
    assert updated["nat"]["snatRules"][-1]["action"] == "masquerade"
    assert updated["filter"] == changed["filter"]
    with sqlite3.connect(directory / "controller.db") as db:
        assert db.execute("SELECT policy_json FROM policy_revisions WHERE revision=2").fetchone()[0] == original
        assert db.execute("SELECT count(*) FROM policy_revisions").fetchone()[0] == 2
    print("PASS: guided MAC/negation and complete postrouting forms, CSRF, malformed input, pins/state and unsaved revisions")
