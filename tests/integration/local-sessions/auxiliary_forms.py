"""Auxiliary UI forms validate complete draft semantics and retain unrelated immutable intent."""
import json
import sqlite3
from raw_forms import decode


def check_auxiliary_forms(browser, directory):
    with sqlite3.connect(directory / "controller.db") as db:
        original = db.execute("SELECT policy_json FROM policy_revisions WHERE revision=2").fetchone()[0]
    common = {"bundleJson": original, "__RequestVerificationToken": browser.token("/manage/policies")}
    path = "/manage/policies/auxiliary/defaults"
    settings = {**common, "operation": "set", "priority": "-5", "inputDefault": "accept", "forwardDefault": "accept", "outputDefault": "accept"}
    browser.request(path, 400, {k: v for k, v in settings.items() if k != "__RequestVerificationToken"})
    for bad in ({"priority": "oops"}, {"priority": "-301"}, {"inputDefault": "reject"}, {"operation": "unknown"}, {"extra": "x"}):
        browser.request(path, 400, {**settings, **bad})
    browser.request(path, 400, [*settings.items(), ("priority", "0")])
    configured, b = decode(browser.request(path, 200, settings))
    assert b["auxiliaryFilter"]["priority"] == -5 and b["auxiliaryFilter"]["filter"]["rules"] == []
    path = "/manage/policies/auxiliary/rule"
    fields = {**common, "bundleJson": configured, "operation": "add", "chain": "input", "family": "ipv4", "protocol": "tcp", "verdict": "reject",
              "sources": "192.0.2.0/24", "destinationPorts": "443", "inputInterface": "lan0", "connectionStates": "new",
              "sourceMacs": "02:00:00:00:00:01", "negateSourceMac": "true", "negateSource": "true", "rateLimitPackets": "10",
              "rateLimitBurst": "20", "rateLimitUnit": "second", "rateLimitTimeout": "60", "rateLimitKey": "destinationAddress"}
    for bad in ({"ruleIndex": ""}, {"sourceMacs": "invalid"}, {"protocol": "any"}, {"rateLimitPackets": "bad"}, {"negateSource": "false"},
                {"rateLimitKey": "unknown"}, {"negateDestination": "true"}, {"extra": "x"}):
        browser.request(path, 400, {**fields, **bad})
    html = browser.request(path, 200, fields)
    added, b = decode(html)
    assert 'name="rateLimitKey"' in html and "Auxiliary rule 1" in html
    assert {k: v for k, v in b.items() if k != "auxiliaryFilter"} == json.loads(original)
    rule = b["auxiliaryFilter"]["filter"]["rules"][0]
    assert rule["rateLimit"]["keyKind"] == "destinationAddress" and rule["sourceMac"] == "02:00:00:00:00:01"
    browser.request("/manage/policies/auxiliary/defaults", 400, {**common, "bundleJson": added, "operation": "remove"})
    disabled, b = decode(browser.request("/manage/policies/rules/state", 200, {**common, "bundleJson": added, "scope": "Auxiliary", "ruleIndex": "0"}))
    edited, b = decode(browser.request(path, 200, {**fields, "bundleJson": disabled, "operation": "edit", "ruleIndex": "0", "description": "Dormant restriction"}))
    assert b["auxiliaryFilter"]["filter"]["rules"][0]["enabled"] is False
    second, b = decode(browser.request(path, 200, {**fields, "bundleJson": edited}))
    moved, b = decode(browser.request(path, 200, {**common, "bundleJson": second, "operation": "up", "ruleIndex": "1"}))
    assert b["auxiliaryFilter"]["filter"]["rules"][1]["enabled"] is False
    one, b = decode(browser.request(path, 200, {**common, "bundleJson": moved, "operation": "remove", "ruleIndex": "1"}))
    empty, b = decode(browser.request(path, 200, {**common, "bundleJson": one, "operation": "remove", "ruleIndex": "0"}))
    removed, b = decode(browser.request("/manage/policies/auxiliary/defaults", 200, {**common, "bundleJson": empty, "operation": "remove"}))
    assert b == json.loads(original)
    with sqlite3.connect(directory / "controller.db") as db:
        assert db.execute("SELECT policy_json FROM policy_revisions WHERE revision=2").fetchone()[0] == original
        assert db.execute("SELECT count(*) FROM policy_revisions").fetchone()[0] == 2
    print("PASS: auxiliary table defaults/priority/full matchers, dormant state, ordering, explicit removal and unchanged unrelated revisions")
