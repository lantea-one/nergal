"""Auxiliary list selection pins the submitted version and never edits the primary matcher implicitly."""
import json
import sqlite3
from raw_forms import decode


def check_auxiliary_references(browser, directory):
    with sqlite3.connect(directory / "controller.db") as db:
        original = db.execute("SELECT policy_json FROM policy_revisions WHERE revision=3").fetchone()[0]
        object_id = db.execute("SELECT id FROM reusable_objects WHERE name='trusted_clients'").fetchone()[0]
    b = json.loads(original)
    b["auxiliaryFilter"] = {"priority": -5, "filter": {"schemaVersion": 2, "inputDefaultVerdict": "accept", "forwardDefaultVerdict": "accept", "outputDefaultVerdict": "accept", "rules": [
        {"family": "ipv4", "protocol": "tcp", "verdict": "drop", "chain": "input", "source": "192.0.2.0/24", "negateSource": True, "sourceMac": "02:00:00:00:00:01", "enabled": False}]}}
    fields = {"bundleJson": json.dumps(b), "scope": "auxiliary", "ruleIndex": "0", "slot": "source", "selection": object_id + "/2", "operation": "attach", "__RequestVerificationToken": browser.token("/manage/policies")}
    path = "/manage/policies/objects"
    for bad in ({"scope": "unknown"}, {"scope": ""}, {"ruleIndex": "1"}, {"slot": "ports"}):
        browser.request(path, 400, {**fields, **bad})
    browser.request(path, 400, [*fields.items(), ("scope", "primary")])
    html = browser.request(path, 200, fields)
    attached, after = decode(html)
    assert "Primary inet references" in html and "Auxiliary inet references" in html
    assert 'id="reference-primary-rule"' in html and 'id="reference-auxiliary-rule"' in html
    assert after["filter"] == b["filter"] and after["bridge"] == b["bridge"]
    rule = after["auxiliaryFilter"]["filter"]["rules"][0]
    assert rule["sourceObject"]["version"] == 2 and rule["sourceObject"]["entries"] == ["203.0.113.10/32"]
    assert rule["enabled"] is False and rule["negateSource"] is True and rule["sourceMac"] == "02:00:00:00:00:01" and "source" not in rule
    # Omitted scope retains the original primary-only API contract; query data cannot select a different table.
    legacy = {k: v for k, v in fields.items() if k != "scope"}
    legacy["selection"] = object_id + "/3"
    _, defaulted = decode(browser.request(path + "?scope=auxiliary", 200, legacy))
    assert defaulted["filter"]["rules"][0]["sourceObject"]["version"] == 3
    assert defaulted["auxiliaryFilter"] == b["auxiliaryFilter"]
    browser.request("/manage/policies/save", 302, {"bundleJson": attached, "summary": "Pin auxiliary static list", "__RequestVerificationToken": browser.token("/manage/policies")})
    usage = browser.request("/manage/objects?objectId=" + object_id, 200)
    assert "auxiliaryFilter.filter.rules[0].sourceObject" in usage
    browser.request("/manage/objects/save", 302, {"id": object_id, "expectedVersion": "3", "name": "trusted_clients", "kind": "ipv4", "description": "Later contents", "entries": "198.51.100.99", "__RequestVerificationToken": browser.token("/manage/objects")})
    with sqlite3.connect(directory / "controller.db") as db:
        assert db.execute("SELECT policy_json FROM policy_revisions WHERE revision=3").fetchone()[0] == original
        saved = json.loads(db.execute("SELECT policy_json FROM policy_revisions WHERE revision=4").fetchone()[0])
        assert saved["auxiliaryFilter"]["filter"]["rules"][0] == rule
    _, removed = decode(browser.request(path, 200, {**fields, "bundleJson": attached, "operation": "remove"}))
    cleared = removed["auxiliaryFilter"]["filter"]["rules"][0]
    assert "sourceObject" not in cleared and "source" not in cleared and "negateSource" not in cleared and cleared["enabled"] is False
    assert removed["filter"] == b["filter"]
    print("PASS: auxiliary list selector, explicit scope, immutable version/usage, dormant MAC/IP intent and legacy primary-only behavior")
