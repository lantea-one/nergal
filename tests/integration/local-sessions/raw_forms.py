"""Real HTTPS raw/MSS/DNAT forms preserve state and reject binder fallbacks or hidden broadening."""
import json
import sqlite3
from policy_objects import Draft


def decode(html):
    parsed = Draft(); parsed.feed(html)
    return parsed.value, json.loads(parsed.value)


def check_raw_forms(browser, directory):
    with sqlite3.connect(directory / "controller.db") as db:
        original = db.execute("SELECT policy_json FROM policy_revisions WHERE revision=2").fetchone()[0]
    token = browser.token("/manage/policies")
    common = {"bundleJson": original, "__RequestVerificationToken": token}
    path = "/manage/policies/raw/rule"
    fields = {**common, "operation": "add", "family": "ipv4", "protocol": "udp", "verdict": "accept", "sourcePort": "68", "description": "DHCP"}
    browser.request(path, 400, {k: v for k, v in fields.items() if k != "__RequestVerificationToken"})
    for bad in ({"operation": "edit"}, {"ruleIndex": ""}, {"sourcePort": "oops"}, {"sourcePort": "65536"},
                {"protocol": "any"}, {"matchFibUnreachable": "false"}, {"extra": "x"}):
        browser.request(path, 400, {**fields, **bad})
    browser.request(path, 400, [*fields.items(), ("verdict", "drop")])
    first, b = decode(browser.request(path, 200, fields))
    assert b["filter"]["rpFilter"]["rules"][0]["sourcePort"] == 68
    second, b = decode(browser.request(path, 200, {**common, "bundleJson": first, "operation": "add", "family": "any", "protocol": "any", "verdict": "drop", "matchFibUnreachable": "true"}))
    moved, b = decode(browser.request(path, 200, {**common, "bundleJson": second, "operation": "up", "ruleIndex": "1"}))
    assert b["filter"]["rpFilter"]["rules"][0]["matchFibUnreachable"] is True
    browser.request("/manage/policies/raw/default", 400, {**common, "bundleJson": moved, "verdict": "remove"})
    # Restore exception order and retain the FIB drop while disabling it.
    ordered, b = decode(browser.request(path, 200, {**common, "bundleJson": moved, "operation": "down", "ruleIndex": "0"}))
    disabled, b = decode(browser.request("/manage/policies/rules/state", 200, {**common, "bundleJson": ordered, "scope": "Raw", "ruleIndex": "1"}))
    edited, b = decode(browser.request(path, 200, {**common, "bundleJson": disabled, "operation": "edit", "ruleIndex": "1", "family": "any", "protocol": "any", "verdict": "drop", "matchFibUnreachable": "true", "description": "Dormant reverse-path rule"}))
    assert b["filter"]["rpFilter"]["rules"][1]["enabled"] is False
    defaulted, b = decode(browser.request("/manage/policies/raw/default", 200, {**common, "bundleJson": edited, "verdict": "drop"}))
    assert b["filter"]["rpFilter"]["defaultVerdict"] == "drop" and len(b["filter"]["rpFilter"]["rules"]) == 2
    path = "/manage/policies/mss"
    for bad in ({"size": ""}, {"size": "1.5"}, {"size": "1461"}, {"operation": "unknown"}, {"extra": "x"}):
        browser.request(path, 400, {**common, "operation": "set", "size": "1360", **bad})
    clamp, b = decode(browser.request(path, 200, {**common, "bundleJson": defaulted, "operation": "set", "size": "1360"}))
    off, b = decode(browser.request("/manage/policies/rules/state", 200, {**common, "bundleJson": clamp, "scope": "Mss", "ruleIndex": "0"}))
    resized, b = decode(browser.request(path, 200, {**common, "bundleJson": off, "operation": "set", "size": "1400"}))
    assert b["filter"]["forwardTcpMssClamp"] == 1400 and b["filter"]["forwardTcpMssClampEnabled"] is False
    cleared, b = decode(browser.request(path, 200, {**common, "bundleJson": resized, "operation": "remove"}))
    assert "forwardTcpMssClamp" not in b["filter"] and "forwardTcpMssClampEnabled" not in b["filter"]
    # Add a source-restricted translation through the existing basic builder, then negate it explicitly.
    dnat, b = decode(browser.request("/manage/policies/nat/dnat/add", 200, {**common, "bundleJson": cleared, "family": "ipv4", "protocol": "tcp", "originalDestination": "192.0.2.1/32", "translatedAddress": "198.51.100.1", "source": "203.0.113.0/24", "inputInterface": "wan0", "originalPort": "443", "translatedPort": "8443"}))
    path = "/manage/policies/nat/dnat/conditions"
    for bad in ({"ruleIndex": "oops"}, {"ruleIndex": "-1"}, {"negateSource": "false"}, {"extra": "x"}):
        browser.request(path, 400, {**common, "bundleJson": dnat, "ruleIndex": "0", **bad})
    result_html = browser.request(path, 200, {**common, "bundleJson": dnat, "ruleIndex": "0", "negateSource": "true", "negateDestination": "true", "negateInputInterface": "true"})
    assert all(value in result_html for value in ("!= 203.0.113.0/24", "!= wan0", "!= 192.0.2.1/32"))
    result, b = decode(result_html)
    rule = b["nat"]["dnatRules"][0]
    assert all(rule[x] for x in ("negateSource", "negateDestination", "negateInputInterface"))
    assert rule["translatedPort"] == 8443 and rule["originalPort"] == 443
    assert b["filter"]["rules"] == json.loads(original)["filter"]["rules"]
    # Reorder complete DNAT entries, including a dormant rule, without changing their contents.
    b["nat"]["dnatRules"].append({**rule, "description": "Second", "enabled": False})
    baseline = json.dumps(b)
    path = "/manage/policies/nat/move"
    movement = {**common, "bundleJson": baseline, "kind": "dnat", "ruleIndex": "1", "direction": "-1"}
    for bad in ({"ruleIndex": "oops"}, {"direction": "2"}, {"kind": "unknown"}, {"ruleIndex": "0"}, {"extra": "x"}):
        browser.request(path, 400, {**movement, **bad})
    moved, b = decode(browser.request(path, 200, movement))
    assert b["nat"]["dnatRules"][0]["description"] == "Second" and b["nat"]["dnatRules"][0]["enabled"] is False
    assert b["nat"]["dnatRules"][1] == rule
    with sqlite3.connect(directory / "controller.db") as db:
        assert db.execute("SELECT policy_json FROM policy_revisions WHERE revision=2").fetchone()[0] == original
        assert db.execute("SELECT count(*) FROM policy_revisions").fetchone()[0] == 2
    print("PASS: guided raw/FIB/UDP source-port ordering, dormant MSS resize, explicit removal, DNAT negation and denied malformed forms")
