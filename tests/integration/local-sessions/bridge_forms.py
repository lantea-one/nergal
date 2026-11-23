"""Real bridge UI forms preserve complete matching/control flow and reject unsafe graph or binder fallbacks."""
import json
import sqlite3
from raw_forms import decode


def check_bridge_forms(browser, directory):
    with sqlite3.connect(directory / "controller.db") as db:
        original = db.execute("SELECT policy_json FROM policy_revisions WHERE revision=2").fetchone()[0]
    common = {"bundleJson": original, "__RequestVerificationToken": browser.token("/manage/policies")}
    path = "/manage/policies/bridge/settings"
    fields = {**common, "operation": "set", "priority": "-5", "verdict": "drop"}
    browser.request(path, 400, {k: v for k, v in fields.items() if k != "__RequestVerificationToken"})
    for bad in ({"priority": "oops"}, {"priority": "301"}, {"verdict": "reject"}, {"extra": "x"}):
        browser.request(path, 400, {**fields, **bad})
    table, b = decode(browser.request(path, 200, fields))
    assert b["bridge"]["priority"] == -5
    path = "/manage/policies/bridge/chain"
    for bad in ({"name": "forward"}, {"name": "bad;command"}, {"operation": "unknown"}, {"extra": "x"}):
        browser.request(path, 400, {**common, "bundleJson": table, "operation": "add", "name": "mail", **bad})
    chain, b = decode(browser.request(path, 200, {**common, "bundleJson": table, "operation": "add", "name": "mail"}))
    path = "/manage/policies/bridge/rule"
    rule_fields = {**common, "bundleJson": chain, "operation": "add", "chain": "mail", "etherType": "ipv4", "action": "return",
                   "family": "ipv4", "source": "192.0.2.0/24", "destination": "198.51.100.0/24", "protocol": "tcp", "destinationPorts": "80,443",
                   "bridgeName": "br0", "sourceMac": "02:00:00:00:00:01", "destinationMac": "02:00:00:00:00:02", "negateDestinationMac": "true"}
    for bad in ({"chain": "unknown"}, {"chain": ""}, {"ruleIndex": ""}, {"action": "goto"}, {"action": "jump", "jumpTarget": "mail"},
                {"family": "none"}, {"protocol": "any"}, {"sourceMac": "invalid"}, {"negateDestinationMac": "false"}, {"extra": "x"}):
        browser.request(path, 400, {**rule_fields, **bad})
    browser.request(path, 400, [*rule_fields.items(), ("action", "accept")])
    returned, b = decode(browser.request(path, 200, rule_fields))
    jump_fields = {**rule_fields, "bundleJson": returned, "chain": "", "action": "jump", "jumpTarget": "mail"}
    html = browser.request(path, 200, jump_fields)
    jumped, b = decode(html)
    assert "Bridge matchers and action" in html and "Regular chain: mail" in html
    assert b["bridge"]["rules"][0]["jumpTarget"] == "mail" and b["bridge"]["subChains"][0]["rules"][0]["return"] is True
    assert {k: v for k, v in b.items() if k != "bridge"} == json.loads(original)
    disabled, b = decode(browser.request("/manage/policies/rules/state", 200, {**common, "bundleJson": jumped, "scope": "BridgeChain", "chain": "mail", "ruleIndex": "0"}))
    edited, b = decode(browser.request(path, 200, {**rule_fields, "bundleJson": disabled, "operation": "edit", "ruleIndex": "0", "description": "Dormant return"}))
    assert b["bridge"]["subChains"][0]["rules"][0]["enabled"] is False
    second, b = decode(browser.request(path, 200, {**rule_fields, "bundleJson": edited, "action": "accept"}))
    moved, b = decode(browser.request(path, 200, {**common, "bundleJson": second, "chain": "mail", "operation": "up", "ruleIndex": "1"}))
    assert b["bridge"]["subChains"][0]["rules"][1]["enabled"] is False
    # Save an immutable graph for the Auditor's read-only UI checks after host restart.
    browser.request("/manage/policies/save", 302, {**common, "bundleJson": moved, "summary": "Synthetic bridge graph"})
    browser.request("/manage/policies/bridge/chain", 400, {**common, "bundleJson": moved, "operation": "remove", "name": "mail"})
    one, b = decode(browser.request(path, 200, {**common, "bundleJson": moved, "chain": "mail", "operation": "remove", "ruleIndex": "1"}))
    empty, b = decode(browser.request(path, 200, {**common, "bundleJson": one, "chain": "mail", "operation": "remove", "ruleIndex": "0"}))
    browser.request("/manage/policies/bridge/chain", 400, {**common, "bundleJson": empty, "operation": "remove", "name": "mail"})
    no_jump, b = decode(browser.request(path, 200, {**common, "bundleJson": empty, "operation": "remove", "ruleIndex": "0"}))
    no_chain, b = decode(browser.request("/manage/policies/bridge/chain", 200, {**common, "bundleJson": no_jump, "operation": "remove", "name": "mail"}))
    removed, b = decode(browser.request("/manage/policies/bridge/settings", 200, {**common, "bundleJson": no_chain, "operation": "remove"}))
    assert b == json.loads(original)
    with sqlite3.connect(directory / "controller.db") as db:
        assert db.execute("SELECT policy_json FROM policy_revisions WHERE revision=2").fetchone()[0] == original
        saved = json.loads(db.execute("SELECT policy_json FROM policy_revisions WHERE revision=3").fetchone()[0])
        assert saved["bridge"]["subChains"][0]["rules"][1]["enabled"] is False
    print("PASS: complete bridge L2/L3/L4 forms, local jump/return graph, dormant edits/order, immutable save and missing/cyclic target denial")
