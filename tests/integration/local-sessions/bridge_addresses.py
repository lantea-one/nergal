"""Real HTTPS bridge address selectors preserve complete L2/L3/graph intent and immutable history."""
import json
import sqlite3
from raw_forms import decode
from transport_references import PortFields


def check_bridge_addresses(browser, directory):
    with sqlite3.connect(directory / "controller.db") as db:
        before = db.execute("SELECT policy_json FROM policy_revisions WHERE revision=6").fetchone()[0]
        objects = {name: object_id for object_id, name in db.execute("SELECT id,name FROM reusable_objects")}
    bundle = json.loads(before)
    base = len(bundle["bridge"]["rules"])
    chain_index = len(bundle["bridge"]["subChains"])
    rules = [{"etherType": family, "verdict": "drop", "family": family, "bridgeName": "br0",
              "sourceMac": "02:00:00:00:00:01", "destinationMac": "02:00:00:00:00:02", "protocol": "tcp",
              "destinationPorts": [443, 9001], "enabled": False} for family in ("ipv4", "ipv6")]
    bundle["bridge"]["rules"].extend([{**rule, "jumpTarget": "services"} for rule in rules])
    bundle["bridge"]["subChains"].append({"name": "services", "rules": [{**rule, "return": True} for rule in rules]})
    current = json.dumps(bundle)
    token = browser.token("/manage/policies")
    common = {"__RequestVerificationToken": token}
    path = "/manage/policies/objects"

    def selected(b, scope, index):
        return b["bridge"]["rules"][index] if scope == "bridge" else b["bridge"]["subChains"][chain_index]["rules"][index]

    for scope in ("bridge", "bridgeChain"):
        for offset, family in enumerate(("ipv4", "ipv6")):
            index = base + offset if scope == "bridge" else offset
            chain = {} if scope == "bridge" else {"chain": "services"}
            for slot in ("source", "destination"):
                object_id = objects[f"nat_{slot}_{family}"]
                fields = {**common, **chain, "bundleJson": current, "ruleIndex": str(index), "scope": scope, "slot": slot,
                          "selection": object_id + "/1", "operation": "attach"}
                other = objects[f'nat_{slot}_{"ipv6" if family == "ipv4" else "ipv4"}']
                browser.request(path, 400, {**fields, "selection": other + "/1"})
                html = browser.request(path, 200, fields)
                current, parsed = decode(html)
                assert selected(parsed, scope, index)[slot + "Object"]["id"] == object_id
                inputs = PortFields(); inputs.feed(html)
                prefix = "forward" if scope == "bridge" else "services"
                field = inputs.fields[f"bridge-{prefix}-{index}-{slot}"]
                assert "readonly" in field and "name" not in field and field["value"]
            rule = selected(json.loads(current), scope, index)
            edit = {**common, **chain, "bundleJson": current, "ruleIndex": str(index), "operation": "edit", "etherType": family,
                    "family": family, "action": "jump" if scope == "bridge" else "return", "protocol": "tcp", "destinationPorts": "443,9001",
                    "bridgeName": "br0", "sourceMac": rule["sourceMac"], "destinationMac": rule["destinationMac"], "description": "Retained bridge pins"}
            if scope == "bridge":
                edit["jumpTarget"] = "services"
            current, parsed = decode(browser.request("/manage/policies/bridge/rule", 200, edit))
            after = selected(parsed, scope, index)
            for key in ("sourceObject", "destinationObject", "sourceMac", "destinationMac", "enabled", "destinationPorts"):
                assert after[key] == rule[key]
            browser.request("/manage/policies/bridge/rule", 400, {**edit, "family": "none"})
            browser.request("/manage/policies/bridge/rule", 400, {**edit, "source": "192.0.2.1" if family == "ipv4" else "2001:db8::1"})
            for slot in ("source", "destination"):
                _, removed = decode(browser.request(path, 200, {**common, **chain, "bundleJson": current, "ruleIndex": str(index),
                    "scope": scope, "slot": slot, "operation": "remove"}))
                remainder = selected(removed, scope, index)
                assert slot + "Object" not in remainder
                assert remainder["sourceMac"] == rule["sourceMac"] and remainder["destinationMac"] == rule["destinationMac"]
                assert remainder["enabled"] is False and remainder["family"] == family
                assert remainder["jumpTarget"] == "services" if scope == "bridge" else remainder["return"] is True
                forged = json.loads(current)
                selected(forged, scope, index)[slot + "Object"]["version"] = 2
                browser.request("/manage/policies/save", 400, {**common, "bundleJson": json.dumps(forged)})
    browser.request("/manage/policies/save", 302, {**common, "bundleJson": current, "summary": "Pinned bridge addresses"})
    for slot in ("source", "destination"):
        for offset, family in enumerate(("ipv4", "ipv6")):
            usage = browser.request("/manage/objects?objectId=" + objects[f"nat_{slot}_{family}"], 200)
            assert f"bridge.rules[{base + offset}].{slot}Object" in usage
            assert f"bridge.subChains[{chain_index}].rules[{offset}].{slot}Object" in usage
    with sqlite3.connect(directory / "controller.db") as db:
        assert db.execute("SELECT policy_json FROM policy_revisions WHERE revision=6").fetchone()[0] == before
        saved = db.execute("SELECT policy_json FROM policy_revisions WHERE revision=7").fetchone()[0]
        assert saved == current and db.execute("SELECT count(*) FROM policy_revisions").fetchone()[0] == 7
        assert json.loads(saved)["nat"] == json.loads(before)["nat"]
    print("PASS: dual-stack bridge address pins in both chains, MAC/graph/state retention, readonly fields, forged history denial and immutable SQL usage")
