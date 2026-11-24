"""DNAT address pins preserve translation, original ports, negation and immutable SQL history through real HTTPS."""
import json
import sqlite3
from raw_forms import decode
from transport_references import PortFields


def check_dnat_addresses(browser, directory):
    with sqlite3.connect(directory / "controller.db") as db:
        before = db.execute("SELECT policy_json FROM policy_revisions WHERE revision=8").fetchone()[0]
        objects = {name: object_id for object_id, name in db.execute("SELECT id,name FROM reusable_objects")}
    current = before
    token = browser.token("/manage/policies")
    common = {"__RequestVerificationToken": token}
    path = "/manage/policies/objects"
    for index, family in enumerate(("ipv4", "ipv6")):
        for slot in ("source", "destination"):
            fields = {**common, "bundleJson": current, "ruleIndex": str(index), "scope": "dnat", "slot": slot,
                      "selection": objects[f"nat_{slot}_{family}"] + "/1", "operation": "attach"}
            wrong_family = "ipv6" if family == "ipv4" else "ipv4"
            for bad in ({"selection": objects[f"nat_{slot}_{wrong_family}"] + "/1"}, {"selection": objects["web_ports"] + "/1"}, {"chain": "mail"}, {"ruleIndex": "-1"}):
                browser.request(path, 400, {**fields, **bad})
            html = browser.request(path, 200, fields)
            current, parsed = decode(html)
            rule = parsed["nat"]["dnatRules"][index]
            assert rule[slot + "Object"]["id"] == objects[f"nat_{slot}_{family}"]
            inputs = PortFields(); inputs.feed(html)
            field = inputs.fields[f'dnat-edit-{index}-{"source" if slot == "source" else "originalDestination"}']
            assert "readonly" in field and "name" not in field and field["value"]
            if slot == "destination":
                browser.request(path, 400, {**fields, "bundleJson": current, "operation": "remove"})
        rule = json.loads(current)["nat"]["dnatRules"][index]
        edit = {**common, "bundleJson": current, "ruleIndex": str(index), "family": family, "protocol": "tcp",
                "translatedAddress": rule["translatedAddress"], "translatedPort": str(rule["translatedPort"]), "description": "Retained DNAT address and port pins"}
        current, parsed = decode(browser.request("/manage/policies/nat/dnat/edit", 200, edit))
        after = parsed["nat"]["dnatRules"][index]
        for key in ("sourceObject", "destinationObject", "originalPortObject", "enabled", "negateSource", "translatedAddress", "translatedPort"):
            assert after[key] == rule[key]
        for forged_field in ("source", "originalDestination"):
            browser.request("/manage/policies/nat/dnat/edit", 400, {**edit, forged_field: "192.0.2.10" if family == "ipv4" else "2001:db8::10"})
        _, removed = decode(browser.request(path, 200, {**common, "bundleJson": current, "scope": "dnat", "slot": "source", "ruleIndex": str(index), "operation": "remove"}))
        cleared = removed["nat"]["dnatRules"][index]
        assert "sourceObject" not in cleared and "negateSource" not in cleared
        assert cleared["destinationObject"] == rule["destinationObject"] and cleared["originalPortObject"] == rule["originalPortObject"]
        for slot in ("source", "destination"):
            _, browsed = decode(browser.request(path, 200, {**common, "bundleJson": current, "scope": "dnat", "slot": slot, "ruleIndex": str(index),
                "selection": objects[f"nat_{slot}_{family}"] + "/1", "operation": "history"}))
            assert browsed == json.loads(current)
            forged = json.loads(current); forged["nat"]["dnatRules"][index][slot + "Object"]["version"] = 2
            browser.request("/manage/policies/save", 400, {**common, "bundleJson": json.dumps(forged)})
    browser.request("/manage/policies/save", 302, {**common, "bundleJson": current, "summary": "Pinned original DNAT addresses"})
    for index, family in enumerate(("ipv4", "ipv6")):
        for slot in ("source", "destination"):
            usage = browser.request("/manage/objects?objectId=" + objects[f"nat_{slot}_{family}"], 200)
            assert f"nat.dnatRules[{index}].{slot}Object" in usage
    with sqlite3.connect(directory / "controller.db") as db:
        assert db.execute("SELECT policy_json FROM policy_revisions WHERE revision=8").fetchone()[0] == before
        assert db.execute("SELECT policy_json FROM policy_revisions WHERE revision=9").fetchone()[0] == current
        assert db.execute("SELECT count(*) FROM policy_revisions").fetchone()[0] == 9
    print("PASS: dual-stack DNAT address pins, required-destination denial, source-negation removal, ordinary edit/port/translation retention and immutable SQL usage/history")
