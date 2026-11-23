"""Complete postrouting address pins, strict forms and immutable SQL history over real HTTPS."""
import json
import sqlite3
from raw_forms import decode
from transport_references import PortFields


def check_postrouting_addresses(browser, directory):
    with sqlite3.connect(directory / "controller.db") as db:
        before = db.execute("SELECT policy_json FROM policy_revisions WHERE revision=5").fetchone()[0]
    bundle = json.loads(before)
    bundle["nat"]["snatRules"].insert(0, {"family": "ipv4", "source": "192.0.2.0/24", "destination": "203.0.113.0/24",
        "translatedAddress": "198.51.100.1", "negateSource": True, "negateDestination": True, "enabled": False})
    bundle["nat"]["snatRules"][1]["negateSource"] = True
    current = json.dumps(bundle)
    token = browser.token("/manage/policies")
    path = "/manage/policies/objects"
    objects = {}
    for index, kind, sources, destinations in ((0, "ipv4", "192.0.2.0/24\n198.51.100.0/24", "203.0.113.10\n203.0.113.20"),
                                               (1, "ipv6", "2001:db8:1::/64\n2001:db8:3::/64", "2001:db8:2::10\n2001:db8:2::20")):
        for slot, entries in (("source", sources), ("destination", destinations)):
            name = f"nat_{slot}_{kind}"
            browser.request("/manage/objects/save", 302, {"expectedVersion": "0", "name": name, "kind": kind, "entries": entries,
                "description": "Synthetic NAT address list", "__RequestVerificationToken": token})
            object_id = browser.location.split("objectId=")[1]
            objects[index, slot] = object_id
            fields = {"bundleJson": current, "ruleIndex": str(index), "scope": "postrouting", "slot": slot,
                "selection": object_id + "/1", "operation": "attach", "__RequestVerificationToken": token}
            other_kind = "ipv6_clients" if kind == "ipv4" else "trusted_clients"
            with sqlite3.connect(directory / "controller.db") as db:
                other_id = db.execute("SELECT id FROM reusable_objects WHERE name=?", (other_kind,)).fetchone()[0]
            browser.request(path, 400, {**fields, "selection": other_id + "/1"})
            browser.request(path, 400, {**fields, "chain": "unexpected"})
            html = browser.request(path, 200, fields)
            current, parsed = decode(html)
            assert parsed["nat"]["snatRules"][index][slot + "Object"]["id"] == object_id
            assert parsed["nat"]["snatRules"][index]["enabled"] is False
            inputs = PortFields(); inputs.feed(html)
            field = inputs.fields[f"postrouting-{index}-{slot}"]
            assert "readonly" in field and "name" not in field and field["value"]
        rule = json.loads(current)["nat"]["snatRules"][index]
        edit = {"bundleJson": current, "ruleIndex": str(index), "family": rule["family"], "action": rule.get("action", "snat"),
            "translatedAddress": rule.get("translatedAddress", ""), "protocol": rule.get("protocol", "any"),
            "inputInterface": rule.get("inputInterface", ""), "outputInterface": rule.get("outputInterface", ""),
            "negateSource": "true", "description": "Edited dormant NAT address pins", "__RequestVerificationToken": token}
        if rule.get("negateDestination"):
            edit["negateDestination"] = "true"
        edited, after = decode(browser.request("/manage/policies/nat/postrouting", 200, edit))
        for slot in ("source", "destination"):
            assert after["nat"]["snatRules"][index][slot + "Object"] == rule[slot + "Object"]
        browser.request("/manage/policies/nat/postrouting", 400, {**edit, "source": sources.splitlines()[0]})
        current = edited
    browser.request("/manage/policies/save", 302, {"bundleJson": current, "summary": "Pinned postrouting addresses", "__RequestVerificationToken": token})
    source_id = objects[0, "source"]
    browser.request("/manage/objects/save", 302, {"id": source_id, "expectedVersion": "1", "name": "nat_source_ipv4", "kind": "ipv4",
        "description": "Later version", "entries": "192.0.2.99", "__RequestVerificationToken": token})
    fields = {"bundleJson": current, "ruleIndex": "0", "scope": "postrouting", "slot": "source", "selection": source_id + "/2", "operation": "history", "__RequestVerificationToken": token}
    _, browsed = decode(browser.request(path, 200, fields))
    assert browsed == json.loads(current)
    browser.request(path, 400, {**fields, "operation": "remove"})  # Explicit SNAT still requires a source.
    _, removed = decode(browser.request(path, 200, {**fields, "slot": "destination", "operation": "remove"}))
    assert "destinationObject" not in removed["nat"]["snatRules"][0] and "negateDestination" not in removed["nat"]["snatRules"][0]
    _, removed = decode(browser.request(path, 200, {**fields, "ruleIndex": "1", "operation": "remove"}))
    assert "sourceObject" not in removed["nat"]["snatRules"][1] and "negateSource" not in removed["nat"]["snatRules"][1]
    for index in (0, 1):
        for slot in ("source", "destination"):
            usage = browser.request("/manage/objects?objectId=" + objects[index, slot], 200)
            assert f"nat.snatRules[{index}].{slot}Object" in usage
            forged = json.loads(current); forged["nat"]["snatRules"][index][slot + "Object"]["version"] = 2
            browser.request("/manage/policies/save", 400, {"bundleJson": json.dumps(forged), "__RequestVerificationToken": token})
    with sqlite3.connect(directory / "controller.db") as db:
        assert db.execute("SELECT policy_json FROM policy_revisions WHERE revision=5").fetchone()[0] == before
        assert db.execute("SELECT policy_json FROM policy_revisions WHERE revision=6").fetchone()[0] == current
        assert db.execute("SELECT count(*) FROM policy_revisions").fetchone()[0] == 6
    print("PASS: guided dual-stack postrouting address pins, retained restrictions/state, required-source denial and immutable history/usage")
