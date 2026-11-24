"""Original DNAT port lists retain immutable history, translation, negation and dormant intent over HTTPS."""
import json
import sqlite3
from raw_forms import decode
from transport_references import PortFields


def check_dnat_ports(browser, directory):
    with sqlite3.connect(directory / "controller.db") as db:
        before = db.execute("SELECT policy_json FROM policy_revisions WHERE revision=7").fetchone()[0]
        port_id = db.execute("SELECT id FROM reusable_objects WHERE name='web_ports'").fetchone()[0]
        address_id = db.execute("SELECT id FROM reusable_objects WHERE name='trusted_clients'").fetchone()[0]
    bundle = json.loads(before)
    for family, destination, target, source in (("ipv4", "198.51.100.10/32", "192.0.2.2", "203.0.113.0/24"),
                                                 ("ipv6", "2001:db8:2::10/128", "2001:db8:1::2", "2001:db8:3::/64")):
        bundle["nat"]["dnatRules"].append({"family": family, "protocol": "tcp", "originalDestination": destination,
            "translatedAddress": target, "originalPort": 443, "translatedPort": 8080, "source": source, "negateSource": True, "enabled": False})
    current = json.dumps(bundle)
    token = browser.token("/manage/policies")
    common = {"__RequestVerificationToken": token}
    path = "/manage/policies/objects"
    for index, family in enumerate(("ipv4", "ipv6")):
        fields = {**common, "bundleJson": current, "ruleIndex": str(index), "scope": "dnat", "slot": "ports", "selection": port_id + "/1", "operation": "attach"}
        for bad in ({"slot": "source"}, {"slot": "destination"}, {"selection": address_id + "/1"}, {"chain": "service"}, {"selection": port_id + "/64"}):
            browser.request(path, 400, {**fields, **bad})
        html = browser.request(path, 200, fields)
        current, parsed = decode(html)
        rule = parsed["nat"]["dnatRules"][index]
        inputs = PortFields(); inputs.feed(html)
        field = inputs.fields[f"dnat-edit-{index}-originalPort"]
        assert "readonly" in field and "name" not in field and field["value"]
        edit = {**common, "bundleJson": current, "ruleIndex": str(index), "family": family, "protocol": "tcp",
            "originalDestination": rule["originalDestination"], "translatedAddress": rule["translatedAddress"], "translatedPort": "8080",
            "source": rule["source"], "description": "Retained DNAT port pin"}
        current, parsed = decode(browser.request("/manage/policies/nat/dnat/edit", 200, edit))
        after = parsed["nat"]["dnatRules"][index]
        assert after["originalPortObject"] == rule["originalPortObject"] and after["translatedPort"] == 8080
        assert after["enabled"] is False and after["negateSource"] is True
        for bad in ({"originalPort": "22"}, {"originalPorts": "22,23"}, {"originalPort": "invalid"}, {"translatedPort": "invalid"}, {"extra": "x"}, {"protocol": "any"}):
            browser.request("/manage/policies/nat/dnat/edit", 400, {**edit, **bad})
        browser.request("/manage/policies/nat/dnat/edit", 400, [*edit.items(), ("translatedPort", "443")])
        _, cleared = decode(browser.request(path, 200, {**fields, "bundleJson": current, "operation": "remove"}))
        removed = cleared["nat"]["dnatRules"][index]
        assert "originalPortObject" not in removed and "originalPort" not in removed and "originalPorts" not in removed
        assert removed["translatedPort"] == 8080 and removed["enabled"] is False and removed["negateSource"] is True
        _, browsed = decode(browser.request(path, 200, {**fields, "bundleJson": current, "operation": "history"}))
        assert browsed == json.loads(current)
        forged = json.loads(current); forged["nat"]["dnatRules"][index]["originalPortObject"]["version"] = 2
        browser.request("/manage/policies/save", 400, {**common, "bundleJson": json.dumps(forged)})
    browser.request("/manage/policies/save", 302, {**common, "bundleJson": current, "summary": "Pinned original DNAT ports"})
    usage = browser.request("/manage/objects?objectId=" + port_id, 200)
    assert "nat.dnatRules[0].originalPortObject" in usage and "nat.dnatRules[1].originalPortObject" in usage
    with sqlite3.connect(directory / "controller.db") as db:
        assert db.execute("SELECT policy_json FROM policy_revisions WHERE revision=7").fetchone()[0] == before
        assert db.execute("SELECT policy_json FROM policy_revisions WHERE revision=8").fetchone()[0] == current
        assert db.execute("SELECT count(*) FROM policy_revisions").fetchone()[0] == 8
    print("PASS: dual-stack DNAT original-port pins, readonly guided edits, malformed binder/conflict denial, immutable SQL history and retained translation/negation/state")
