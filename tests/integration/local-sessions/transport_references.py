"""HTTP destination-port references retain table/chain scope, immutable versions and dormant control-flow restrictions."""
import json
import sqlite3
from html.parser import HTMLParser
from raw_forms import decode


class PortFields(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = {}
        self.links = []
        self.selected = {}
        self.active_select = None

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "select":
            self.active_select = fields.get("id")
        if tag == "option" and "selected" in fields and self.active_select:
            self.selected[self.active_select] = fields.get("value")
        if tag == "a":
            self.links.append(fields)
        if tag == "input" and fields.get("id"):
            self.fields[fields["id"]] = fields

    def handle_endtag(self, tag):
        if tag == "select":
            self.active_select = None


def check_transport_references(browser, directory):
    with sqlite3.connect(directory / "controller.db") as db:
        original = db.execute("SELECT policy_json FROM policy_revisions WHERE revision=4").fetchone()[0]
        port_id = db.execute("SELECT id FROM reusable_objects WHERE name='web_ports'").fetchone()[0]
        address_id = db.execute("SELECT id FROM reusable_objects WHERE name='trusted_clients'").fetchone()[0]
    b = json.loads(original)
    b["nat"] = {"schemaVersion": 1, "dnatRules": [], "snatRules": [{"family": "ipv6", "source": "2001:db8:1::/64", "action": "masquerade", "protocol": "tcp", "destinationPort": 443, "inputInterface": "lan0", "outputInterface": "wan0", "enabled": False}]}
    b["bridge"]["rules"][0]["enabled"] = False
    current = json.dumps(b)
    token = browser.token("/manage/policies")
    path = "/manage/policies/objects"
    for scope, index, chain in (("postrouting", "0", None), ("bridge", "0", None), ("bridgeChain", "1", "mail")):
        fields = {"bundleJson": current, "scope": scope, "ruleIndex": index, "slot": "ports", "selection": port_id + "/1", "operation": "attach", "__RequestVerificationToken": token}
        if chain is not None:
            fields["chain"] = chain
        for bad in ({"slot": "source"}, {"ruleIndex": "-1"}, {"selection": address_id + "/1"}, {"selection": port_id + "/64"}, {"chain": "unknown"}, {"extra": "x"}):
            browser.request(path, 400, {**fields, **bad})
        browser.request(path, 400, [*fields.items(), ("scope", scope)])
        if chain is not None:
            browser.request(path, 400, {k: v for k, v in fields.items() if k != "chain"})
        html = browser.request(path, 200, fields)
        current, updated = decode(html)
        rule = updated["nat"]["snatRules"][0] if scope == "postrouting" else updated["bridge"]["rules"][0] if scope == "bridge" else updated["bridge"]["subChains"][0]["rules"][1]
        assert rule["destinationPortObject"]["id"] == port_id and rule["destinationPortObject"]["version"] == 1
        assert "destinationPort" not in rule and "destinationPorts" not in rule and rule["enabled"] is False
        if scope == "bridge":
            assert rule["jumpTarget"] == "mail" and rule["bridgeName"] == "br0"
        elif scope == "bridgeChain":
            assert rule["return"] is True
        assert updated["filter"] == b["filter"] and updated["auxiliaryFilter"] == b["auxiliaryFilter"]
        assert "Pinned port list:" in html and "web_ports v1" in html
        inputs = PortFields(); inputs.feed(html)
        field_id = "postrouting-0-ports" if scope == "postrouting" else "bridge-forward-0-destinationPorts" if scope == "bridge" else "bridge-mail-1-destinationPorts"
        field = inputs.fields[field_id]
        assert "readonly" in field and "name" not in field and field["value"] == "443, 80"
        # Removing is explicit and clears only this port restriction; other references and state remain.
        _, removed = decode(browser.request(path, 200, {**fields, "bundleJson": current, "operation": "remove"}))
        cleared = removed["nat"]["snatRules"][0] if scope == "postrouting" else removed["bridge"]["rules"][0] if scope == "bridge" else removed["bridge"]["subChains"][0]["rules"][1]
        assert "destinationPortObject" not in cleared and "destinationPort" not in cleared and "destinationPorts" not in cleared and cleared["enabled"] is False
    browser.request("/manage/policies/save", 302, {"bundleJson": current, "summary": "Synthetic pinned transport lists", "__RequestVerificationToken": token})
    usage = browser.request("/manage/objects?objectId=" + port_id, 200)
    for location in ("nat.snatRules[0].destinationPortObject", "bridge.rules[0].destinationPortObject", "bridge.subChains[0].rules[1].destinationPortObject"):
        assert location in usage
    browser.request("/manage/objects/save", 302, {"id": port_id, "expectedVersion": "1", "name": "web_ports", "kind": "port", "entries": "8443", "description": "Later transport list", "__RequestVerificationToken": browser.token("/manage/objects")})
    summary = PortFields(); summary.feed(browser.request("/manage/policies?revision=5", 200))
    expected_link = "/manage/objects?objectId=" + port_id + "&compareToVersion=1"
    pin_links = [link for link in summary.links if link.get("href") == expected_link]
    assert len(pin_links) >= 3 and all(link.get("target") == "_blank" and link.get("rel") == "noopener" for link in pin_links)
    comparison = browser.request(expected_link, 200)
    assert "Version 1" in comparison and "version 2" in comparison and "2 removed" in comparison and "1 added" in comparison
    for scope in ("primary", "auxiliary", "postrouting", "bridge", "bridgeChain"):
        history_fields = {"bundleJson": current, "summary": "Retained historical draft", "compareToRevision": "4", "scope": scope, "ruleIndex": "1" if scope == "bridgeChain" else "0", "slot": "ports", "selection": port_id + "/2", "operation": "history", "__RequestVerificationToken": token}
        if scope == "bridgeChain":
            history_fields["chain"] = "mail"
        html = browser.request(path, 200, history_fields)
        _, unchanged = decode(html)
        assert unchanged == json.loads(current), "history browsing must not mutate any matcher or reference"
        assert "Saved versions loaded for" in html and "Retained historical draft" in html
        assert 'name="compareToRevision" value="4"' in html
        assert f'value="{port_id}/1"' in html and f'value="{port_id}/2"' in html
        rendered = PortFields(); rendered.feed(html)
        prefix = "reference-" + scope + ("-mail" if scope == "bridgeChain" else "-base" if scope in ("postrouting", "bridge") else "")
        assert rendered.selected[prefix + "-rule"] == history_fields["ruleIndex"]
        assert rendered.selected[prefix + "-selection"] == port_id + "/2"
        if scope in ("primary", "auxiliary"):
            assert rendered.selected[prefix + "-slot"] == "ports"
        for bad in ({"slot": "unknown"}, {"ruleIndex": "-1"}, {"ruleIndex": "999"}, {"chain": "unknown"}, {"selection": port_id + "/64"}, {"selection": ""}, {"operation": "unsupported"}, {"scope": "unknown"}):
            browser.request(path, 400, {**history_fields, **bad})
        # The existing attach contract must accept the exact displayed old snapshot, never substitute the current version.
        attached = {**history_fields, "operation": "attach", "ruleIndex": "1" if scope == "bridgeChain" else "0"}
        def matcher(bundle):
            if scope == "primary":
                return bundle["filter"]["rules"][0]
            if scope == "auxiliary":
                return bundle["auxiliaryFilter"]["filter"]["rules"][0]
            if scope == "postrouting":
                return bundle["nat"]["snatRules"][0]
            if scope == "bridge":
                return bundle["bridge"]["rules"][0]
            return bundle["bridge"]["subChains"][0]["rules"][1]
        _, retained = decode(browser.request(path, 200, attached))
        assert matcher(retained)["destinationPortObject"]["version"] == 2
        _, old = decode(browser.request(path, 200, {**attached, "selection": port_id + "/1"}))
        assert matcher(old)["destinationPortObject"]["version"] == 1
    forged = json.loads(current)
    forged["nat"]["snatRules"][0]["destinationPortObject"]["version"] = 2
    browser.request("/manage/policies/save", 400, {"bundleJson": json.dumps(forged), "__RequestVerificationToken": token})
    with sqlite3.connect(directory / "controller.db") as db:
        assert db.execute("SELECT policy_json FROM policy_revisions WHERE revision=4").fetchone()[0] == original
        saved = json.loads(db.execute("SELECT policy_json FROM policy_revisions WHERE revision=5").fetchone()[0])
        assert saved["nat"]["snatRules"][0]["destinationPortObject"]["version"] == 1
        assert db.execute("SELECT count(*) FROM policy_revisions").fetchone()[0] == 5
    print("PASS: NAT/bridge/regular-chain port-list selection, denied scope/type/version, dormant intent, saved usage and forged history denial")
