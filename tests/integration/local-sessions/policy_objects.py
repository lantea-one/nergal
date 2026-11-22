"""Real HTTPS draft selection, immutable revision pinning and usage visibility."""
import json
import sqlite3
from html.parser import HTMLParser


class Draft(HTMLParser):
    value = None

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "input" and fields.get("name") == "bundleJson":
            self.value = fields["value"]


def check_policy_objects(browser, directory):
    with sqlite3.connect(directory / "controller.db") as db:
        object_id = db.execute("SELECT id FROM reusable_objects WHERE name='trusted_clients'").fetchone()[0]
    raw = json.dumps({"schemaVersion": 1, "filter": {"schemaVersion": 2, "inputDefaultVerdict": "drop",
        "forwardDefaultVerdict": "drop", "outputDefaultVerdict": "accept", "rules": [
            {"family": "ipv4", "protocol": "tcp", "verdict": "accept", "destinationPort": 443}]}})
    fields = {"bundleJson": raw, "ruleIndex": "0", "slot": "source", "selection": object_id + "/2", "operation": "attach"}
    browser.request("/manage/policies/objects", 400, fields)
    fields["__RequestVerificationToken"] = browser.token("/manage/policies")
    browser.request("/manage/policies/objects", 400, {**fields, "selection": object_id + "/64"})
    browser.request("/manage/policies/objects", 400, {**fields, "slot": "ports"})
    browser.request("/manage/policies/objects", 400, {**fields, "unexpected": "value"})
    html = browser.request("/manage/policies/objects", 200, fields)
    assert "· v2 ·" in html and "v@item" not in html
    parsed = Draft(); parsed.feed(html); assert parsed.value
    bundle = json.loads(parsed.value)
    reference = bundle["filter"]["rules"][0]["sourceObject"]
    assert reference["id"] == object_id and reference["version"] == 2
    assert reference["entries"] == ["203.0.113.10/32"]
    assert "trusted_clients v2" in html and "ip saddr 203.0.113.10/32" in html
    browser.request("/manage/policies/save", 302, {"bundleJson": parsed.value, "summary": "Pinned synthetic list",
                    "__RequestVerificationToken": browser.token("/manage/policies")})
    usage = browser.request("/manage/objects?objectId=" + object_id, 200)
    assert "Saved revision references (1)" in usage and "Policy revision 1" in usage
    browser.request("/manage/objects/save", 302, {"id": object_id, "expectedVersion": "2", "name": "trusted_clients",
        "kind": "ipv4", "description": "New library version", "entries": "192.0.2.99",
        "__RequestVerificationToken": browser.token("/manage/objects")})
    with sqlite3.connect(directory / "controller.db") as db:
        saved = json.loads(db.execute("SELECT policy_json FROM policy_revisions WHERE revision=1").fetchone()[0])
        assert saved["filter"]["rules"][0]["sourceObject"] == reference
    preview = browser.request("/manage/policies?revision=1", 200)
    assert "trusted_clients v2" in preview and "ip saddr 203.0.113.10/32" in preview
    forged = json.loads(parsed.value); forged["filter"]["rules"][0]["sourceObject"]["version"] = 1
    denied = browser.request("/manage/policies/save", 400, {"bundleJson": json.dumps(forged),
        "__RequestVerificationToken": browser.token("/manage/policies")})
    assert "object.referenceMismatch" in denied
    removed = browser.request("/manage/policies/objects", 200, {**fields, "bundleJson": parsed.value, "operation": "remove"})
    draft = Draft(); draft.feed(removed)
    assert "sourceObject" not in json.loads(draft.value)["filter"]["rules"][0]
    print("PASS: HTTPS policy reference selection, saved-version pinning, impact visibility and forged-reference denial")
