"""Real HTTPS state controls retain complete pinned intent without bypassing revision/apply boundaries."""
import json
import html as html_module
import sqlite3
from policy_objects import Draft


def check_rule_states(browser, directory):
    with sqlite3.connect(directory / "controller.db") as db:
        original = db.execute("SELECT policy_json FROM policy_revisions WHERE revision=1").fetchone()[0]
    fields = {"bundleJson": original, "scope": "Filter", "ruleIndex": "0"}
    browser.request("/manage/policies/rules/state", 400, fields)
    fields["__RequestVerificationToken"] = browser.token("/manage/policies")
    for bad in ({"scope": "unknown"}, {"ruleIndex": "-1"}, {"enabled": "false"}, {"chain": "unexpected"}, {"extra": "x"}):
        browser.request("/manage/policies/rules/state", 400, {**fields, **bad})
    browser.request("/manage/policies/rules/state", 400, [*fields.items(), ("enabled", "true"), ("enabled", "true")])
    html = browser.request("/manage/policies/rules/state", 200, fields)
    parsed = Draft(); parsed.feed(html); disabled = json.loads(parsed.value)
    before = json.loads(original)["filter"]["rules"][0]
    after = disabled["filter"]["rules"][0]
    assert after == {**before, "enabled": False}
    assert "Bundle summary" in html and "All authored rule states" in html and "Filter v2" in html
    assert "Disabled · omitted from candidate" in html_module.unescape(html) and "Intent diff" in html
    assert 'aria-label="Filter rule 1 enabled"' in html
    assert "ip saddr 203.0.113.10/32" not in html.split("Compiled nftables candidate")[1].split("</pre>")[0]
    browser.request("/manage/policies/save", 302, {"bundleJson": parsed.value, "summary": "Disable synthetic rule",
        "__RequestVerificationToken": browser.token("/manage/policies")})
    with sqlite3.connect(directory / "controller.db") as db:
        assert db.execute("SELECT policy_json FROM policy_revisions WHERE revision=1").fetchone()[0] == original
        saved = json.loads(db.execute("SELECT policy_json FROM policy_revisions WHERE revision=2").fetchone()[0])
        assert saved["filter"]["rules"][0] == after
    restored = browser.request("/manage/policies/rules/state", 200, {**fields, "bundleJson": parsed.value, "enabled": "true"})
    active = Draft(); active.feed(restored)
    assert json.loads(active.value)["filter"]["rules"][0] == before
    assert "ip saddr 203.0.113.10/32" in restored
    print("PASS: inline rule state, exact retained settings/reference/order, intent diff, immutable revisions and denied forms")
