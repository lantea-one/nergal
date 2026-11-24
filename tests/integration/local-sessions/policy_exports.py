"""Saved exports bind native bytes to database artifacts and retain dormant authored intent separately."""
import hashlib
import json
import sqlite3


def check_policy_exports(browser, directory):
    with sqlite3.connect(directory / "controller.db") as db:
        revisions = db.execute("SELECT revision, policy_json, candidate_digest FROM policy_revisions ORDER BY revision").fetchall()
        audit_count = db.execute("SELECT count(*) FROM audit_log").fetchone()[0]
    assert len(revisions) >= 2
    active = dormant = False
    for revision, intent, digest in revisions:
        path = "/manage/policies/export/native?revision=" + str(revision)
        native = browser.request(path, 200)
        assert browser.last_headers["content-type"] == "application/octet-stream"
        assert "attachment;" in browser.last_headers["content-disposition"]
        assert f"nergal-revision-{revision}-nftables.conf" in browser.last_headers["content-disposition"]
        assert "no-store" in browser.last_headers["cache-control"]
        assert hashlib.sha256(native.encode()).hexdigest() == digest
        assert browser.request(path, 200) == native
        exported_intent = browser.request("/manage/policies/export/intent?revision=" + str(revision), 200)
        assert browser.last_headers["content-type"] == "application/json"
        assert f"nergal-revision-{revision}-policy.json" in browser.last_headers["content-disposition"]
        assert json.loads(exported_intent) == json.loads(intent)
        active |= "@nergal_obj_" in native
        dormant |= '"enabled": false' in exported_intent
    assert active and dormant
    for kind in ("native", "intent"):
        path = "/manage/policies/export/" + kind
        for value in ("", "?revision=0", "?revision=-1", "?revision=abc", "?revision=18446744073709551615"):
            browser.request(path + value, 400)
        browser.request(path + "?revision=9223372036854775807", 404)
    assert "Export a saved revision" in browser.request("/manage/policies", 200)
    with sqlite3.connect(directory / "controller.db") as db:
        assert db.execute("SELECT revision, policy_json, candidate_digest FROM policy_revisions ORDER BY revision").fetchall() == revisions
        assert db.execute("SELECT count(*) FROM audit_log").fetchone()[0] == audit_count
    print("PASS: exact deterministic native/intent attachments, dormant state, saved artifact bindings, invalid IDs and read-only exports")
