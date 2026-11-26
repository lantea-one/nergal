"""Real guided source-bound conversion, immutable plans and separate revision creation over HTTPS."""
import hashlib
import json
import sqlite3
from urllib.parse import parse_qs, urlencode, urlsplit


def check_native_conversion(browser, upload, ctrl_state):
    root = b'define host = 192.0.2.10\ntable inet portal_source {\n set allowed { type ipv4_addr; elements = {$host}; }\n include "/uploaded/input.conf"\n}\n'
    child = b'chain incoming { type filter hook input priority filter; policy drop; ip saddr @allowed tcp dport 443 accept; }\n'
    upload("Uploaded include snapshot", child)
    child_id = parse_qs(urlsplit(browser.location).query)["sourceId"][0]
    upload("Conversion root snapshot", root)
    root_id = parse_qs(urlsplit(browser.location).query)["sourceId"][0]
    source_path = "/manage/sources?sourceId=" + root_id
    html = browser.request(source_path, 200)
    assert "Convert to a managed policy" in html and "No additional file" in html
    fields = {"Conversion.SourceId": root_id, "Conversion.Tables[0].Family": "inet", "Conversion.Tables[0].Name": "portal_source",
              "Conversion.Tables[0].Role": "Filter", "Conversion.Includes[0].Path": "/uploaded/input.conf", "Conversion.Includes[0].Sources": child_id}
    review_path = "/manage/sources/conversion/review"
    commit_path = "/manage/sources/conversion/commit"
    with sqlite3.connect(ctrl_state / "controller.db") as db:
        baseline = tuple(db.execute("SELECT (SELECT count(*) FROM policy_revisions),(SELECT count(*) FROM reusable_objects),(SELECT count(*) FROM native_conversion_plans),(SELECT count(*) FROM audit_log)").fetchone())
    browser.request(review_path, 400, {**fields, "operation": "review"})
    valid_fields = {**fields, "operation": "review", "__RequestVerificationToken": browser.token(source_path)}
    browser.request(review_path, 400, {**valid_fields, "Conversion.RestrictGlobalOperations": "false"})
    browser.request(review_path, 400, {**valid_fields, "Conversion.Tables[0].Unknown": "ignored"})
    browser.request(review_path, 400, raw=urlencode(list(valid_fields.items()) + [("Conversion.Tables[0].Role", "Auxiliary")]), headers={"Content-Type": "application/x-www-form-urlencoded"})
    html = browser.request(review_path, 200, {**fields, "operation": "refresh", "__RequestVerificationToken": browser.token(source_path)})
    assert "portal_source" in html and "Uploaded include snapshot" in html
    browser.request(review_path, 302, {**fields, "operation": "review", "__RequestVerificationToken": browser.token(source_path)})
    plan_path = browser.location
    plan_id = parse_qs(urlsplit(plan_path).query)["planId"][0]
    html = browser.request(plan_path, 200)
    assert "Ready to create a saved revision" in html and "Create reviewed policy revision" in html
    report_path = "/manage/sources/conversion/plan/" + plan_id + "/report"
    report = json.loads(browser.request(report_path, 200))
    assert report["schemaVersion"] == 1 and report["gaps"] == [] and len(report["sourceBindings"]) == 2
    assert {s["digest"] for s in report["sourceBindings"]} == {hashlib.sha256(root).hexdigest(), hashlib.sha256(child).hexdigest()}
    assert {"include", "definition", "named-object", "rule"} <= {m["disposition"] for m in report["mappings"]}
    assert "192.0.2.10" not in json.dumps(report) and "portal_source" not in json.dumps(report)
    with sqlite3.connect(ctrl_state / "controller.db") as db:
        counts = db.execute("SELECT (SELECT count(*) FROM policy_revisions),(SELECT count(*) FROM reusable_objects),(SELECT count(*) FROM native_conversion_plans),(SELECT count(*) FROM audit_log)").fetchone()
        assert counts == (baseline[0], baseline[1], baseline[2] + 1, baseline[3] + 1)
        digest = db.execute("SELECT content_sha256 FROM native_conversion_plans WHERE id=?", (plan_id,)).fetchone()[0]
    browser.request(commit_path, 400, {"planId": plan_id, "digest": digest})
    browser.request(commit_path, 400, raw=urlencode([("planId", plan_id), ("digest", digest), ("digest", "0" * 64), ("__RequestVerificationToken", browser.token(source_path))]), headers={"Content-Type": "application/x-www-form-urlencoded"})
    browser.request(commit_path, 409, {"planId": plan_id, "digest": "0" * 64, "__RequestVerificationToken": browser.token(source_path)})
    browser.request(commit_path, 302, {"planId": plan_id, "digest": digest, "__RequestVerificationToken": browser.token(source_path)})
    revision = parse_qs(urlsplit(browser.location).query)["revision"][0]
    html = browser.request(plan_path, 200)
    assert "was created from this plan" in html and "Create reviewed policy revision" not in html
    with sqlite3.connect(ctrl_state / "controller.db") as db:
        counts = db.execute("SELECT (SELECT count(*) FROM policy_revisions),(SELECT count(*) FROM reusable_objects)").fetchone()
        assert counts == (baseline[0] + 1, baseline[1] + 1)
        policy = json.loads(db.execute("SELECT policy_json FROM policy_revisions WHERE revision=?", (revision,)).fetchone()[0])
        pin = policy["filter"]["rules"][0]["sourceObject"]
        assert pin["entries"] == ["192.0.2.10/32"] and pin["version"] == 1 and pin["nativeSet"]
        after = db.execute("SELECT count(*) FROM audit_log").fetchone()[0]
    browser.request(commit_path, 409, {"planId": plan_id, "digest": digest, "__RequestVerificationToken": browser.token(source_path)})
    with sqlite3.connect(ctrl_state / "controller.db") as db:
        assert db.execute("SELECT count(*) FROM audit_log").fetchone()[0] == after
    native = browser.request("/manage/policies/export/native?revision=" + revision, 200)
    intent = json.loads(browser.request("/manage/policies/export/intent?revision=" + revision, 200))
    assert "@" in native and "create table inet nergal_filter" in native and "flush" not in native
    assert intent["filter"]["rules"][0]["sourceObject"]["id"] == pin["id"]
    assert browser.request("/manage/sources/download?sourceId=" + root_id, 200).encode() == root
    assert browser.request("/manage/sources/download?sourceId=" + child_id, 200).encode() == child
    upload("Unsupported native source", b'table inet blocked { chain input { type filter hook input priority 0; counter packets 3 bytes 60 accept; } }')
    denied_source = parse_qs(urlsplit(browser.location).query)["sourceId"][0]
    browser.request(review_path, 302, {"Conversion.SourceId": denied_source, "Conversion.Tables[0].Family": "inet", "Conversion.Tables[0].Name": "blocked", "Conversion.Tables[0].Role": "Filter", "operation": "review", "__RequestVerificationToken": browser.token(source_path)})
    denied_id = parse_qs(urlsplit(browser.location).query)["planId"][0]
    html = browser.request(browser.location, 200)
    assert "Conversion blocked:" in html and "Create reviewed policy revision" not in html
    with sqlite3.connect(ctrl_state / "controller.db") as db:
        candidate = db.execute("SELECT policy_json,candidate_sha256,content_sha256 FROM native_conversion_plans WHERE id=?", (denied_id,)).fetchone()
        assert candidate[0] is None and candidate[1] is None
    browser.request(commit_path, 409, {"planId": denied_id, "digest": candidate[2], "__RequestVerificationToken": browser.token(source_path)})
    print("PASS: guided source/include/table conversion, immutable source-bound plans, blocked-prefix denial, atomic pinned-list/revision creation, replay denial and exact exports")
    return plan_id
