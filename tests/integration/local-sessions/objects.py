"""Synthetic HTTPS object-library conformance, without kernel or agent access."""
import sqlite3


def check_objects(browser, controller_directory):
    fields = {"expectedVersion": "0", "name": "trusted_clients", "kind": "ipv4",
              "description": "Synthetic <script>alert(1)</script>", "entries": "192.0.2.10\r\n198.51.100.0/24"}
    assert "Policies can pin a list version" in browser.request("/manage/objects", 200)
    browser.request("/manage/objects/save", 400, fields)

    def save(values, status=302):
        return browser.request("/manage/objects/save", status,
                               {**values, "__RequestVerificationToken": browser.token("/manage/objects")})

    for values in ({**fields, "name": "Bad name"}, {**fields, "kind": "unsupported"},
                   {**fields, "entries": "2001:db8::1"}, {**fields, "entries": "192.0.2.1/24"},
                   {**fields, "entries": "192.0.2.1\n192.0.2.1/32"}, {**fields, "unknown": "x"}):
        html = save(values, 400)
        assert 'role="alert"' in html
        assert values["name"] in html
    duplicate = [*fields.items(), ("name", "other"),
                 ("__RequestVerificationToken", browser.token("/manage/objects"))]
    browser.request("/manage/objects/save", 400, duplicate)
    save(fields)
    object_id = browser.location.split("objectId=")[1]
    path = "/manage/objects?objectId=" + object_id
    html = browser.request(path, 200)
    assert "&lt;script&gt;" in html and "<script>alert(1)</script>" not in html
    assert 'data-local-time datetime="' in html and "192.0.2.10/32" in html
    updated = {**fields, "id": object_id, "expectedVersion": "1", "description": "Updated synthetic list",
               "entries": "203.0.113.10"}
    save(updated)
    stale = save({**updated, "description": "retained stale input"}, 409)
    assert "Another edit was saved first" in stale and "retained stale input" in stale
    save({**updated, "expectedVersion": "2", "kind": "port", "entries": "443"}, 400)
    save(fields, 400)
    historical = browser.request(path + "&version=1", 200)
    assert "192.0.2.10/32" in historical and "Viewing historical contents" in historical
    assert 'action="/manage/objects/save"' not in historical
    current = browser.request(path, 200)
    assert "203.0.113.10/32" in current and "Updated synthetic list" in current
    assert "No matching lists" in browser.request("/manage/objects?q=no_matching_list", 200)
    browser.request("/manage/objects?objectId=invalid", 400)
    browser.request(path + "&version=0", 400)
    browser.request(path + "&version=3", 404)
    comparison = browser.request(path + "&version=2&compareToVersion=1", 200)
    assert "2 removed" in comparison and "1 added" in comparison and "0 unchanged entries" in comparison
    assert "Description changed" in comparison and "&lt;script&gt;" in comparison
    assert "<script>alert(1)</script>" not in comparison
    reverse = browser.request(path + "&version=1&compareToVersion=2", 200)
    assert "2 added" in reverse and "1 removed" in reverse
    assert 'action="/manage/objects/save"' not in reverse
    same = browser.request(path + "&version=1&compareToVersion=1", 200)
    assert "0 added" in same and "0 removed" in same and "2 unchanged entries" in same
    assert "Description unchanged" in same
    for query in ("compareToVersion=0", "compareToVersion=65", "compareToVersion=invalid",
                  "compareToVersion=1&compareToVersion=2", "version=1&version=2"):
        browser.request(path + "&" + query, 400)
    browser.request(path + "&compareToVersion=3", 404)
    browser.request("/manage/objects?compareToVersion=1", 400)
    save({**fields, "name": "web_ports", "kind": "port", "entries": "80\n443"})
    save({**fields, "name": "ipv6_clients", "kind": "ipv6", "entries": "2001:db8::1\n2001:db8:1::/64"})
    browser.request("/manage/objects/save", 413, {**fields, "entries": "x" * 25_000})
    with sqlite3.connect(controller_directory / "controller.db") as db:
        assert db.execute("SELECT count(*) FROM reusable_objects").fetchone() == (3,)
        assert db.execute("SELECT count(*) FROM reusable_object_versions").fetchone() == (4,)
        assert db.execute("SELECT count(*) FROM audit_log WHERE action LIKE 'object.%'").fetchone() == (4,)
        assert db.execute("SELECT count(*) FROM policy_revisions").fetchone() == (0,)
    print("PASS: typed object UI, immutable versions, stale-input retention, validation, escaping and atomic audit")
    return path
