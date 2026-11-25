"""Real server navigation preserves authorization and makes first-use state explicit without writes."""
import sqlite3


def check_appliance_navigation(browser, state):
    with sqlite3.connect(state / 'controller.db') as db:
        before = db.execute('SELECT count(*) FROM audit_log').fetchone()[0]
    overview = browser.request('/manage', 200)
    assert 'Start with your firewall policy' in overview and 'Create a policy' in overview
    assert 'id="management-navigation"' in overview and 'Skip to content' in overview
    assert 'Register agent host' not in overview and 'Saved configuration preferences' not in overview
    assert '0 synced' not in overview and 'offline' not in overview
    assert 'No hosts connected' in overview and '<meter ' not in overview
    hosts = browser.request('/manage/hosts', 200)
    assert 'Register agent host' in hosts and 'already enrolled' in hosts
    assert 'Registering a connection does not apply a policy' in hosts
    for section in ('filter', 'nat', 'bridge', 'preview', 'json'):
        page = browser.request('/manage/policies?section=' + section, 200)
        assert 'data-initial-tab="tab-' + section + '"' in page
    browser.request('/manage/policies?section=unknown', 400)
    browser.request('/manage/policies?section=nat&section=filter', 400)
    with sqlite3.connect(state / 'controller.db') as db:
        assert db.execute('SELECT count(*) FROM audit_log').fetchone()[0] == before
    print('PASS: appliance navigation, focused first-use/host pages, allowlisted sections and unchanged state after read/denial')


def check_host_connections(browser, state):
    """Registration stays an explicit audited endpoint record; invalid/CSRF submissions create no host."""
    fields = {'name': 'synthetic-console-connection', 'transportKind': 'unix',
              'endpoint': '/run/nergal-fixture/nonexistent.sock', 'expectedServerUserId': '0'}
    browser.request('/manage/hosts/add', 400, fields)
    browser.request('/manage/hosts/add', 400, {**fields, 'expectedServerUserId': 'invalid', '__RequestVerificationToken': browser.token('/manage/hosts')})
    with sqlite3.connect(state / 'controller.db') as db:
        assert db.execute('SELECT count(*) FROM hosts').fetchone()[0] == 0
    browser.request('/manage/hosts/add', 302, {**fields, '__RequestVerificationToken': browser.token('/manage/hosts')})
    assert browser.location == '/manage/hosts'
    page = browser.request('/manage/hosts', 200)
    assert fields['name'] in page and 'Connection and identity' in page
    assert 'Last recorded' in page and 'unavailable' in page
    overview = browser.request('/manage', 200)
    assert 'No usable agent status classifications' in overview and '<meter ' not in overview
    assert 'Gaps in status coverage' in overview and 'Status unavailable' in overview
    with sqlite3.connect(state / 'controller.db') as db:
        host_id = db.execute('SELECT id FROM hosts').fetchone()[0]
    browser.request('/manage/hosts/delete', 400, {'id': host_id})
    browser.request('/manage/hosts/delete', 302, {'id': host_id, '__RequestVerificationToken': browser.token('/manage/hosts')})
    assert browser.location == '/manage/hosts'
    with sqlite3.connect(state / 'controller.db') as db:
        assert db.execute('SELECT count(*) FROM hosts').fetchone()[0] == 0
    print('PASS: focused host registration/removal, retained Administrator/CSRF boundary and explicit Overview observation gaps')
