"""HTML navigation and recovery pages never turn API authentication into redirects or disclose exceptions."""
import sqlite3

HTML = {'Accept': 'text/html,application/xhtml+xml'}


def check_anonymous_browser_errors(browser):
    for path in ('/manage', '/profile', '/session', '/manage/users'):
        browser.request(path, 302, headers=HTML)
        assert browser.location == '/login'
        browser.request(path, 401)
    browser.request('/controller/hosts', 401, headers=HTML)
    browser.request('/missing-synthetic-page?private=not-reflected', 302, headers=HTML)
    assert browser.location == '/login'


def check_authenticated_browser_errors(browser):
    missing = browser.request('/missing-synthetic-page?private=not-reflected', 404, headers=HTML)
    assert 'Page not found' in missing and 'href="/"' in missing
    assert 'not-reflected' not in missing and '<footer' not in missing
    assert browser.last_headers['content-type'].startswith('text/html')
    assert browser.last_headers['cache-control'] == 'no-store'
    browser.request('/missing-synthetic-page', 404)
    assert not browser.last_headers.get('content-type', '').startswith('text/html')


def check_auditor_browser_errors(browser):
    denied = browser.request('/manage/users', 403, headers=HTML)
    assert 'Access denied' in denied and 'Administrator' in denied
    assert 'PasswordHash' not in denied and 'Exception' not in denied
    browser.request('/manage/users', 403)


def check_unavailable_browser_page(browser, database):
    # Damage only this private synthetic account store, after all normal cases.
    # The error renderer must work even though authentication/profile reads fail.
    with sqlite3.connect(database) as db:
        definition = db.execute("SELECT sql FROM sqlite_master WHERE name='identity_audit_no_delete'").fetchone()[0]
        db.execute('DROP TRIGGER identity_audit_no_delete')
    try:
        page = browser.request('/profile', 503, headers=HTML)
        assert 'Service temporarily unavailable' in page
        assert 'account.schemaOrIntegrity' not in page and 'Sqlite' not in page and 'Exception' not in page
        assert browser.last_headers['content-type'].startswith('text/html')
        assert '/* nergal' in browser.request('/css/nergal.css', 200)
        assert '<symbol id="overview"' in browser.request('/icons/navigation.svg', 200)
        browser.request('/profile', 503)
        assert not browser.last_headers.get('content-type', '').startswith('text/html')
    finally:
        with sqlite3.connect(database) as db:
            db.execute(definition)
    print('PASS: fixed browser sign-in redirects, API status separation and standalone 403/404/503 pages without exception disclosure')
