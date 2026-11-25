"""Fresh synthetic accounts exercise real HTTPS authorization, strict forms, profiles and ticket revocation."""
import sqlite3
import subprocess


def check_user_management(host, browser_type, root, tls, admin_tool, password, cookie_name):
    accounts = root / 'user-management-accounts'
    accounts.mkdir(mode=0o700)
    subprocess.run(['dotnet', admin_tool, 'account', 'init', accounts], check=True)
    subprocess.run(['dotnet', admin_tool, 'account', 'provision', accounts, 'fixture-admin', '--password-stdin'],
                   input=(password + '\n').encode(), check=True)
    settings = {'LocalSessions__AccountDirectory': str(accounts)}
    database = accounts / 'accounts.db'

    def state(name):
        with sqlite3.connect(database) as db:
            return db.execute('SELECT u.Id,s.Version FROM AspNetUsers u JOIN LocalAccountState s ON s.UserId=u.Id WHERE u.UserName=?', (name,)).fetchone()

    def count(table):
        with sqlite3.connect(database) as db:
            return db.execute('SELECT count(*) FROM ' + table).fetchone()[0]

    def login(browser, name, secret=password, expected=302):
        browser.request('/login', expected, {'username': name, 'password': secret,
                                           '__RequestVerificationToken': browser.token('/login')})

    def post(browser, path, fields, expected=302, token_page='/manage/users'):
        return browser.request(path, expected, {**fields, '__RequestVerificationToken': browser.token(token_page)})

    with host(root, tls, settings) as admin:
        for path in ('/profile', '/manage/users'):
            admin.request(path, 401)
        for path in ('/manage/users/create', '/manage/users/update', '/manage/users/revoke', '/profile/save', '/profile/password'):
            admin.request(path, 401, {})
        admin.login()
        original = admin.cookies[cookie_name]
        from browser_errors import check_authenticated_browser_errors
        check_authenticated_browser_errors(admin)
        html = admin.request('/manage/users', 200)
        assert 'Local users' in html and 'User and profile activity' in html
        assert 'fixture-admin' in html and 'account.bootstrap' in html
        assert password not in html
        admin.request('/profile?id=another-user', 400)
        admin.request('/manage/users?role=admin', 400)
        version = state('fixture-admin')[1]
        post(admin, '/manage/users/update', {'id': state('fixture-admin')[0], 'version': str(version),
             'role': 'nergal:auditor', 'enabled': 'true'}, 400)
        assert state('fixture-admin')[1] == version
        assert 'Keep at least one enabled' in admin.request('/manage/users', 200)
        fields = {'userName': 'fixture-auditor', 'password': password, 'role': 'nergal:auditor'}
        admin.request('/manage/users/create', 400, fields)
        post(admin, '/manage/users/create', {**fields, 'unknown': 'not-accepted'}, 400)
        admin.request('/manage/users/create', 400, [*fields.items(), ('role', 'nergal:administrator'),
                      ('__RequestVerificationToken', admin.token('/manage/users'))])
        post(admin, '/manage/users/create', fields)
        assert admin.location == '/manage/users'
        post(admin, '/manage/users/create', fields, 400)
        assert count('AspNetUsers') == 2
        post(admin, '/manage/users/create', {'userName': 'fixture-second', 'password': password,
                                           'role': 'nergal:administrator'})
        auditor = browser_type(admin.ports, admin.tls)
        login(auditor, 'fixture-auditor')
        auditor_cookie = auditor.cookies[cookie_name]
        auditor.request('/manage/users', 403)
        from browser_errors import check_auditor_browser_errors
        check_auditor_browser_errors(auditor)
        for path in ('/manage/users/create', '/manage/users/update', '/manage/users/revoke'):
            auditor.request(path, 403, {})
        profile = auditor.request('/profile', 200)
        assert 'My profile' in profile and 'Local password' in profile
        assert 'fixture-auditor' in profile
        before = count('IdentityAudit')
        post(auditor, '/profile/save', {'version': '0', 'displayName': 'Administrator <script>fixture</script>'}, token_page='/profile')
        assert auditor.location == '/profile'
        updated = auditor.request('/profile', 200)
        assert 'Administrator &lt;script&gt;fixture&lt;/script&gt;' in updated
        assert '<script>fixture</script>' not in updated and 'Auditor' in updated
        post(auditor, '/profile/save', {'version': '0', 'displayName': 'lost edit'}, 400, '/profile')
        post(auditor, '/profile/save', {'version': '1', 'displayName': 'forged', 'actorId': 'local:another'}, 400, '/profile')
        assert count('IdentityAudit') == before + 1
        assert 'Administrator &lt;script&gt;fixture&lt;/script&gt;' not in admin.request('/profile', 200)
        auditor.request('/profile/password', 400, {'version': str(state('fixture-auditor')[1]),
                                                  'currentPassword': password, 'newPassword': password})
        target, target_version = state('fixture-auditor')
        post(admin, '/manage/users/update', {'id': target, 'version': str(target_version),
             'role': 'nergal:auditor', 'enabled': 'false'})
        auditor.request('/profile', 401)
        auditor.cookies.clear()
        login(auditor, 'fixture-auditor', expected=401)
        post(admin, '/manage/users/update', {'id': target, 'version': str(target_version),
             'role': 'nergal:administrator', 'enabled': 'true'}, 400)
        post(admin, '/manage/users/update', {'id': target, 'version': str(state('fixture-auditor')[1]),
             'role': 'nergal:auditor', 'enabled': 'true'})
        login(auditor, 'fixture-auditor')
        # Rotating a security stamp cannot resurrect a pre-disable ticket.
        replay = browser_type(admin.ports, admin.tls)
        replay.cookies[cookie_name] = auditor_cookie
        replay.request('/profile', 401)
        second = browser_type(admin.ports, admin.tls)
        login(second, 'fixture-second')
        second_cookie = second.cookies[cookie_name]
        second_id, second_version = state('fixture-second')
        post(admin, '/manage/users/update', {'id': second_id, 'version': str(second_version),
             'role': 'nergal:auditor', 'enabled': 'true'})
        second.request('/manage/users', 401)
        second.cookies[cookie_name] = second_cookie
        second.request('/profile', 401)
        post(admin, '/manage/users/revoke', {'id': target, 'version': str(state('fixture-auditor')[1])})
        auditor.request('/profile', 401)
        auditor.cookies.clear()
        login(auditor, 'fixture-auditor')
        replacement = 'synthetic changed user password 0002'
        prior_cookie = auditor.cookies[cookie_name]
        denial = post(auditor, '/profile/password', {'version': str(state('fixture-auditor')[1]),
                      'currentPassword': 'synthetic wrong current password', 'newPassword': replacement}, 400, '/profile')
        assert replacement not in denial and 'synthetic wrong current password' not in denial
        post(auditor, '/profile/password', {'version': str(state('fixture-auditor')[1]),
             'currentPassword': password, 'newPassword': replacement}, token_page='/profile')
        assert auditor.location == '/login'
        replay.cookies[cookie_name] = prior_cookie
        replay.request('/profile', 401)
        auditor.cookies.clear()
        login(auditor, 'fixture-auditor', expected=401)
        login(auditor, 'fixture-auditor', secret=replacement)
        assert 'Administrator &lt;script&gt;fixture&lt;/script&gt;' in auditor.request('/profile', 200)
        admin.cookies[cookie_name] = original
        assert 'User and profile activity' in admin.request('/manage/users', 200)
    with host(root, tls, settings) as reopened:
        reopened.login()
        assert 'fixture-auditor' in reopened.request('/manage/users', 200)
        assert 'profile.updated' in reopened.request('/manage/users', 200)
        from browser_errors import check_unavailable_browser_page
        check_unavailable_browser_page(reopened, database)
    print('PASS: local users/profile HTTPS, last Administrator, strict forms/CSRF/RBAC, escaped identity-isolated metadata, stamp replay/password revocation, audit and restart')
