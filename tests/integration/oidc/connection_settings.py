"""UI-only OIDC setup, retired trust, write-only secrets and restart using the real protocol fixture."""
import sqlite3


def exercise_connections(temp, sessions, provider, host_settings, RelyingParty):
    tls = sessions.provision(temp)
    with provider(temp) as (op, cert):
        bootstrap = host_settings(op, cert)
        settings = {k: v for k, v in bootstrap.items() if not k.startswith('Oidc__')}
        path = '/manage/identity/connection'
        fields = {'version': '0', 'enabled': 'true', 'issuer': op.issuer, 'clientId': op.client,
                  'callbackUri': op.callback, 'groupClaim': 'groups', 'administratorGroups': 'fixture-admins',
                  'auditorGroups': 'fixture-auditors', 'clientSecret': op.secret, 'confirm': 'replace-trust'}
        database = temp / 'accounts/accounts.db'
        with sessions.host(temp, tls, settings) as browser:
            admin = RelyingParty(browser)
            admin.request('/login/oidc', 404, {})
            assert 'Sign in with identity provider' not in admin.request('/login', 200)[0]
            admin.request('/login', 302, {'username': 'fixture-admin', 'password': sessions.PASSWORD,
                '__RequestVerificationToken': admin.token('/login')})
            page = admin.request(path, 200)[0]
            assert 'Save and replace provider settings' in page and 'No UI-managed connection' in page
            assert op.secret not in page

            def post(values, expected=302):
                page = admin.request(path + '/save', expected, {**values, '__RequestVerificationToken': admin.token(path)})[0]
                assert op.secret not in page

            admin.request(path + '/save', 400, fields)
            for change in [{'extra': 'x'}, {'enabled': 'false'}, {'issuer': 'http://identity.example.test'},
                           {'callbackUri': op.callback + '?next=x'}, {'administratorGroups': 'same', 'auditorGroups': 'same'},
                           {'clientSecret': ''}, {'confirm': 'unconfirmed'}]:
                post({**fields, **change}, 400)
            admin.request(path + '/save', 400, [*fields.items(), ('issuer', 'https://other.example.test'),
                ('__RequestVerificationToken', admin.token(path))])
            with sqlite3.connect(database) as db:
                assert db.execute('SELECT count(*) FROM OidcConnection').fetchone()[0] == 0
            post(fields)
            page = admin.request(path, 200)[0]
            assert 'A secret is stored' in page and op.secret not in page
            with sqlite3.connect(database) as db:
                encrypted = db.execute('SELECT ProtectedSecret FROM OidcConnection').fetchone()[0]
                assert op.secret not in encrypted
            post(fields, 400)  # stale expected version
            external = RelyingParty(browser)
            external.exchange(op, cert, 302)
            external.request('/session', 200)
            post({**fields, 'version': '1', 'issuer': 'https://other.example.test', 'clientSecret': ''}, 400)
            # Even an authenticated external Administrator cannot replace provider trust.
            external.request(path + '/save', 400, {**fields, 'version': '1', '__RequestVerificationToken': external.token(path)})
            # Save between authorization and callback: the outstanding state and old cookie both retire.
            pending = RelyingParty(browser)
            def disable(_):
                post({k: v for k, v in {**fields, 'version': '1', 'clientSecret': ''}.items() if k != 'enabled'})
            pending.exchange(op, cert, 401, alter_form=disable)
            external.request('/session', 401)
            assert 'Sign in with identity provider' not in pending.request('/login', 200)[0]
            pending.request('/login/oidc', 404, {'__RequestVerificationToken': pending.token('/login')})
            # Disabling never affects the independent local Administrator.
            admin.request('/session', 200)
            post({**fields, 'version': '2', 'clientSecret': ''})
            fresh = RelyingParty(browser)
            fresh.exchange(op, cert, 302)
            fresh.request('/session', 200)
            external.request('/session', 401)
            op.overrides = {'groups': ['fixture-auditors']}
            auditor = RelyingParty(browser)
            auditor.exchange(op, cert, 302)
            auditor.request(path, 403)
            auditor.request(path + '/save', 403, {})
            op.overrides = {}
            # A still-enabled replacement also rejects protected old state before code redemption.
            token_requests = op.token_requests
            retired = RelyingParty(browser)
            retired.exchange(op, cert, 401, alter_form=lambda _: post({**fields, 'version': '3', 'clientSecret': ''}))
            assert op.token_requests == token_requests
            fresh.request('/session', 401)
            fresh = RelyingParty(browser)
            fresh.exchange(op, cert, 302)
            # A failed audit cannot replace live trust or invalidate an otherwise current ticket.
            with sqlite3.connect(database) as db:
                db.execute("CREATE TRIGGER fixture_provider_failure BEFORE INSERT ON IdentityAudit BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END")
            post({**fields, 'version': '4', 'clientSecret': 'synthetic-replacement'}, 503)
            fresh.request('/session', 200)
            with sqlite3.connect(database) as db:
                assert db.execute('SELECT Version,ProtectedSecret FROM OidcConnection').fetchone() == (4, encrypted)
                db.execute('DROP TRIGGER fixture_provider_failure')
        with sessions.host(temp, tls, settings) as browser:
            fresh = RelyingParty(browser)
            assert 'Sign in with identity provider' in fresh.request('/login', 200)[0]
            fresh.exchange(op, cert, 302)
            fresh.request('/session', 200)
        print('PASS: UI-only OIDC activation, encrypted write-only secret retention, retired sessions/callbacks, local fallback, CSRF/RBAC/audit denial and restart')
