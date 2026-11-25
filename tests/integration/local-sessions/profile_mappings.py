"""Real mapping forms exercise strict input, CSRF and current Administrator authority without contacting a provider."""
import sqlite3


def check_profile_mappings(admin, auditor, database):
    path = '/manage/identity/profiles'
    assert 'Manage OIDC profile defaults' in admin.request('/profile', 200)
    auditor.request(path, 403)
    auditor.request(path + '/save', 403, {})
    admin.request(path + '?issuer=unselected', 400)
    fields = {'issuer': 'https://identity.example.test', 'version': '0', 'enabled': 'true',
              'displayNameClaim': 'name', 'givenNameClaim': 'given_name', 'familyNameClaim': 'family_name', 'emailClaim': 'email'}

    def count():
        with sqlite3.connect(database) as db:
            return db.execute('SELECT count(*) FROM IdentityAudit').fetchone()[0]

    def post(values, expected=302):
        return admin.request(path + '/save', expected, {**values, '__RequestVerificationToken': admin.token(path)})

    before = count()
    admin.request(path + '/save', 400, fields)
    for bad in ({'unexpected': 'x'}, {'issuer': 'http://identity.example.test'}, {'displayNameClaim': 'groups'},
                {'givenNameClaim': '$.nested.given'}, {'enabled': 'false'}):
        post({**fields, **bad}, 400)
    admin.request(path + '/save', 400, [*fields.items(), ('issuer', 'https://other.example.test'),
                  ('__RequestVerificationToken', admin.token(path))])
    assert count() == before
    post(fields)
    assert admin.location == path
    page = admin.request(path, 200)
    assert 'https://identity.example.test' in page and 'version 1' in page
    assert 'role="switch"' in page and 'literal top-level claim names' in page
    post(fields, 400)
    off = {k: v for k, v in fields.items() if k != 'enabled'}
    post({**off, 'version': '1'})
    with sqlite3.connect(database) as db:
        assert db.execute('SELECT Version,Enabled,GivenNameClaim FROM OidcProfileMap').fetchone() == (2, 0, 'given_name')
        assert db.execute('SELECT count(*) FROM OidcProfileObservation').fetchone()[0] == 0
    assert count() == before + 2
    print('PASS: exact-issuer profile-mapping forms, literal selectors, switch off-state, versioning, CSRF/RBAC and denied ambiguity')
