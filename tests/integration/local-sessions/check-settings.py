"""Real HTTPS settings validation, SQLite backup/restore, and native-source RBAC.

Uses disposable stores, a synthetic source and synthetic host observations.
"""
from contextlib import closing
import hashlib
import http.client
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
from urllib.parse import urlencode

import check as sessions


SETTINGS = '/manage/settings'
SAVE = SETTINGS + '/save'
CSRF = '__RequestVerificationToken'
TOKEN = 'settingsToken'
OBSERVATION_FIXTURE = (Path(__file__).resolve().parents[1] / 'controller-sql' / 'bin' / 'Release' /
                       'net10.0' / 'Nergal.ControllerSql.Fixture.dll')


class Fields(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = {}
        self.switches = {}
        self.select = None
        self.first = True
        self.in_settings = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'form':
            self.in_settings = a.get('action') == SAVE
        if not self.in_settings:
            return
        if tag == 'input' and a.get('role') == 'switch':
            self.switches[a['name']] = a
        if tag == 'input' and a.get('name'):
            if a.get('type') in ('checkbox', 'radio') and 'checked' not in a:
                return
            self.fields[a['name']] = a.get('value', '')
        if tag == 'select':
            self.select = a.get('name')
            self.first = True
        if tag == 'option' and self.select:
            if self.first or 'selected' in a:
                self.fields[self.select] = a.get('value', '')
            self.first = False

    def handle_endtag(self, tag):
        if tag == 'form':
            self.in_settings = False
        elif tag == 'select':
            self.select = None


def parse_fields(html):
    fields = Fields()
    fields.feed(html)
    fields.close()
    return fields


def settings_fields(browser):
    fields = parse_fields(browser.request(SETTINGS, 200)).fields
    assert fields.get(CSRF) and fields.get(TOKEN), 'Settings form must render both tokens'
    return fields


def post(browser, fields, expected):
    connection = http.client.HTTPSConnection('127.0.0.1', browser.ports['https'], context=browser.tls, timeout=10)
    try:
        connection.request('POST', SAVE, urlencode(fields),
                           {'Content-Type': 'application/x-www-form-urlencoded',
                            'Cookie': '; '.join(f'{k}={v}' for k, v in browser.cookies.items())})
        response = connection.getresponse()
        body = response.read().decode()
        assert response.status == expected, f'{SAVE}: expected {expected}, received {response.status}'
        if expected == 302:
            assert response.getheader('Location') == SETTINGS + '?notice=saved'
        return body
    finally:
        connection.close()


def open_readonly(database, *, main_file_only=False):
    query = '?mode=ro&immutable=1' if main_file_only else '?mode=ro'
    return closing(sqlite3.connect(database.as_uri() + query, uri=True))


def read_history(db):
    versions = db.execute('''
        SELECT version, form_token, settings_json, audit_sequence FROM system_settings ORDER BY version
    ''').fetchall()
    audit = db.execute('''
        SELECT sequence, timestamp_utc, actor_id, actor_role, action, target, revision, outcome, detail_code
        FROM audit_log ORDER BY sequence
    ''').fetchall()
    objects = db.execute('SELECT * FROM reusable_object_versions ORDER BY object_id, version').fetchall()
    hosts = db.execute('SELECT * FROM hosts ORDER BY id').fetchall()
    observations = db.execute('SELECT * FROM host_observations ORDER BY host_id').fetchall()
    return versions, audit, objects, hosts, observations


def history(database):
    with open_readonly(database) as db:
        return read_history(db)


def assert_settings_history(snapshot, names):
    versions, audit = snapshot[:2]
    assert [row[0] for row in versions] == list(range(len(names)))
    assert [json.loads(row[2])['branding']['applicationName'] for row in versions] == names
    assert len({row[1] for row in versions}) == len(names), 'Each settings version must have its own token'
    assert versions[0][3] is None, 'Default settings must have no settings audit event'
    events = [row for row in audit if row[4] == 'settings.update']
    assert len(events) == len(names) - 1
    for (version, token, settings_json, sequence), event in zip(versions[1:], events):
        assert event[0] == sequence, f'Settings version {version} must reference its audit event'
        assert event[3:-1] == ('nergal:administrator', 'settings.update', 'system', None, 'succeeded')
        binding = hashlib.sha256((token + settings_json).encode('utf-8')).hexdigest()
        assert event[-1] == f'settings.version:{version}:{binding}', f'Incorrect audit binding for settings version {version}'


def assert_conflict(browser, fields, current):
    response = post(browser, fields, 409)
    assert 'System settings changed while you were editing' in response
    shown = parse_fields(response).fields
    for name in ('applicationName', TOKEN):
        assert shown[name] == current[name], f'Conflict must display current {name}'


def check_initial_save(browser, database):
    initial = history(database)
    assert_settings_history(initial, ['nergal'])
    html = browser.request(SETTINGS, 200)
    assert html.count('role="switch"') == 5
    assert 'do not reconfigure the running services' in html
    assert 'synthetic' in browser.request('/manage/sources', 200)
    fields = parse_fields(html)
    assert set(fields.switches) == {'localAuthEnabled', 'oidcEnabled', 'ldapEnabled', 'ldapUseStartTls', 'requireChangeSummary'}
    assert all(a.get('aria-label') for a in fields.switches.values())
    assert fields.fields[TOKEN] == initial[0][0][1]
    edit = {**fields.fields, 'applicationName': 'Synthetic Console'}
    post(browser, {**edit, 'defaultConfirmationTimeoutSeconds': '0'}, 400)
    escaped = '界' * 2048
    oversized = {**edit, 'oidcAuthorityUrl': escaped, 'oidcRedirectUri': escaped, 'ldapServerUri': escaped}
    post(browser, oversized, 413)
    post(browser, {k: v for k, v in edit.items() if k != CSRF}, 400)
    for invalid_token in ({k: v for k, v in edit.items() if k != TOKEN},
                          {**edit, TOKEN: 'malformed'},
                          [*edit.items(), (TOKEN, edit[TOKEN])]):
        assert 'settings.invalidVersion' in post(browser, invalid_token, 400)
    assert history(database) == initial, 'Invalid or denied forms must not change settings or audit'

    post(browser, edit, 302)
    saved = history(database)
    assert_settings_history(saved, ['nergal', 'Synthetic Console'])
    assert saved[0][0] == initial[0][0]
    current = settings_fields(browser)
    assert current['applicationName'] == 'Synthetic Console' and current[TOKEN] == saved[0][-1][1]
    assert_conflict(browser, {**edit, 'applicationName': 'Stale Repeat'}, current)
    assert history(database) == saved, 'A stale repeat must not change settings or audit'


def save_object_history(browser):
    fields = {'expectedVersion': '0', 'name': 'backup_clients', 'kind': 'ipv4',
              'description': 'Synthetic backup list', 'entries': '192.0.2.10'}
    browser.request('/manage/objects/save', 302, {**fields, CSRF: browser.token('/manage/objects')})
    path = browser.location
    object_id = path.split('objectId=')[1]
    browser.request('/manage/objects/save', 302, {**fields, 'id': object_id, 'expectedVersion': '1',
                    'entries': '203.0.113.10', CSRF: browser.token('/manage/objects')})
    return path


def backup_controller(source, destination, before, committed):
    # A pinned reader keeps the pre-save snapshot available in the main file.
    # Read the backup source through a different connection so it can see the new commit.
    with open_readonly(source, main_file_only=True) as main_file:
        assert read_history(main_file) == before, 'Fixture must keep new controller records in the WAL'
    destination.touch(mode=0o600, exist_ok=False)
    with open_readonly(source) as live, closing(sqlite3.connect(destination)) as backup:
        assert live.execute('PRAGMA journal_mode').fetchone() == ('wal',)
        live.backup(backup)
    with open_readonly(destination, main_file_only=True) as backup:
        assert read_history(backup) == committed, 'The standalone backup must include committed WAL changes'


def check_observation_fixture(phase, directory):
    subprocess.run(['dotnet', OBSERVATION_FIXTURE, 'sqlite-observations', phase, directory], check=True, timeout=30)


def check_immutable_history(database, expected):
    with closing(sqlite3.connect(database)) as db:
        for table, key, value, message in (
            ('system_settings', 'version', 1, 'settings versions are immutable'),
            ('reusable_object_versions', 'version', 1, 'object history is immutable'),
            ('audit_log', 'sequence', 1, 'audit log is append-only'),
        ):
            for sql in (f'UPDATE {table} SET {key} = {key} WHERE {key} = ?',
                        f'DELETE FROM {table} WHERE {key} = ?'):
                try:
                    with db:
                        db.execute(sql, (value,))
                        raise AssertionError(f'Restored database accepted {sql}')
                except sqlite3.IntegrityError as error:
                    assert str(error) == message
        assert read_history(db) == expected


def check_restored_writes(root, tls, settings, browser, source, backup, backed_up, object_path):
    restored = root / 'restored-controller'
    restored.mkdir(mode=0o700)
    database = restored / 'controller.db'
    shutil.copyfile(backup, database)
    database.chmod(0o600)
    assert list(restored.iterdir()) == [database]
    with open_readonly(database, main_file_only=True) as db:
        assert db.execute('PRAGMA user_version').fetchone() == (6,)
        assert db.execute('PRAGMA quick_check').fetchall() == [('ok',)]
        assert db.execute('PRAGMA foreign_key_check').fetchall() == []
    check_observation_fixture('verify', restored)
    check_immutable_history(database, backed_up)

    source_parent = settings_fields(browser)
    post(browser, {**source_parent, 'applicationName': 'Source Branch'}, 302)
    source_form = settings_fields(browser)
    source_history = history(source)
    assert_settings_history(source_history, ['nergal', 'Synthetic Console', 'Source Branch'])

    with sessions.host(root, tls, {**settings, 'ControllerState__Directory': str(restored)}) as restored_browser:
        restored_browser.login()
        restored_parent = settings_fields(restored_browser)
        assert restored_parent['applicationName'] == 'Synthetic Console'
        assert restored_parent[TOKEN] == source_parent[TOKEN] == backed_up[0][-1][1]
        assert '192.0.2.10/32' in restored_browser.request(object_path + '&version=1', 200)
        assert '203.0.113.10/32' in restored_browser.request(object_path, 200)
        assert history(database) == backed_up

        post(restored_browser, {**restored_parent, 'applicationName': 'Restored Branch'}, 302)
        restored_form = settings_fields(restored_browser)
        divergent_history = history(database)
        assert_settings_history(divergent_history, ['nergal', 'Synthetic Console', 'Restored Branch'])
        for versions, audit, *records in (source_history, divergent_history):
            assert (versions[:-1], audit[:-1], *records) == backed_up
        assert source_history[0][-1][:2] == (2, source_form[TOKEN])
        assert divergent_history[0][-1][:2] == (2, restored_form[TOKEN])
        assert source_form[TOKEN] != restored_form[TOKEN], 'Equal versions on divergent histories must have different tokens'

        # Keep antiforgery valid on the restore so only the settings token is stale.
        stale = {**source_form, CSRF: restored_form[CSRF], 'applicationName': 'Stale Source Edit'}
        assert_conflict(restored_browser, stale, restored_form)
        assert history(database) == divergent_history, 'A divergent stale token must not change settings or audit'

        post(restored_browser, {**restored_form, 'applicationName': 'Restored Console'}, 302)
        final = history(database)
        assert_settings_history(final, ['nergal', 'Synthetic Console', 'Restored Branch', 'Restored Console'])
        assert (final[0][:-1], final[1][:-1], *final[2:]) == divergent_history
        saved_form = settings_fields(restored_browser)
        assert (saved_form['applicationName'], saved_form[TOKEN]) == ('Restored Console', final[0][-1][1])

    # The hosts share the synthetic account store, and restored login rotates its session stamp.
    browser.cookies.clear()
    browser.login()
    current_source = settings_fields(browser)
    assert (current_source['applicationName'], current_source[TOKEN]) == ('Source Branch', source_form[TOKEN])
    assert history(source) == source_history, 'Restored writes must leave the source database unchanged'


def main():
    assert OBSERVATION_FIXTURE.is_file(), 'Build the Release controller SQL fixture first'
    with tempfile.TemporaryDirectory(prefix='ng-settings-') as directory:
        root = Path(directory)
        root.chmod(0o700)
        tls = sessions.provision(root)
        state = root / 'controller'; state.mkdir(mode=0o700)
        subprocess.run(['dotnet', sessions.ADMIN_TOOL, 'controller', 'init', state], check=True)
        sources = root / 'sources'; sources.mkdir(mode=0o700)
        (sources / 'synthetic.conf').write_text('table inet synthetic { }\n')
        settings = {'ControllerState__Enabled': 'true', 'ControllerState__Directory': str(state),
                    'NativeSources__Directory': str(sources)}
        database = state / 'controller.db'
        backup_directory = root / 'backup'
        backup_directory.mkdir(mode=0o700)
        backup = backup_directory / 'controller.db'
        with sessions.host(root, tls, settings) as browser:
            browser.login()
            with open_readonly(database) as pinned:
                pinned.execute('BEGIN')
                before = read_history(pinned)
                assert before[3:] == ([], []), 'The pinned snapshot must predate host registration and observation'
                check_initial_save(browser, database)
                object_path = save_object_history(browser)
                check_observation_fixture('seed', state)
                backed_up = history(database)
                assert [row[1] for row in backed_up[2]] == [1, 2]
                assert [row[4] for row in backed_up[1]] == ['settings.update', 'object.create', 'object.version', 'host.register']
                assert [len(rows) for rows in backed_up[3:]] == [1, 1], 'The backup must capture the registered host and its observation'
                backup_controller(database, backup, before, backed_up)
            check_restored_writes(root, tls, settings, browser, database, backup, backed_up, object_path)
            source_fields = settings_fields(browser)
        before_auditor = history(database)
        auditor = root / 'auditor'; auditor.mkdir(mode=0o700)
        subprocess.run(['dotnet', sessions.ADMIN_TOOL, 'account', 'init', auditor], check=True)
        subprocess.run(['dotnet', sessions.ADMIN_TOOL, 'account', 'provision', auditor, 'fixture-admin', '--role', 'auditor', '--password-stdin'],
                       input=sessions.PASSWORD.encode() + b'\n', check=True)
        with sessions.host(root, tls, {**settings, 'LocalSessions__AccountDirectory': str(auditor)}) as browser:
            browser.login()
            readonly_fields = parse_fields(browser.request(SETTINGS, 200))
            assert len(readonly_fields.switches) == 5
            assert all('disabled' in a and a.get('aria-label') for a in readonly_fields.switches.values())
            browser.request('/manage/sources', 403)
            post(browser, {**source_fields, CSRF: readonly_fields.fields[CSRF]}, 403)
        assert history(database) == before_auditor, 'Auditor attempts must leave source history unchanged'
    print('PASS: HTTPS settings validation, CSRF and RBAC, immutable versions and audit, WAL observation backup, restored writes and divergent stale forms')


if __name__ == '__main__':
    main()
