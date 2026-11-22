"""Real HTTPS settings validation, CSRF, audit persistence, and native-source RBAC.

Uses only disposable application stores and a synthetic source; no firewall commands.
"""
import http.client
from html.parser import HTMLParser
from pathlib import Path
import sqlite3
import subprocess
import tempfile
from urllib.parse import urlencode

import check as sessions


class Fields(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = {}
        self.select = None
        self.first = True

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
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
        if tag == 'select':
            self.select = None


def post(browser, fields):
    connection = http.client.HTTPSConnection('127.0.0.1', browser.ports['https'], context=browser.tls, timeout=10)
    try:
        connection.request('POST', '/manage/settings/save', urlencode(fields),
                           {'Content-Type': 'application/x-www-form-urlencoded',
                            'Cookie': '; '.join(f'{k}={v}' for k, v in browser.cookies.items())})
        response = connection.getresponse()
        body = response.read().decode()
        return response.status, body
    finally:
        connection.close()


def main():
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
        with sessions.host(root, tls, settings) as browser:
            browser.login()
            html = browser.request('/manage/settings', 200)
            assert 'do not reconfigure the running services' in html
            assert 'synthetic' in browser.request('/manage/sources', 200)
            fields = Fields(); fields.feed(html)
            # The login notice is optional and textarea controls have no default value here.
            fields.fields['applicationName'] = 'Synthetic Console'
            invalid = {**fields.fields, 'defaultConfirmationTimeoutSeconds': '0'}
            assert post(browser, invalid)[0] == 400
            assert post(browser, {k: v for k, v in fields.fields.items() if k != '__RequestVerificationToken'})[0] == 400
            status, body = post(browser, fields.fields)
            assert status == 302, f'Valid settings save returned {status}: {body[:100]}'
            assert 'Synthetic Console' in browser.request('/manage/settings', 200)
        auditor = root / 'auditor'; auditor.mkdir(mode=0o700)
        subprocess.run(['dotnet', sessions.ADMIN_TOOL, 'account', 'init', auditor], check=True)
        subprocess.run(['dotnet', sessions.ADMIN_TOOL, 'account', 'provision', auditor, 'fixture-admin', '--role', 'auditor', '--password-stdin'],
                       input=sessions.PASSWORD.encode() + b'\n', check=True)
        with sessions.host(root, tls, {**settings, 'LocalSessions__AccountDirectory': str(auditor)}) as browser:
            browser.login()
            browser.request('/manage/settings', 200)
            browser.request('/manage/sources', 403)
            fields.fields['__RequestVerificationToken'] = browser.token('/manage/settings')
            assert post(browser, fields.fields)[0] == 403
        with sqlite3.connect(state / 'controller.db') as db:
            assert db.execute("SELECT count(*) FROM audit_log WHERE action='settings.update'").fetchone() == (1,)
    print('PASS: HTTPS settings save/invalid/CSRF denial, audit persistence, auditor mutation and private-source denial')


if __name__ == '__main__':
    main()
