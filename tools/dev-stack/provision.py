"""Provision disposable local UI state; private inputs never enter a build context."""
import argparse
import os
from pathlib import Path
import secrets
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'artifacts/dev-stack'
PRIVATE = BASE / 'private'
ADMIN = BASE / 'admin/nergal-admin.dll'


def run(*args, **kwargs):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', action='append', default=[], type=Path,
                        help='Private nftables.conf to copy for read-only inspection; repeatable.')
    args = parser.parse_args()
    os.umask(0o077)
    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in ('accounts', 'keys', 'controller'):
        (PRIVATE / name).mkdir(mode=0o700, exist_ok=True)
    # Container and host use different absolute paths. Provision with the container
    # paths via a disposable container, never changing system accounts or groups.
    container = ['docker', 'run', '--rm', '--network', 'none', '--cap-drop', 'ALL',
                 '--security-opt', 'no-new-privileges', '--user', f'{os.getuid()}:{os.getgid()}',
                 '-v', f'{BASE / "admin"}:/app:ro', '-v', f'{PRIVATE}:/state',
                 'mcr.microsoft.com/dotnet/aspnet:10.0.15', 'dotnet', '/app/nergal-admin.dll']
    if not (PRIVATE / 'accounts/accounts.db').exists():
        run(*container, 'account', 'init', '/state/accounts')
        password = secrets.token_urlsafe(24)
        subprocess.run([*container[:3], '-i', *container[3:], 'account', 'provision',
                        '/state/accounts', 'sandbox-admin', '--password-stdin'],
                       input=(password + '\n').encode(), check=True, stdout=subprocess.DEVNULL)
        (PRIVATE / 'access.txt').write_text('Local disposable sandbox only\nUsername: sandbox-admin\nPassword: ' + password + '\n')
    if not (PRIVATE / 'controller/controller.db').exists():
        run(*container, 'controller', 'init', '/state/controller')
    if not (PRIVATE / 'tls.crt').exists():
        for name in ('tls', 'wrapping'):
            run('openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '30',
                '-subj', '/CN=nergal-local-sandbox', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
                '-keyout', str(PRIVATE / f'{name}.key'), '-out', str(PRIVATE / f'{name}.crt'), stderr=subprocess.DEVNULL)
        run('openssl', 'pkcs12', '-export', '-inkey', str(PRIVATE / 'wrapping.key'), '-in', str(PRIVATE / 'wrapping.crt'),
            '-out', str(PRIVATE / 'wrapping.pfx'), '-passout', 'pass:')
    sources = BASE / 'sources'
    sources.mkdir(mode=0o700, exist_ok=True)
    mapping = BASE / 'source-map.txt'
    if args.source:
        mapping.write_text('\n'.join(str(p.resolve()) for p in args.source) + '\n')
    elif mapping.exists():
        args.source = [Path(p) for p in mapping.read_text().splitlines()]
    for source in args.source:
        if not source.is_file() or source.name != 'nftables.conf':
            raise ValueError('Expected a readable nftables.conf')
        name = source.parent.name
        if not name.isascii() or not name.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Source directory name must be an ASCII identifier')
        shutil.copyfile(source, sources / f'{name}.conf')
    # Generated private Compose overrides keep source names out of public examples.
    validators = ['services:']
    for index, source in enumerate(sorted(sources.glob('*.conf'))):
        target = BASE / 'reports' / source.stem
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        validators.extend([
            f'  source-check-{index + 1}:',
            '    image: nergal-source-validator:local',
            '    build:', f'      context: {ROOT / "tools/dev-stack"}', '      dockerfile: Validator.Dockerfile',
            '    restart: unless-stopped', '    network_mode: none', '    read_only: true',
            '    cap_drop: [ALL]', '    cap_add: [NET_ADMIN, DAC_OVERRIDE]', '    security_opt: [no-new-privileges:true]',
            '    volumes:', f'      - {source}:/source.nft:ro', f'      - {target}:/report',
            '    tmpfs: ["/tmp:mode=1777,size=16m"]',
        ])
    if len(validators) == 1:
        validators = ['services: {}']
    (BASE / 'sources.compose.yaml').write_text('\n'.join(validators) + '\n')
    print('Private sandbox state ready; no native configuration was executed.')


if __name__ == '__main__':
    main()
