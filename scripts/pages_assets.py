#!/usr/bin/env python3
"""Keep the documentation portal's shared application styles and theme initialization identical."""
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSETS = {
    'src/Nergal.Web/wwwroot/css/nergal.css': 'pages/assets/application.css',
    'src/Nergal.Web/wwwroot/js/theme.js': 'pages/assets/theme.js',
}


def verify_shared_assets():
    """Return drift diagnostics; copied assets must not become an independent design system."""
    return [f'Shared Pages asset is stale: {target}; run python3 scripts/pages_assets.py'
            for source, target in ASSETS.items()
            if not (ROOT / target).is_file() or (ROOT / source).read_bytes() != (ROOT / target).read_bytes()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if not args.check:
        for source, target in ASSETS.items():
            (ROOT / target).write_bytes((ROOT / source).read_bytes())
    errors = verify_shared_assets()
    if errors:
        print('\n'.join(errors))
        return 1
    print('PASS: Pages application stylesheet and theme initialization are identical.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
