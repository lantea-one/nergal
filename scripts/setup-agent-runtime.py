"""Generate a private Codex catalog that selects the depth-enforced V1 backend.

Only backend metadata changes. Model identifiers, capabilities and instructions
remain supplied by the installed Codex binary. Never commit the derived catalog.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def select_v1(catalog):
    """Return a defensive V1 catalog, preserving explicitly disabled agent capabilities."""
    result = json.loads(json.dumps(catalog))
    models = result.get('models')
    if not isinstance(models, list) or not models:
        raise ValueError('agent.catalogShape')
    names = set()
    for model in models:
        if not isinstance(model, dict) or not isinstance(model.get('slug'), str) or not model['slug'] or model['slug'] in names:
            raise ValueError('agent.catalogModel')
        names.add(model['slug'])
        backend = model.get('multi_agent_version')
        if backend not in (None, 'v1', 'v2', 'disabled'):
            raise ValueError('agent.catalogBackend')
        if backend != 'disabled':
            model['multi_agent_version'] = 'v1'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--codex', default='codex', help='Installed Codex executable.')
    args = parser.parse_args()
    # Work outside this repository so a missing derived catalog cannot prevent
    # the very command that creates it from loading the project configuration.
    with tempfile.TemporaryDirectory(prefix='nergal-agent-catalog-') as temporary:
        run = subprocess.run([args.codex, '-C', temporary, 'debug', 'models', '--bundled'],
                             cwd=temporary, capture_output=True, text=True, check=True)
    catalog = select_v1(json.loads(run.stdout))
    directory = ROOT / 'artifacts/codex-agent-runtime'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    destination = directory / 'models.json'
    descriptor, pending = tempfile.mkstemp(prefix='models-', suffix='.pending', dir=directory)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(catalog, stream)
            stream.write('\n')
        os.replace(pending, destination)
    finally:
        Path(pending).unlink(missing_ok=True)
    print(f'Prepared private V1 catalog for {len(catalog["models"])} installed models.')
    print('Start a fresh Codex session to load it; existing sessions are unchanged.')


if __name__ == '__main__':
    main()
