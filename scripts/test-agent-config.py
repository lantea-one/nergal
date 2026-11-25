"""Deterministic denial checks for delegation configuration and catalog-only backend adaptation."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = load('agent_policy', ROOT / 'scripts/verify-agent-config.py')
setup = load('agent_setup', ROOT / 'scripts/setup-agent-runtime.py')


class AgentPolicyTests(unittest.TestCase):
    """Rejected configuration must not silently weaken limits, roles or inherited permissions."""

    def test_repository_contract(self):
        self.assertEqual(9, len(policy.check_project(ROOT)))

    def test_unsafe_or_ignored_configuration_is_rejected(self):
        mutations = [
            ('.codex/config.toml', 'max_concurrent_threads_per_session = 4', 'max_concurrent_threads_per_session = 5'),
            ('.codex/config.toml', 'max_depth = 1', 'max_depth = 2'),
            ('.codex/config.toml', 'multi_agent_v2 = false', 'multi_agent_v2 = true'),
            ('.codex/config.toml', '../artifacts/codex-agent-runtime/models.json', '/tmp/foreign-models.json'),
            ('.codex/config.toml', 'agents/code_explorer.toml', '../../../foreign.toml'),
            ('.codex/agents/code_explorer.toml', 'model = "gpt-6-luna"', 'model = "unknown-model"'),
            ('.codex/agents/code_explorer.toml', 'name = "code_explorer"', 'name = "another-role"'),
            ('.codex/agents/code_explorer.toml', 'model_reasoning_effort = "high"', 'model_reasoning_effort = "ultra"'),
        ]
        for path, before, after in mutations:
            with self.subTest(path=path, after=after), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                shutil.copytree(ROOT / '.codex', root / '.codex')
                file = root / path
                content = file.read_text()
                self.assertIn(before, content)
                file.write_text(content.replace(before, after))
                with self.assertRaises(policy.AgentConfigurationError):
                    policy.check_project(root)
        for extra in ['\n[agents]\nenabled = false\n', '\nsandbox_mode = "danger-full-access"\n', '\napproval_policy = "never"\n']:
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                shutil.copytree(ROOT / '.codex', root / '.codex')
                file = root / '.codex/agents/code_explorer.toml'
                file.write_text(file.read_text() + extra)
                with self.assertRaises(policy.AgentConfigurationError):
                    policy.check_project(root)

    def test_missing_or_unregistered_profiles_are_rejected(self):
        for missing in [True, False]:
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                shutil.copytree(ROOT / '.codex', root / '.codex')
                if missing:
                    (root / '.codex/agents/code_explorer.toml').unlink()
                else:
                    (root / '.codex/agents/unregistered.toml').write_text('name = "extra"')
                with self.assertRaises(policy.AgentConfigurationError):
                    policy.check_project(root)

    def test_catalog_changes_only_backend_metadata_and_defensively_copies(self):
        source = {'models': [{'slug': 'synthetic-model', 'multi_agent_version': 'v2',
                              'base_instructions': 'synthetic instructions', 'capabilities': ['tools']}]}
        before = json.dumps(source, sort_keys=True)
        result = setup.select_v1(source)
        self.assertEqual(before, json.dumps(source, sort_keys=True))
        expected = json.loads(before)
        expected['models'][0]['multi_agent_version'] = 'v1'
        self.assertEqual(expected, result)
        result['models'][0]['capabilities'].append('changed')
        self.assertEqual(['tools'], source['models'][0]['capabilities'])

    def test_disabled_model_agent_capabilities_are_not_enabled(self):
        source = {'models': [{'slug': 'synthetic-disabled', 'multi_agent_version': 'disabled'}]}
        self.assertEqual(source, setup.select_v1(source))

    def test_malformed_catalogs_never_produce_partial_runtime_configuration(self):
        for catalog in [{}, {'models': []}, {'models': [None]}, {'models': [{'slug': ''}]},
                        {'models': [{'slug': 'same'}, {'slug': 'same'}]},
                        {'models': [{'slug': 'synthetic-model', 'multi_agent_version': 'unknown'}]}]:
            with self.subTest(catalog=catalog), self.assertRaises(ValueError):
                setup.select_v1(catalog)


if __name__ == '__main__':
    unittest.main()
