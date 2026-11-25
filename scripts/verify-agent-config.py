"""Validate the repository's explicit agent roles and enforceable delegation policy."""
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]
ROLE_MODELS = {
    'code_explorer': 'gpt-6-luna',
    'dotnet_engineer': 'gpt-6.2-sol',
    'nftables_engineer': 'gpt-6.2-astra',
    'identity_security': 'gpt-6.2-astra',
    'database_engineer': 'gpt-6.2-sol',
    'ui_engineer': 'gpt-6.2-sol',
    'browser_qa': 'gpt-6.1-terra',
    'verification_engineer': 'gpt-6.2-sol',
    'docs_release': 'gpt-6-luna',
}


HIGH_REASONING_ROLES = {'nftables_engineer', 'identity_security'}


class AgentConfigurationError(ValueError):
    """A stable, value-free repository agent policy violation."""


def check_project(root):
    """Check public configuration without loading credentials, Codex or private catalog contents."""
    config = tomllib.loads((root / '.codex/config.toml').read_text())
    if set(config) != {'model_catalog_json', 'features', 'agents'}:
        raise AgentConfigurationError('agent.rootKeys')
    if config['model_catalog_json'] != '../artifacts/codex-agent-runtime/models.json':
        raise AgentConfigurationError('agent.privateCatalog')
    if config['features'] != {'multi_agent_v2': False}:
        raise AgentConfigurationError('agent.backend')
    agents = config['agents']
    settings = {'enabled', 'max_concurrent_threads_per_session', 'max_depth',
                'default_subagent_model', 'default_subagent_reasoning_effort'}
    if set(agents) != settings | set(ROLE_MODELS):
        raise AgentConfigurationError('agent.roleRegistry')
    if agents['enabled'] is not True:
        raise AgentConfigurationError('agent.disabled')
    if type(agents['max_concurrent_threads_per_session']) is not int or agents['max_concurrent_threads_per_session'] != 4:
        raise AgentConfigurationError('agent.concurrency')
    if type(agents['max_depth']) is not int or agents['max_depth'] != 1:
        raise AgentConfigurationError('agent.depth')
    if agents['default_subagent_model'] != 'gpt-6.2-sol' or agents['default_subagent_reasoning_effort'] != 'medium':
        raise AgentConfigurationError('agent.defaultModel')
    files = {p.name for p in (root / '.codex/agents').glob('*.toml')}
    if files != {name + '.toml' for name in ROLE_MODELS}:
        raise AgentConfigurationError('agent.roleFiles')
    for name, model in ROLE_MODELS.items():
        registration = agents[name]
        if set(registration) != {'description', 'config_file'} or registration['config_file'] != f'agents/{name}.toml':
            raise AgentConfigurationError('agent.rolePath')
        profile = root / '.codex/agents' / (name + '.toml')
        if profile.is_symlink():
            raise AgentConfigurationError('agent.roleSymlink')
        role = tomllib.loads(profile.read_text())
        # Role files accept only effective overrides. In particular, per-child
        # agents/sandbox/approval settings would be ignored by current Codex.
        if set(role) != {'name', 'description', 'model', 'model_reasoning_effort', 'developer_instructions'}:
            raise AgentConfigurationError('agent.roleKeys')
        effort = 'high' if name in HIGH_REASONING_ROLES else 'medium'
        if role['name'] != name or role['model'] != model or role['model_reasoning_effort'] != effort:
            raise AgentConfigurationError('agent.roleModel')
        if not isinstance(role['description'], str) or not role['description'].strip() or role['description'] != registration['description']:
            raise AgentConfigurationError('agent.description')
        if not isinstance(role['developer_instructions'], str) or not role['developer_instructions'].strip():
            raise AgentConfigurationError('agent.instructions')
    return tuple(ROLE_MODELS)


if __name__ == '__main__':
    roles = check_project(ROOT)
    print(f'PASS: {len(roles)} registered specialist roles; four-child ceiling; V1 catalog selection; depth one.')
    print('Runtime activation additionally requires the private catalog and a fresh trusted Codex runtime process.')
