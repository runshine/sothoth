from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List

from agent_ai_service.config import settings
from agent_ai_service.models.agent_backend import BackendConfig
from agent_ai_service.persistence.file_store import JsonFileStore


DEFAULT_BACKENDS = {
    'claude': {
        'name': 'claude',
        'backend_type': 'claude',
        'command': 'claude',
        'args': [],
        'env': {},
        'enabled': True,
        'description': 'Claude Code CLI backend',
    },
    'codex': {
        'name': 'codex',
        'backend_type': 'codex',
        'command': 'codex',
        'args': [],
        'env': {},
        'enabled': False,
        'description': 'OpenAI Codex CLI backend',
    },
    'opencode': {
        'name': 'opencode',
        'backend_type': 'opencode',
        'command': 'opencode',
        'args': [],
        'env': {},
        'enabled': False,
        'description': 'OpenCode CLI backend',
    },
    'claude-a2a': {
        'name': 'claude-a2a',
        'backend_type': 'claude-a2a',
        'command': 'claude-a2a',
        'args': [],
        'env': {},
        'enabled': False,
        'description': 'Claude A2A bridge backend',
    },
}


class BackendRegistry:
    def __init__(self):
        self.store = JsonFileStore(settings.state_dir / 'backends.json', self._default_state)
        self._ensure_defaults()

    def _default_state(self) -> Dict[str, Any]:
        return {
            'default_backend': settings.agent_default_backend,
            'backends': deepcopy(DEFAULT_BACKENDS),
        }

    def _ensure_defaults(self) -> None:
        data = self.store.read()
        changed = False
        data.setdefault('backends', {})
        data.setdefault('default_backend', settings.agent_default_backend)
        for name, cfg in DEFAULT_BACKENDS.items():
            if name not in data['backends']:
                data['backends'][name] = deepcopy(cfg)
                changed = True
        if changed:
            self.store.write(data)

    def list(self) -> Dict[str, Any]:
        return self.store.read()

    def get(self, name: str) -> Dict[str, Any] | None:
        return self.store.read().get('backends', {}).get(name)

    def put(self, name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        data = self.store.read()
        backends = data.setdefault('backends', {})
        existing = backends.get(name, {})
        merged = {
            **existing,
            'name': name,
            'backend_type': payload.get('backend_type', existing.get('backend_type', existing.get('name', name))),
            'command': payload.get(
                'command',
                existing.get('command', payload.get('backend_type', existing.get('backend_type', name)))
            ),
            'args': payload.get('args', existing.get('args', [])),
            'env': payload.get('env', existing.get('env', {})),
            'enabled': bool(payload.get('enabled', existing.get('enabled', True))),
            'cwd': payload.get('cwd', existing.get('cwd')),
            'description': payload.get('description', existing.get('description', '')),
            'llm_provider_key': payload.get('llm_provider_key', existing.get('llm_provider_key')),
            'llm_provider_snapshot': payload.get('llm_provider_snapshot', existing.get('llm_provider_snapshot')),
            'llm_provider_applied_at': payload.get('llm_provider_applied_at', existing.get('llm_provider_applied_at')),
            'llm_provider_mapped_env_keys': payload.get('llm_provider_mapped_env_keys', existing.get('llm_provider_mapped_env_keys', [])),
        }
        backends[name] = merged
        self.store.write(data)
        return merged

    def delete(self, name: str) -> None:
        data = self.store.read()
        if data.get('default_backend') == name:
            raise ValueError('cannot delete active backend')
        data.get('backends', {}).pop(name, None)
        self.store.write(data)

    def activate(self, name: str) -> Dict[str, Any]:
        data = self.store.read()
        if name not in data.get('backends', {}):
            raise KeyError(name)
        data['default_backend'] = name
        self.store.write(data)
        return data['backends'][name]

    def replace_env(self, name: str, env: Dict[str, str]) -> Dict[str, Any]:
        data = self.store.read()
        if name not in data.get('backends', {}):
            raise KeyError(name)
        data['backends'][name]['env'] = dict(env or {})
        self.store.write(data)
        return data['backends'][name]

    def delete_env_keys(self, name: str, keys: List[str]) -> Dict[str, Any]:
        data = self.store.read()
        if name not in data.get('backends', {}):
            raise KeyError(name)
        env = data['backends'][name].setdefault('env', {})
        for key in keys:
            env.pop(key, None)
        self.store.write(data)
        return data['backends'][name]

    def to_model(self, name: str) -> BackendConfig:
        cfg = self.get(name)
        if not cfg:
            raise KeyError(name)
        return BackendConfig(
            name=name,
            backend_type=cfg.get('backend_type', cfg.get('name', name)),
            command=cfg.get('command', cfg.get('backend_type', name)),
            args=list(cfg.get('args', []) or []),
            env=dict(cfg.get('env', {}) or {}),
            enabled=bool(cfg.get('enabled', True)),
            cwd=cfg.get('cwd'),
            description=cfg.get('description', ''),
        )

    def env_keys(self, name: str) -> List[str]:
        cfg = self.get(name) or {}
        return sorted(list((cfg.get('env') or {}).keys()))
