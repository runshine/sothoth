from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List

from agent_ai_service.config import settings
from agent_ai_service.models.agent_backend import BackendConfig
from agent_ai_service.persistence.file_store import JsonFileStore

DEFAULT_WORKDIR = '/host'


DEFAULT_BACKENDS = {
    'claude': {
        'name': 'claude',
        'backend_type': 'claude',
        'command': 'claude',
        'args': [],
        'cwd': DEFAULT_WORKDIR,
        'env': {},
        'enabled': True,
        'description': 'Claude Code CLI backend',
    },
    'codex': {
        'name': 'codex',
        'backend_type': 'codex',
        'command': 'codex',
        'args': ['exec'],
        'cwd': DEFAULT_WORKDIR,
        'env': {},
        'enabled': False,
        'description': 'OpenAI Codex CLI backend',
    },
    'opencode': {
        'name': 'opencode',
        'backend_type': 'opencode',
        'command': 'opencode',
        'args': [],
        'cwd': DEFAULT_WORKDIR,
        'env': {},
        'enabled': False,
        'description': 'OpenCode CLI backend',
    },
}

def _normalize_backend_args(backend_type: Any, args: Any) -> List[str]:
    normalized = [str(item) for item in (args or []) if str(item).strip()]
    backend = str(backend_type or '').strip().lower()
    # Codex CLI 默认参数：
    # - exec: 统一走非交互执行入口
    # - --skip-git-repo-check: 允许在非 git 目录执行
    # - --dangerously-bypass-approvals-and-sandbox: helper 运行在外层受控环境时使用
    #
    # 说明：
    # 当前 codex CLI 中 `--yolo` 与
    # `--dangerously-bypass-approvals-and-sandbox` 存在语义重叠/冲突，
    # 同时下发会触发 “cannot be used multiple times”。
    # 因此 helper 侧仅保留显式的危险模式参数。
    if backend == 'codex':
        required = ['exec', '--skip-git-repo-check', '--dangerously-bypass-approvals-and-sandbox']
        if not normalized:
            return required
        seen = set()
        result: List[str] = []
        # exec 固定放在首位，避免被附加到 prompt 后导致参数顺序异常
        if 'exec' in normalized:
            result.append('exec')
            seen.add('exec')
        for item in normalized:
            text = str(item).strip()
            if not text or text == 'exec' or text in seen:
                continue
            seen.add(text)
            result.append(text)
        # 若原参数未携带 exec，则补到首位
        if 'exec' not in seen:
            result.insert(0, 'exec')
            seen.add('exec')
        # 补齐默认参数（不重复）
        filtered_result = [item for item in result if item != '--yolo']
        seen = set(filtered_result)
        result = filtered_result
        for item in ('--skip-git-repo-check', '--dangerously-bypass-approvals-and-sandbox'):
            if item not in seen:
                result.append(item)
                seen.add(item)
        return result
    return normalized


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
        # 清理已下线的历史默认后端，避免在 AI Agent 管理页继续出现
        removed_legacy = data['backends'].pop('claude-a2a', None)
        if removed_legacy is not None:
            changed = True
        for name, cfg in DEFAULT_BACKENDS.items():
            if name not in data['backends']:
                data['backends'][name] = deepcopy(cfg)
                changed = True
        # 所有 AI Agent 默认工作目录统一为 /host；保留已有显式配置
        for name, cfg in list(data.get('backends', {}).items()):
            if not isinstance(cfg, dict):
                continue
            if not str(cfg.get('cwd') or '').strip():
                cfg['cwd'] = DEFAULT_WORKDIR
                data['backends'][name] = cfg
                changed = True
            normalized_args = _normalize_backend_args(cfg.get('backend_type', name), cfg.get('args', []))
            if normalized_args != list(cfg.get('args', []) or []):
                cfg['args'] = normalized_args
                data['backends'][name] = cfg
                changed = True
        if data.get('default_backend') == 'claude-a2a':
            data['default_backend'] = settings.agent_default_backend if settings.agent_default_backend in data['backends'] else 'claude'
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
        requested_cwd = payload.get('cwd', existing.get('cwd', DEFAULT_WORKDIR))
        normalized_cwd = str(requested_cwd or '').strip() or DEFAULT_WORKDIR
        normalized_backend_type = payload.get('backend_type', existing.get('backend_type', existing.get('name', name)))
        normalized_args = _normalize_backend_args(normalized_backend_type, payload.get('args', existing.get('args', [])))
        merged = {
            **existing,
            'name': name,
            'backend_type': normalized_backend_type,
            'command': payload.get(
                'command',
                existing.get('command', normalized_backend_type)
            ),
            'args': normalized_args,
            'env': payload.get('env', existing.get('env', {})),
            'enabled': bool(payload.get('enabled', existing.get('enabled', True))),
            'cwd': normalized_cwd,
            'description': payload.get('description', existing.get('description', '')),
            'llm_provider_key': payload.get('llm_provider_key', existing.get('llm_provider_key')),
            'llm_provider_keys': payload.get('llm_provider_keys', existing.get('llm_provider_keys', [])),
            'llm_provider_snapshot': payload.get('llm_provider_snapshot', existing.get('llm_provider_snapshot')),
            'llm_provider_snapshots': payload.get('llm_provider_snapshots', existing.get('llm_provider_snapshots', [])),
            'llm_provider_applied_at': payload.get('llm_provider_applied_at', existing.get('llm_provider_applied_at')),
            'llm_provider_mapped_env_keys': payload.get('llm_provider_mapped_env_keys', existing.get('llm_provider_mapped_env_keys', [])),
            'llm_provider_file_bindings': payload.get('llm_provider_file_bindings', existing.get('llm_provider_file_bindings', [])),
            'llm_provider_file_backups': payload.get('llm_provider_file_backups', existing.get('llm_provider_file_backups', [])),
            'llm_provider_merge_strategy': payload.get('llm_provider_merge_strategy', existing.get('llm_provider_merge_strategy', 'overwrite')),
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
            cwd=str(cfg.get('cwd') or '').strip() or DEFAULT_WORKDIR,
            description=cfg.get('description', ''),
        )

    def env_keys(self, name: str) -> List[str]:
        cfg = self.get(name) or {}
        return sorted(list((cfg.get('env') or {}).keys()))
