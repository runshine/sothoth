from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Generator

from agent_ai_service.adapters.claude_a2a_adapter import ClaudeA2AAdapter
from agent_ai_service.adapters.claude_adapter import ClaudeAdapter
from agent_ai_service.adapters.codex_adapter import CodexAdapter
from agent_ai_service.adapters.opencode_adapter import OpencodeAdapter
from agent_ai_service.services.agent_process_manager import AgentProcessManager
from agent_ai_service.services.backend_registry import BackendRegistry


class BackendRuntimeService:
    def __init__(self, registry: BackendRegistry, process_manager: AgentProcessManager):
        self.registry = registry
        self.process_manager = process_manager

    def _adapter(self, name: str):
        model = self.registry.to_model(name)
        mapping = {
            'claude': ClaudeAdapter,
            'codex': CodexAdapter,
            'opencode': OpencodeAdapter,
            'claude-a2a': ClaudeA2AAdapter,
        }
        adapter_cls = mapping.get(model.backend_type, ClaudeAdapter)
        return adapter_cls(model)

    def list_backends(self) -> Dict[str, Any]:
        data = self.registry.list()
        items = []
        for name, cfg in data.get('backends', {}).items():
            adapter = self._adapter(name)
            status = self.process_manager.status(name)
            items.append({
                'name': name,
                'enabled': bool(cfg.get('enabled', True)),
                'backend_type': cfg.get('backend_type', name),
                'installed': adapter.check_installed(),
                'running': status.get('running', False),
                'pid': status.get('pid'),
                'command': cfg.get('command'),
                'args': cfg.get('args', []),
                'cwd': cfg.get('cwd'),
                'description': cfg.get('description', ''),
                'env_keys': self.registry.env_keys(name),
                'env': cfg.get('env', {}),
                'capabilities': adapter.capabilities(),
                'llm_provider_key': cfg.get('llm_provider_key'),
                'llm_provider_snapshot': cfg.get('llm_provider_snapshot') if isinstance(cfg.get('llm_provider_snapshot'), dict) else None,
                'llm_provider_applied_at': cfg.get('llm_provider_applied_at'),
                'llm_provider_mapped_env_keys': list(cfg.get('llm_provider_mapped_env_keys', []) or []),
            })
        return {
            'default_backend': data.get('default_backend'),
            'items': items,
        }

    def get_backend(self, name: str) -> Dict[str, Any]:
        cfg = self.registry.get(name)
        if not cfg:
            raise KeyError(name)
        adapter = self._adapter(name)
        status = self.process_manager.status(name)
        return {
            'name': name,
            'enabled': bool(cfg.get('enabled', True)),
            'backend_type': cfg.get('backend_type', name),
            'installed': adapter.check_installed(),
            'running': status.get('running', False),
            'pid': status.get('pid'),
            'command': cfg.get('command'),
            'args': cfg.get('args', []),
            'cwd': cfg.get('cwd'),
            'description': cfg.get('description', ''),
            'env_keys': self.registry.env_keys(name),
            'env': cfg.get('env', {}),
            'capabilities': adapter.capabilities(),
            'llm_provider_key': cfg.get('llm_provider_key'),
            'llm_provider_snapshot': cfg.get('llm_provider_snapshot') if isinstance(cfg.get('llm_provider_snapshot'), dict) else None,
            'llm_provider_applied_at': cfg.get('llm_provider_applied_at'),
            'llm_provider_mapped_env_keys': list(cfg.get('llm_provider_mapped_env_keys', []) or []),
        }

    def upsert_backend(self, name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.registry.put(name, payload)
        return self.get_backend(name)

    def delete_backend(self, name: str) -> None:
        self.process_manager.stop(name)
        self.registry.delete(name)

    def activate_backend(self, name: str) -> Dict[str, Any]:
        self.registry.activate(name)
        return self.get_backend(name)

    def get_backend_env(self, name: str) -> Dict[str, Any]:
        cfg = self.registry.get(name)
        if not cfg:
            raise KeyError(name)
        return {
            'name': name,
            'env': cfg.get('env', {}),
            'env_keys': self.registry.env_keys(name),
        }

    def replace_backend_env(self, name: str, env: Dict[str, str]) -> Dict[str, Any]:
        self.registry.replace_env(name, env)
        return self.get_backend(name)

    def delete_backend_env(self, name: str, keys: list[str]) -> Dict[str, Any]:
        self.registry.delete_env_keys(name, keys)
        return self.get_backend(name)

    def start_backend(self, name: str) -> Dict[str, Any]:
        model = self.registry.to_model(name)
        result = self.process_manager.start(model)
        self.process_manager.touch(name)
        detail = self.get_backend(name)
        detail.update(result)
        return detail

    def stop_backend(self, name: str) -> Dict[str, Any]:
        result = self.process_manager.stop(name)
        detail = self.get_backend(name)
        detail.update(result)
        return detail

    def invoke_backend(self, name: str | None, prompt: str, messages: list[dict[str, Any]] | None = None) -> Dict[str, Any]:
        data = self.registry.list()
        chosen = name or data.get('default_backend')
        if not chosen:
            raise ValueError('no backend configured')
        model = self.registry.to_model(chosen)
        self.process_manager.touch(chosen)
        response = self.process_manager.invoke_once(model, prompt=prompt, messages=messages)
        self.process_manager.touch(chosen)
        return {
            'backend': chosen,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            **response,
        }

    def invoke_backend_stream(self, name: str | None, prompt: str, messages: list[dict[str, Any]] | None = None) -> Generator[Dict[str, Any], None, None]:
        data = self.registry.list()
        chosen = name or data.get('default_backend')
        if not chosen:
            raise ValueError('no backend configured')
        model = self.registry.to_model(chosen)
        self.process_manager.touch(chosen)

        for event in self.process_manager.invoke_once_stream(model, prompt=prompt, messages=messages):
            if event.get('type') == 'done':
                self.process_manager.touch(chosen)
                yield {
                    'backend': chosen,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    **event,
                }
                continue
            yield {
                'backend': chosen,
                **event,
            }

    def service_health(self) -> Dict[str, Any]:
        backends = self.list_backends()
        running = sum(1 for item in backends.get('items', []) if item.get('running'))
        installed = sum(1 for item in backends.get('items', []) if item.get('installed'))
        return {
            'default_backend': backends.get('default_backend'),
            'backend_total': len(backends.get('items', [])),
            'backend_installed': installed,
            'backend_running': running,
            'items': backends.get('items', []),
            'process_store': self.process_manager.list_states(),
        }
