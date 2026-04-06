from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import shutil
from typing import Any, Dict, Generator, List

from agent_ai_service.config import settings
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

    def _normalize_provider_keys(self, provider_keys: Any) -> List[str]:
        result: List[str] = []
        seen = set()
        for item in provider_keys or []:
            text = str(item or '').strip()
            if not text or text in seen:
                continue
            seen.add(text)
            result.append(text)
        return result

    def _normalize_env_map(self, env: Any) -> Dict[str, str]:
        if not isinstance(env, dict):
            return {}
        normalized: Dict[str, str] = {}
        for key, value in env.items():
            key_text = str(key or '').strip()
            if not key_text:
                continue
            normalized[key_text] = '' if value is None else str(value)
        return normalized

    def _normalize_file_bindings(self, files: Any) -> List[Dict[str, Any]]:
        if not isinstance(files, list):
            return []
        normalized: List[Dict[str, Any]] = []
        for idx, item in enumerate(files):
            if not isinstance(item, dict):
                continue
            path = str(item.get('path') or '').strip()
            content = item.get('content')
            if not path or not isinstance(content, str):
                continue
            normalized.append({
                'name': str(item.get('name') or '').strip() or f'file-{idx + 1}',
                'path': path,
                'content': content,
                'format': str(item.get('format') or 'other').strip().lower() or 'other',
                'enabled': bool(item.get('enabled', True)),
                'provider_key': str(item.get('provider_key') or '').strip() or None,
            })
        return normalized

    def _merge_files(self, base: List[Dict[str, Any]], override: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        by_path: Dict[str, Dict[str, Any]] = {}
        for item in base + override:
            path = str(item.get('path') or '').strip()
            if not path:
                continue
            by_path[path] = item
        return [item for item in by_path.values() if bool(item.get('enabled', True))]

    def _normalize_file_backups(self, backups: Any) -> List[Dict[str, Any]]:
        if not isinstance(backups, list):
            return []
        normalized: List[Dict[str, Any]] = []
        for item in backups:
            if not isinstance(item, dict):
                continue
            path = str(item.get('path') or '').strip()
            backup_path = str(item.get('backup_path') or '').strip()
            if not path or not backup_path:
                continue
            normalized.append({
                'path': path,
                'backup_path': backup_path,
                'existed': bool(item.get('existed', False)),
            })
        return normalized

    def _resolve_target_path(self, binding_path: str, backend_cwd: str) -> Path:
        raw = str(binding_path or '').strip()
        if not raw:
            raise ValueError('file path is empty')
        target = Path(raw)
        if target.is_absolute():
            return target
        base = Path(str(backend_cwd or '').strip() or '/')
        return (base / target).resolve()

    def _backup_dir_for_agent(self, name: str) -> Path:
        safe = str(name or 'default').replace('/', '_')
        return settings.state_dir / 'llm_file_backups' / safe

    def _ensure_backup(self, name: str, target: Path, backup_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        key = str(target)
        existing = backup_map.get(key)
        if existing:
            return existing

        backup_dir = self._backup_dir_for_agent(name)
        backup_dir.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha1(key.encode('utf-8')).hexdigest()
        backup_path = backup_dir / f'{digest}.bak'
        existed = target.exists()
        if existed:
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(target), str(backup_path))
        else:
            if backup_path.exists():
                backup_path.unlink()
        record = {
            'path': key,
            'backup_path': str(backup_path),
            'existed': existed,
        }
        backup_map[key] = record
        return record

    def _restore_backup_record(self, record: Dict[str, Any]) -> None:
        target = Path(str(record.get('path') or '').strip())
        backup_path = Path(str(record.get('backup_path') or '').strip())
        existed = bool(record.get('existed', False))
        if not str(target):
            return
        try:
            if existed and backup_path.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(backup_path), str(target))
            elif not existed:
                if target.exists() and target.is_file():
                    target.unlink()
        finally:
            if backup_path.exists():
                try:
                    backup_path.unlink()
                except Exception:
                    pass

    def _restore_removed_bindings(
        self,
        removed_paths: List[str],
        backup_map: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        for path in removed_paths:
            record = backup_map.get(path)
            if not record:
                continue
            self._restore_backup_record(record)
            backup_map.pop(path, None)
        return backup_map

    def _materialize_file_bindings(
        self,
        name: str,
        backend_cwd: str,
        final_files: List[Dict[str, Any]],
        existing_backups: List[Dict[str, Any]],
        previous_files: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        backup_map = {
            str(item.get('path') or '').strip(): item
            for item in existing_backups
            if str(item.get('path') or '').strip()
        }
        previous_paths = set(
            str(self._resolve_target_path(str(item.get('path') or '').strip(), backend_cwd))
            for item in previous_files
            if str(item.get('path') or '').strip()
        )
        next_paths = set(
            str(self._resolve_target_path(str(item.get('path') or '').strip(), backend_cwd))
            for item in final_files
            if str(item.get('path') or '').strip()
        )
        removed_paths = sorted(list(previous_paths - next_paths))
        if not next_paths and not previous_paths and backup_map:
            removed_paths = sorted(list(backup_map.keys()))
        if removed_paths:
            backup_map = self._restore_removed_bindings(removed_paths, backup_map)

        for item in final_files:
            target = self._resolve_target_path(str(item.get('path') or '').strip(), backend_cwd)
            self._ensure_backup(name, target, backup_map)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(str(item.get('content') or ''), encoding='utf-8')

        return [backup_map[key] for key in sorted(backup_map.keys())]

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
                'llm_provider_keys': list(cfg.get('llm_provider_keys', []) or []),
                'llm_provider_snapshot': cfg.get('llm_provider_snapshot') if isinstance(cfg.get('llm_provider_snapshot'), dict) else None,
                'llm_provider_snapshots': list(cfg.get('llm_provider_snapshots', []) or []),
                'llm_provider_applied_at': cfg.get('llm_provider_applied_at'),
                'llm_provider_mapped_env_keys': list(cfg.get('llm_provider_mapped_env_keys', []) or []),
                'llm_provider_file_bindings': list(cfg.get('llm_provider_file_bindings', []) or []),
                'llm_provider_file_backups': list(cfg.get('llm_provider_file_backups', []) or []),
                'llm_provider_merge_strategy': cfg.get('llm_provider_merge_strategy') or 'overwrite',
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
            'llm_provider_keys': list(cfg.get('llm_provider_keys', []) or []),
            'llm_provider_snapshot': cfg.get('llm_provider_snapshot') if isinstance(cfg.get('llm_provider_snapshot'), dict) else None,
            'llm_provider_snapshots': list(cfg.get('llm_provider_snapshots', []) or []),
            'llm_provider_applied_at': cfg.get('llm_provider_applied_at'),
            'llm_provider_mapped_env_keys': list(cfg.get('llm_provider_mapped_env_keys', []) or []),
            'llm_provider_file_bindings': list(cfg.get('llm_provider_file_bindings', []) or []),
            'llm_provider_file_backups': list(cfg.get('llm_provider_file_backups', []) or []),
            'llm_provider_merge_strategy': cfg.get('llm_provider_merge_strategy') or 'overwrite',
        }

    def upsert_backend(self, name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        current = self.registry.get(name) or {}
        next_payload = dict(payload or {})
        requested_files = next_payload.get('llm_provider_file_bindings')
        should_process_files = isinstance(requested_files, list)
        if not should_process_files:
            clear_llm = (
                next_payload.get('llm_provider_key', '__keep__') is None
                and isinstance(next_payload.get('llm_provider_mapped_env_keys', []), list)
                and len(next_payload.get('llm_provider_mapped_env_keys', [])) == 0
            )
            if clear_llm and isinstance(current.get('llm_provider_file_bindings'), list):
                requested_files = []
                should_process_files = True

        if should_process_files:
            backend_cwd = str(next_payload.get('cwd') or current.get('cwd') or '/')
            previous_files = self._normalize_file_bindings(current.get('llm_provider_file_bindings'))
            target_files = self._normalize_file_bindings(requested_files)
            existing_backups = self._normalize_file_backups(current.get('llm_provider_file_backups'))
            updated_backups = self._materialize_file_bindings(
                name=name,
                backend_cwd=backend_cwd,
                final_files=target_files,
                existing_backups=existing_backups,
                previous_files=previous_files,
            )
            next_payload['llm_provider_file_bindings'] = target_files
            next_payload['llm_provider_file_backups'] = updated_backups

        self.registry.put(name, next_payload)
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

    def get_backend_llm_config(self, name: str) -> Dict[str, Any]:
        detail = self.get_backend(name)
        return {
            'agent_id': detail.get('name'),
            'provider_keys': list(detail.get('llm_provider_keys') or ([detail.get('llm_provider_key')] if detail.get('llm_provider_key') else [])),
            'provider_snapshots': list(detail.get('llm_provider_snapshots') or ([detail.get('llm_provider_snapshot')] if detail.get('llm_provider_snapshot') else [])),
            'merge_strategy': detail.get('llm_provider_merge_strategy') or 'overwrite',
            'mapped_env_keys': list(detail.get('llm_provider_mapped_env_keys') or []),
            'file_bindings': list(detail.get('llm_provider_file_bindings') or []),
            'file_backups': list(detail.get('llm_provider_file_backups') or []),
            'applied_at': detail.get('llm_provider_applied_at'),
            'env': detail.get('env', {}) or {},
        }

    def apply_backend_llm_config(self, name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        current = self.registry.get(name)
        if not current:
            raise KeyError(name)

        provider_keys = self._normalize_provider_keys(payload.get('provider_keys'))
        provider_snapshots = payload.get('provider_snapshots') if isinstance(payload.get('provider_snapshots'), list) else []
        merge_strategy = str(payload.get('merge_strategy') or 'overwrite').strip().lower()
        if merge_strategy not in ('overwrite', 'merge'):
            merge_strategy = 'overwrite'

        resolved_env = self._normalize_env_map(payload.get('resolved_env'))
        env_overrides = self._normalize_env_map(payload.get('env_overrides'))
        resolved_files = self._normalize_file_bindings(payload.get('resolved_files'))
        file_overrides = self._normalize_file_bindings(payload.get('file_overrides'))

        existing_env = self._normalize_env_map(current.get('env'))
        existing_files = self._normalize_file_bindings(current.get('llm_provider_file_bindings'))
        existing_backups = self._normalize_file_backups(current.get('llm_provider_file_backups'))
        if merge_strategy == 'merge':
            final_env = dict(existing_env)
            final_env.update(resolved_env)
            final_env.update(env_overrides)
            final_files = self._merge_files(self._merge_files(existing_files, resolved_files), file_overrides)
        else:
            final_env = dict(resolved_env)
            final_env.update(env_overrides)
            final_files = self._merge_files(resolved_files, file_overrides)
        backend_cwd = str(current.get('cwd') or '/')
        updated_backups = self._materialize_file_bindings(
            name=name,
            backend_cwd=backend_cwd,
            final_files=final_files,
            existing_backups=existing_backups,
            previous_files=existing_files,
        )

        first_snapshot = provider_snapshots[0] if provider_snapshots else None
        self.registry.put(name, {
            'env': final_env,
            'llm_provider_key': provider_keys[0] if provider_keys else None,
            'llm_provider_keys': provider_keys,
            'llm_provider_snapshot': first_snapshot if isinstance(first_snapshot, dict) else None,
            'llm_provider_snapshots': provider_snapshots,
            'llm_provider_applied_at': datetime.now(timezone.utc).isoformat(),
            'llm_provider_mapped_env_keys': sorted(final_env.keys()),
            'llm_provider_file_bindings': final_files,
            'llm_provider_file_backups': updated_backups,
            'llm_provider_merge_strategy': merge_strategy,
        })
        return self.get_backend_llm_config(name)

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
