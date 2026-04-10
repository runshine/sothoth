from __future__ import annotations

import os
from typing import Dict, Tuple, Type

from app.models.config_models import FrameworkConfig
from app.models.contracts import SessionMode
from app.runtime.base import (
    BaseAgentRuntime,
    ClaudeCodeRuntime,
    CodexRuntime,
    OpenCodeRuntime,
    PiAgentRuntime,
    RuntimeBackendConfig,
    RuntimeResponse,
)


ADAPTERS: dict[str, Type[BaseAgentRuntime]] = {
    "codex": CodexRuntime,
    "claude_code": ClaudeCodeRuntime,
    "opencode": OpenCodeRuntime,
    "pi_agent": PiAgentRuntime,
}


class RuntimeManager:
    def __init__(self, config: FrameworkConfig):
        self.config = config
        self._runtimes: Dict[str, BaseAgentRuntime] = {}
        self._session_cache: Dict[Tuple[str, str, str, str], str] = {}

    def _backend_config(self, agent_instance_id: str) -> RuntimeBackendConfig:
        instance = next(item for item in self.config.agent_instances if item.id == agent_instance_id)
        agent_type = next(item for item in self.config.agent_types if item.id == instance.agent_type_id)
        runtime = agent_type.runtime
        overrides = instance.runtime_overrides
        command_or_sdk = overrides.command_or_sdk if overrides and overrides.command_or_sdk else runtime.command_or_sdk
        env = {name: value for name, value in ((env_name, os.environ.get(env_name, "")) for env_name in runtime.env_from) if value}
        if overrides and overrides.env:
            env.update(overrides.env)
        session_mode = overrides.session_mode if overrides and overrides.session_mode else runtime.session_mode_default
        return RuntimeBackendConfig(
            backend_id=agent_instance_id,
            adapter=runtime.adapter,
            command=command_or_sdk.command,
            args=list(command_or_sdk.args),
            cwd=overrides.cwd if overrides and overrides.cwd else runtime.cwd,
            env=env,
            session_mode_default=session_mode,
            reset_context=instance.reset_context,
        )

    def _get_runtime(self, agent_instance_id: str) -> BaseAgentRuntime:
        runtime = self._runtimes.get(agent_instance_id)
        if runtime:
            return runtime
        backend_config = self._backend_config(agent_instance_id)
        adapter_cls = ADAPTERS.get(backend_config.adapter)
        if adapter_cls is None:
            raise ValueError(f"unsupported adapter: {backend_config.adapter}")
        runtime = adapter_cls(
            backend_config=backend_config,
            quiet_window_ms=self.config.run.session_quiet_window_ms,
            max_window_ms=self.config.run.session_max_window_ms,
        )
        self._runtimes[agent_instance_id] = runtime
        return runtime

    def healthcheck(self, agent_instance_id: str) -> dict[str, object]:
        return self._get_runtime(agent_instance_id).healthcheck()

    def run_prompt(
        self,
        *,
        agent_instance_id: str,
        prompt: str,
        task_scope: str,
        session_mode_override: SessionMode | None = None,
        force_new_session: bool = False,
        cwd_override: str | None = None,
    ) -> RuntimeResponse:
        runtime = self._get_runtime(agent_instance_id)
        backend = runtime.backend_config
        mode = session_mode_override or backend.session_mode_default
        effective_cwd = cwd_override or backend.cwd
        if mode == SessionMode.INVOKE:
            return runtime.invoke_once(prompt, mode, cwd_override=effective_cwd)
        if backend.reset_context or force_new_session:
            session_id = runtime.create_session(mode, cwd_override=effective_cwd)
            try:
                return runtime.send_message(session_id, prompt)
            finally:
                runtime.close_session(session_id)

        cache_key = (task_scope, agent_instance_id, mode.value, effective_cwd or "")
        session_id = self._session_cache.get(cache_key)
        if not session_id:
            session_id = runtime.create_session(mode, cwd_override=effective_cwd)
            self._session_cache[cache_key] = session_id
        return runtime.send_message(session_id, prompt)

    def close_task_scope(self, task_scope: str) -> None:
        to_delete = [cache_key for cache_key in self._session_cache if cache_key[0] == task_scope]
        for cache_key in to_delete:
            _, agent_instance_id, _, _ = cache_key
            session_id = self._session_cache.pop(cache_key)
            self._get_runtime(agent_instance_id).close_session(session_id)

    def close_all(self) -> None:
        cache_keys = list(self._session_cache.keys())
        for task_scope, agent_instance_id, mode, cwd in cache_keys:
            session_id = self._session_cache.pop((task_scope, agent_instance_id, mode, cwd), None)
            if session_id:
                self._get_runtime(agent_instance_id).close_session(session_id)
