from __future__ import annotations

import json
from typing import Any, AsyncIterator

import httpx

from app.config import get_service_yaml
from app.models import DiagnosticAgentSummary, LlmProviderConfig


class AgentServiceError(RuntimeError):
    pass


def _base_url() -> str:
    return get_service_yaml().agent_helper.base_url.rstrip("/")


def _api_candidates(path: str) -> list[str]:
    base = _base_url()
    normalized = path if path.startswith("/") else f"/{path}"
    if base.endswith("/api/agentmanage"):
        return [f"{base}{normalized}"]
    if base.endswith("/api"):
        return [f"{base}{normalized}", f"{base}/agentmanage{normalized}"]
    return [f"{base}{normalized}", f"{base}/api/agentmanage{normalized}"]


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _parse_agent(item: dict[str, Any]) -> DiagnosticAgentSummary:
    agent_id = str(item.get("agent_id") or item.get("name") or "").strip()
    return DiagnosticAgentSummary(
        agent_id=agent_id,
        name=str(item.get("name") or agent_id),
        backend_type=str(item.get("backend_type") or agent_id),
        enabled=bool(item.get("enabled", True)),
        active=bool(item.get("active", False)),
        running=bool(item.get("running", False)),
        description=str(item.get("description") or ""),
    )


def list_agents(token: str) -> list[DiagnosticAgentSummary]:
    timeout = get_service_yaml().agent_helper.timeout
    last_error = ""
    with httpx.Client(timeout=timeout) as client:
        for url in _api_candidates("/api/ai-agents"):
            try:
                response = client.get(url, headers=_headers(token))
            except httpx.HTTPError as exc:
                last_error = str(exc)
                continue
            if response.status_code == 404:
                last_error = f"404 @ {url}"
                continue
            if response.status_code != 200:
                raise AgentServiceError(f"获取 agent 列表失败，状态码: {response.status_code}")
            payload = response.json()
            items = payload.get("items")
            if not isinstance(items, list):
                return []
            return [_parse_agent(item) for item in items if isinstance(item, dict)]
    raise AgentServiceError(f"获取 agent 列表失败: {last_error or 'no reachable agent endpoint'}")


def create_agent_session(token: str, *, agent_id: str, session_mode: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = {
        "agent_id": agent_id,
        "session_mode": session_mode,
        "metadata": metadata or {},
    }
    timeout = get_service_yaml().agent_helper.timeout
    last_error = ""
    with httpx.Client(timeout=timeout) as client:
        for url in _api_candidates("/api/ai-agents/sessions"):
            try:
                response = client.post(url, headers=_headers(token), json=payload)
            except httpx.HTTPError as exc:
                last_error = str(exc)
                continue
            if response.status_code == 404:
                last_error = f"404 @ {url}"
                continue
            if response.status_code not in {200, 201}:
                raise AgentServiceError(f"创建 agent 会话失败，状态码: {response.status_code}")
            body = response.json()
            if not isinstance(body, dict):
                raise AgentServiceError("创建 agent 会话返回格式异常")
            return body
    raise AgentServiceError(f"创建 agent 会话失败: {last_error or 'no reachable agent endpoint'}")


async def stream_agent_session_message(
    token: str,
    *,
    agent_session_id: str,
    message: str,
) -> AsyncIterator[dict[str, Any]]:
    timeout = get_service_yaml().agent_helper.timeout
    payload = {
        "content": message,
        "include_trace": True,
    }
    last_error = ""
    async with httpx.AsyncClient(timeout=None) as client:
        for url in _api_candidates(f"/api/ai-agents/sessions/{agent_session_id}/messages/stream"):
            try:
                async with client.stream("POST", url, headers=_headers(token), json=payload) as response:
                    if response.status_code == 404:
                        last_error = f"404 @ {url}"
                        continue
                    if response.status_code != 200:
                        detail = (await response.aread())[:200]
                        raise AgentServiceError(f"agent 流式调用失败: {response.status_code} {detail!r}")
                    async for line in response.aiter_lines():
                        if not line or not line.startswith("data:"):
                            continue
                        data = line[5:].strip()
                        if not data:
                            continue
                        try:
                            parsed = json.loads(data)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(parsed, dict):
                            yield parsed
                    return
            except httpx.HTTPError as exc:
                last_error = str(exc)
                continue
    raise AgentServiceError(f"agent 流式调用失败: {last_error or 'no reachable agent endpoint'}")


async def stream_agent_invoke(
    token: str,
    *,
    agent_id: str,
    message: str,
) -> AsyncIterator[dict[str, Any]]:
    timeout = get_service_yaml().agent_helper.timeout
    payload = {
        "agent_id": agent_id,
        "prompt": message,
        "task": message,
        "include_trace": True,
    }
    last_error = ""
    async with httpx.AsyncClient(timeout=None) as client:
        for url in _api_candidates("/api/ai-agents/invoke/stream"):
            try:
                async with client.stream("POST", url, headers=_headers(token), json=payload) as response:
                    if response.status_code == 404:
                        last_error = f"404 @ {url}"
                        continue
                    if response.status_code != 200:
                        detail = (await response.aread())[:200]
                        raise AgentServiceError(f"agent invoke 失败: {response.status_code} {detail!r}")
                    async for line in response.aiter_lines():
                        if not line or not line.startswith("data:"):
                            continue
                        data = line[5:].strip()
                        if not data:
                            continue
                        try:
                            parsed = json.loads(data)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(parsed, dict):
                            yield parsed
                    return
            except httpx.HTTPError as exc:
                last_error = str(exc)
                continue
    raise AgentServiceError(f"agent invoke 失败: {last_error or 'no reachable agent endpoint'}")


def get_agent_llm_config(token: str, agent_id: str) -> dict[str, Any]:
    timeout = get_service_yaml().agent_helper.timeout
    last_error = ""
    with httpx.Client(timeout=timeout) as client:
        for url in _api_candidates(f"/api/ai-agents/{agent_id}/llm-config"):
            try:
                response = client.get(url, headers=_headers(token))
            except httpx.HTTPError as exc:
                last_error = str(exc)
                continue
            if response.status_code == 404:
                last_error = f"404 @ {url}"
                continue
            if response.status_code != 200:
                raise AgentServiceError(f"读取 agent LLM 配置失败，状态码: {response.status_code}")
            body = response.json()
            if not isinstance(body, dict):
                raise AgentServiceError("读取 agent LLM 配置返回格式异常")
            return body
    raise AgentServiceError(f"读取 agent LLM 配置失败: {last_error or 'no reachable agent endpoint'}")


def apply_agent_llm_config(token: str, agent_id: str, provider: LlmProviderConfig) -> dict[str, Any]:
    timeout = get_service_yaml().agent_helper.timeout
    env_bindings = provider.extra_config.get("env_bindings") if isinstance(provider.extra_config.get("env_bindings"), dict) else {}
    file_bindings = provider.extra_config.get("file_bindings") if isinstance(provider.extra_config.get("file_bindings"), list) else []
    resolved_env = {str(k): str(v) for k, v in env_bindings.items() if str(k).strip()}
    provider_type = str(provider.provider_type or "").strip().lower().replace("_", "-")
    api_key_env = "ANTHROPIC_API_KEY" if provider_type == "anthropic" else "OPENAI_API_KEY"
    api_base_env = "ANTHROPIC_BASE_URL" if provider_type == "anthropic" else "OPENAI_BASE_URL"
    if provider.api_key:
        resolved_env.setdefault(api_key_env, provider.api_key)
    if provider.api_base:
        resolved_env.setdefault(api_base_env, provider.api_base)

    snapshot = {
        "provider_key": provider.provider_key,
        "display_name": str(provider.extra_config.get("display_name") or provider.provider_key),
        "provider_type": provider.provider_type,
        "enabled": provider.enabled,
        "api_base": provider.api_base,
        "model": provider.model,
        "updated_at": provider.extra_config.get("updated_at"),
        "mapped_env_keys": sorted(resolved_env.keys()),
        "mapped_file_paths": sorted(
            str(item.get("path") or "").strip()
            for item in file_bindings
            if isinstance(item, dict) and str(item.get("path") or "").strip()
        ),
    }
    payload = {
        "provider_keys": [provider.provider_key],
        "provider_snapshots": [snapshot],
        "resolved_env": resolved_env,
        # Local agent-helper runs as an unprivileged process in dev. Forwarding
        # config-center file bindings makes helper try to write paths like
        # /root/.codex/config.toml, which fails with EPERM and blocks the run.
        # For the passthrough workbench we only need env-based provider config.
        "resolved_files": [],
        "merge_strategy": "overwrite",
        "env_overrides": {},
        "file_overrides": [],
    }
    last_error = ""
    with httpx.Client(timeout=timeout) as client:
        for url in _api_candidates(f"/api/ai-agents/{agent_id}/llm-config"):
            try:
                response = client.put(url, headers=_headers(token), json=payload)
            except httpx.HTTPError as exc:
                last_error = str(exc)
                continue
            if response.status_code == 404:
                last_error = f"404 @ {url}"
                continue
            if response.status_code != 200:
                raise AgentServiceError(f"下发 agent LLM 配置失败，状态码: {response.status_code}")
            body = response.json()
            if not isinstance(body, dict):
                raise AgentServiceError("下发 agent LLM 配置返回格式异常")
            return body
    raise AgentServiceError(f"下发 agent LLM 配置失败: {last_error or 'no reachable agent endpoint'}")
