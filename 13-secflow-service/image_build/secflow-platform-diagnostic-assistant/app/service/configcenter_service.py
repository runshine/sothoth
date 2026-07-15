from __future__ import annotations

from typing import Any

import httpx

from app.config import get_service_yaml
from app.models import LlmProviderConfig, LlmProviderSummary


class ConfigCenterError(RuntimeError):
    pass


def _service_headers(token_override: str | None = None) -> dict[str, str]:
    token = token_override or get_service_yaml().auth_service.service_machine_token
    return {"Authorization": f"Bearer {token}"} if token else {}


def _normalize_provider_items(payload: Any) -> list[LlmProviderConfig]:
    items = payload.get("items") if isinstance(payload, dict) else None
    if items is None and isinstance(payload, list):
        items = payload
    if items is None and isinstance(payload, dict) and isinstance(payload.get("data"), dict):
        items = payload["data"].get("items") or payload["data"].get("records")
    if items is None:
        items = []

    result: list[LlmProviderConfig] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        result.append(
            LlmProviderConfig(
                provider_key=str(item.get("provider_key") or "").strip(),
                provider_type=str(item.get("provider_type") or "openai-compatible").strip(),
                api_base=str(item.get("api_base") or "").strip(),
                api_key=str(item.get("api_key") or "").strip(),
                model=str(item.get("model") or "").strip(),
                enabled=bool(item.get("enabled", True)),
                extra_config={
                    **(item.get("extra_config") if isinstance(item.get("extra_config"), dict) else {}),
                    "display_name": str(item.get("display_name") or "").strip(),
                    "updated_at": item.get("updated_at"),
                    "env_bindings": item.get("env_bindings") if isinstance(item.get("env_bindings"), dict) else {},
                    "file_bindings": item.get("file_bindings") if isinstance(item.get("file_bindings"), list) else [],
                },
            )
        )
    return [item for item in result if item.provider_key]


def list_llm_providers(token_override: str | None = None) -> list[LlmProviderConfig]:
    cfg = get_service_yaml()
    base_url = cfg.configcenter.base_url.rstrip("/")
    urls = [
        f"{base_url}/service/llm/providers",
        f"{base_url}/admin/llm/providers",
    ]
    last_status: int | None = None
    last_error: str | None = None
    try:
        with httpx.Client(timeout=cfg.configcenter.timeout) as client:
            for url in urls:
                response = client.get(url, headers=_service_headers(token_override))
                if response.status_code == 200:
                    return _normalize_provider_items(response.json())
                last_status = response.status_code
                last_error = response.text[:300]
                if response.status_code not in {401, 403, 404}:
                    break
    except httpx.HTTPError as exc:
        raise ConfigCenterError(f"读取配置中心失败: {exc}") from exc
    raise ConfigCenterError(f"配置中心返回异常状态码: {last_status}; detail={last_error or '-'}")


def get_provider_config(provider_key: str | None = None, token_override: str | None = None) -> LlmProviderConfig:
    cfg = get_service_yaml()
    providers = list_llm_providers(token_override=token_override)
    target = (provider_key or cfg.app.default_provider_key).strip()
    fallback_keys = [target, "share_codex"]
    for key in fallback_keys:
        if not key:
            continue
        for provider in providers:
            if provider.provider_key != key:
                continue
            if not provider.enabled:
                raise ConfigCenterError(f"Provider {key} 已禁用")
            if not provider.api_base or not provider.api_key or not provider.model:
                raise ConfigCenterError(f"Provider {key} 配置不完整")
            return provider

    for provider in providers:
        if provider.enabled and provider.api_base and provider.api_key and provider.model:
            return provider

    if target:
        raise ConfigCenterError(f"配置中心未找到 provider_key={target}")
    raise ConfigCenterError("配置中心没有可用的 provider")


def list_provider_summaries(token_override: str | None = None) -> list[LlmProviderSummary]:
    providers = list_llm_providers(token_override=token_override)
    result: list[LlmProviderSummary] = []
    for provider in providers:
        env_bindings = provider.extra_config.get("env_bindings") if isinstance(provider.extra_config.get("env_bindings"), dict) else {}
        file_bindings = provider.extra_config.get("file_bindings") if isinstance(provider.extra_config.get("file_bindings"), list) else []
        result.append(
            LlmProviderSummary(
                provider_key=provider.provider_key,
                display_name=str(provider.extra_config.get("display_name") or provider.provider_key),
                provider_type=provider.provider_type,
                api_base=provider.api_base,
                model=provider.model,
                enabled=provider.enabled,
                mapped_env_keys=sorted(str(key).strip() for key in env_bindings.keys() if str(key).strip()),
                mapped_file_paths=sorted(
                    str(item.get("path") or "").strip()
                    for item in file_bindings
                    if isinstance(item, dict) and str(item.get("path") or "").strip()
                ),
                updated_at=str(provider.extra_config.get("updated_at") or "") or None,
            )
        )
    return result
