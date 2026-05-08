"""Config center client for firmware unpacker."""

from __future__ import annotations

import json
import os
from typing import Any, Optional

import httpx

from app.config import get_config
from app.exception import InternalError, NotFoundError, ValidationError


class ConfigCenterClient:
    def __init__(self) -> None:
        cfg = get_config()
        self.config = cfg.configcenter_service
        self.auth = cfg.auth_service

    def _headers(self) -> dict[str, str]:
        token = os.environ.get("SECFLOW_SERVICE_MACHINE_TOKEN") or self.auth.service_machine_token
        return {"Authorization": f"Bearer {token}"} if token else {}

    def _base_url(self) -> str:
        return self.config.base_url.rstrip("/")

    def list_llm_providers(self) -> dict[str, Any]:
        if not self.config.enabled:
            raise InternalError("配置中心未启用")
        try:
            with httpx.Client(timeout=self.config.timeout, headers=self._headers()) as client:
                response = client.get(f"{self._base_url()}/service/llm/providers")
        except httpx.TimeoutException:
            raise InternalError("配置中心请求超时")
        except httpx.ConnectError as exc:
            raise InternalError(f"无法连接配置中心: {exc}")
        return _handle(response)

    def get_llm_provider(self, provider_key: str) -> dict[str, Any]:
        if not self.config.enabled:
            raise InternalError("配置中心未启用")
        normalized = str(provider_key or "").strip()
        if not normalized:
            raise ValidationError("llm_provider_key不能为空")
        try:
            with httpx.Client(timeout=self.config.timeout, headers=self._headers()) as client:
                response = client.get(f"{self._base_url()}/service/llm/providers/{normalized}")
        except httpx.TimeoutException:
            raise InternalError("配置中心请求超时")
        except httpx.ConnectError as exc:
            raise InternalError(f"无法连接配置中心: {exc}")
        if response.status_code == 404:
            raise NotFoundError("已启用的LLM Provider", normalized)
        return _handle(response)

    def list_llm_config_files(self) -> dict[str, Any]:
        payload = self.list_llm_providers()
        raw_items = payload.get("items") if isinstance(payload.get("items"), list) else []
        items: list[dict[str, Any]] = []
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            extracted = extract_models_json_config(item)
            if extracted is None:
                continue
            items.append(
                {
                    "config_file_key": str(item.get("provider_key") or "").strip(),
                    "display_name": str(item.get("display_name") or item.get("provider_key") or "").strip(),
                    "provider_type": str(item.get("provider_type") or "").strip(),
                    "enabled": bool(item.get("enabled", False)),
                    "is_default": bool(item.get("is_default", False)),
                    "default_model": extracted["default_model"],
                    "description": str(item.get("description") or "").strip() or None,
                    "updated_at": str(item.get("updated_at") or "").strip() or None,
                    "model_options": extracted["model_options"],
                }
            )
        return {"total": len(items), "items": items}

    def get_llm_config_file(self, config_file_key: str) -> dict[str, Any]:
        provider = self.get_llm_provider(config_file_key)
        extracted = extract_models_json_config(provider)
        if extracted is None:
            raise ValidationError(f"配置文件 {config_file_key} 缺少可用的 models.json")
        return {
            "config_file_key": str(provider.get("provider_key") or "").strip(),
            "display_name": str(provider.get("display_name") or provider.get("provider_key") or "").strip(),
            "provider_type": str(provider.get("provider_type") or "").strip(),
            "enabled": bool(provider.get("enabled", False)),
            "is_default": bool(provider.get("is_default", False)),
            "default_model": extracted["default_model"],
            "models_json": extracted["models_json"],
            "model_options": extracted["model_options"],
            "description": str(provider.get("description") or "").strip() or None,
            "updated_at": str(provider.get("updated_at") or "").strip() or None,
        }


def _iter_file_bindings(provider: dict[str, Any]) -> list[dict[str, Any]]:
    bindings = provider.get("file_bindings")
    if not isinstance(bindings, list):
        return []
    return [item for item in bindings if isinstance(item, dict)]


def _extract_provider_models(models_json: dict[str, Any], provider_key: str) -> list[dict[str, str]]:
    providers = models_json.get("providers") if isinstance(models_json.get("providers"), dict) else {}
    options: list[dict[str, str]] = []
    seen: set[str] = set()
    for block_key, provider_block in providers.items():
        if not isinstance(provider_block, dict):
            continue
        selected_provider_key = str(block_key or "").strip() or provider_key
        models = provider_block.get("models") if isinstance(provider_block.get("models"), list) else []
        for item in models:
            if not isinstance(item, dict):
                continue
            model_id = str(item.get("id") or "").strip()
            if not model_id:
                continue
            selector = f"{selected_provider_key}/{model_id}"
            if selector in seen:
                continue
            seen.add(selector)
            options.append(
                {
                    "value": selector,
                    "label": str(item.get("name") or model_id).strip() or selector,
                    "source": "configured",
                }
            )
    return options


def extract_models_json_config(provider: dict[str, Any]) -> dict[str, Any] | None:
    provider_key = str(provider.get("provider_key") or "").strip()
    if not provider_key:
        return None
    for binding in _iter_file_bindings(provider):
        if not bool(binding.get("enabled", True)):
            continue
        name = str(binding.get("name") or "").strip().lower()
        path = str(binding.get("path") or "").strip().lower()
        if name != "models.json" and not path.endswith("/models.json") and path != "models.json":
            continue
        content = binding.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ValidationError(f"配置文件 {provider_key} 的 models.json 内容为空")
        try:
            models_json = json.loads(content)
        except Exception as exc:
            raise ValidationError(f"配置文件 {provider_key} 的 models.json 不是合法 JSON: {exc}") from exc
        if not isinstance(models_json, dict):
            raise ValidationError(f"配置文件 {provider_key} 的 models.json 顶层必须是对象")
        model_options = _extract_provider_models(models_json, provider_key)
        default_model = str(provider.get("model") or "").strip() or None
        if default_model and "/" not in default_model:
            default_model = f"{provider_key}/{default_model}"
        if not default_model and model_options:
            default_model = model_options[0]["value"]
        return {
            "models_json": models_json,
            "model_options": model_options,
            "default_model": default_model,
        }
    return None


def _handle(response: httpx.Response) -> dict[str, Any]:
    if 200 <= response.status_code < 300:
        payload = response.json() if response.content else {}
        return payload if isinstance(payload, dict) else {}
    if response.status_code in (401, 403):
        raise InternalError(f"配置中心认证失败: {response.status_code}")
    if response.status_code == 422:
        raise ValidationError(response.text or "配置中心参数校验失败")
    raise InternalError(f"配置中心返回异常状态码: {response.status_code}")


_configcenter_client: Optional[ConfigCenterClient] = None


def get_configcenter_client() -> ConfigCenterClient:
    global _configcenter_client
    if _configcenter_client is None:
        _configcenter_client = ConfigCenterClient()
    return _configcenter_client
