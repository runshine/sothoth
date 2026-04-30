"""ConfigCenter client for LLM Provider consumption."""

from __future__ import annotations

import os
from typing import Any, Optional

import httpx

from app.config import get_config
from app.exception import NotFoundError, UpstreamError, ValidationError


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

    async def list_llm_providers(self) -> dict[str, Any]:
        if not self.config.enabled:
            raise UpstreamError("配置中心未启用")
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout, headers=self._headers()) as client:
                resp = await client.get(f"{self._base_url()}/service/llm/providers")
        except httpx.TimeoutException:
            raise UpstreamError("配置中心请求超时")
        except httpx.ConnectError as exc:
            raise UpstreamError(f"无法连接配置中心: {exc}")
        return _handle(resp)

    async def get_llm_provider(self, provider_key: str) -> dict[str, Any]:
        if not self.config.enabled:
            raise UpstreamError("配置中心未启用")
        key = str(provider_key or "").strip()
        if not key:
            raise ValidationError("llm_provider_key不能为空")
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout, headers=self._headers()) as client:
                resp = await client.get(f"{self._base_url()}/service/llm/providers/{key}")
        except httpx.TimeoutException:
            raise UpstreamError("配置中心请求超时")
        except httpx.ConnectError as exc:
            raise UpstreamError(f"无法连接配置中心: {exc}")
        if resp.status_code == 404:
            raise NotFoundError(f"已启用的LLM Provider不存在: {key}")
        return _handle(resp)

    async def get_default_llm_provider(self) -> dict[str, Any]:
        payload = await self.list_llm_providers()
        key = payload.get("default_provider_key")
        items = payload.get("items") if isinstance(payload.get("items"), list) else []
        if key:
            for item in items:
                if item.get("provider_key") == key:
                    return item
            return await self.get_llm_provider(key)
        if items:
            return items[0]
        raise NotFoundError("没有可用的LLM Provider")


def _handle(resp: httpx.Response) -> dict[str, Any]:
    if 200 <= resp.status_code < 300:
        data = resp.json() if resp.content else {}
        return data if isinstance(data, dict) else {}
    if resp.status_code in (401, 403):
        raise UpstreamError(f"配置中心认证失败: {resp.status_code}")
    if resp.status_code == 422:
        raise ValidationError(resp.text or "配置中心参数校验失败")
    raise UpstreamError(f"配置中心返回异常状态码: {resp.status_code}, body={resp.text[:500]}")


_configcenter_client: Optional[ConfigCenterClient] = None


def get_configcenter_client() -> ConfigCenterClient:
    global _configcenter_client
    if _configcenter_client is None:
        _configcenter_client = ConfigCenterClient()
    return _configcenter_client
