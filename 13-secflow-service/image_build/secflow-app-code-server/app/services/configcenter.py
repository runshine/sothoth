"""
Code Server Manager - 配置中心客户端
"""

from typing import Any, Dict, Optional

import httpx

from app.config import get_config
from app.exception import InternalError, NotFoundError, ValidationError


class ConfigCenterClient:
    """Config Center service client (machine token)"""

    def __init__(self):
        cfg = get_config()
        self.configcenter = cfg.configcenter_service
        self.auth = cfg.auth_service
        self._client: Optional[httpx.Client] = None

    def _default_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        machine_token = getattr(self.auth, "service_machine_token", None)
        if machine_token:
            headers["Authorization"] = f"Bearer {machine_token}"
        return headers

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            timeout = self.configcenter.timeout if self.configcenter else 30
            self._client = httpx.Client(timeout=timeout, headers=self._default_headers())
        return self._client

    def _base_url(self) -> str:
        return self.configcenter.base_url.rstrip("/")

    def get_llm_provider(self, provider_key: str) -> Dict[str, Any]:
        if not self.configcenter.enabled:
            raise InternalError("配置中心未启用")
        if not str(provider_key or "").strip():
            raise ValidationError("llm_provider_key 不能为空")

        url = f"{self._base_url()}/service/llm/providers/{provider_key}"
        try:
            resp = self.client.get(url)
            resp.raise_for_status()
            payload = resp.json()
            return payload if isinstance(payload, dict) else {}
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                raise NotFoundError("已启用的 LLM Provider", provider_key)
            if exc.response.status_code == 422:
                raise ValidationError(f"无效的 llm_provider_key: {provider_key}")
            raise InternalError("拉取 LLM Provider 失败")
        except httpx.HTTPError:
            raise InternalError("配置中心服务不可用")


_configcenter_client: Optional[ConfigCenterClient] = None


def get_configcenter_client() -> ConfigCenterClient:
    global _configcenter_client
    if _configcenter_client is None:
        _configcenter_client = ConfigCenterClient()
    return _configcenter_client

