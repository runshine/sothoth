"""
Config Center Service API Client
"""

import logging
from typing import Any, Dict, Optional

import httpx

from app.config import get_config
from app.exception import InternalError, NotFoundError, ValidationError

logger = logging.getLogger(__name__)


class ConfigCenterClient:
    """Config Center微服务客户端"""

    def __init__(self):
        config = get_config()
        self.configcenter_service_config = config.configcenter_service
        self.auth_service_config = config.auth_service
        self._client: Optional[httpx.AsyncClient] = None

    def _default_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        machine_token = getattr(self.auth_service_config, "service_machine_token", None)
        if machine_token:
            headers["Authorization"] = f"Bearer {machine_token}"
        return headers

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            timeout = self.configcenter_service_config.timeout if self.configcenter_service_config else 30
            self._client = httpx.AsyncClient(timeout=timeout, headers=self._default_headers())
        return self._client

    def _get_base_url(self) -> str:
        return self.configcenter_service_config.base_url

    async def list_llm_providers(self) -> Dict[str, Any]:
        if not self.configcenter_service_config.enabled:
            raise InternalError("config center service is required but disabled")
        url = f"{self._get_base_url()}/service/llm/providers"
        try:
            response = await self.client.get(url)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            logger.error("Failed to list llm providers from config center: %s", exc.response.text)
            raise InternalError("Failed to load llm providers from config center")
        except httpx.HTTPError as exc:
            logger.error("Failed to connect config center: %s", exc)
            raise InternalError("Config center service is unavailable")

    async def get_llm_provider(self, provider_key: str) -> Dict[str, Any]:
        if not self.configcenter_service_config.enabled:
            raise InternalError("config center service is required but disabled")
        url = f"{self._get_base_url()}/service/llm/providers/{provider_key}"
        try:
            response = await self.client.get(url)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            logger.error(
                "Failed to get llm provider %s from config center: %s",
                provider_key,
                exc.response.text,
            )
            if exc.response.status_code == 404:
                raise NotFoundError("Enabled LLM Provider", provider_key)
            if exc.response.status_code == 422:
                raise ValidationError(f"Invalid llm provider key: {provider_key}")
            raise InternalError("Failed to fetch llm provider from config center")
        except httpx.HTTPError as exc:
            logger.error("Failed to connect config center: %s", exc)
            raise InternalError("Config center service is unavailable")


_configcenter_client: Optional[ConfigCenterClient] = None


def get_configcenter_client() -> ConfigCenterClient:
    global _configcenter_client
    if _configcenter_client is None:
        _configcenter_client = ConfigCenterClient()
    return _configcenter_client
