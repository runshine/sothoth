from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from app.core.config import get_config


class ProviderClientError(RuntimeError):
    pass


class ProviderNotFoundError(ProviderClientError):
    pass


class ProviderClient:
    def __init__(self) -> None:
        self._client: httpx.Client | None = None

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            cfg = get_config().provider_source
            headers: dict[str, str] = {}
            if cfg.machine_token:
                headers["Authorization"] = f"Bearer {cfg.machine_token}"
            self._client = httpx.Client(timeout=float(cfg.timeout_seconds), headers=headers)
        return self._client

    def list_providers(self) -> dict[str, Any]:
        payload = self._request_json(self._list_url(), provider_key=None)
        items = payload.get("items")
        if not isinstance(items, list):
            raise ProviderClientError("provider list response is invalid")
        return {
            "total": int(payload.get("total") or len(items)),
            "default_provider_key": payload.get("default_provider_key"),
            "items": items,
        }

    def get_provider_detail(self, provider_key: str) -> dict[str, Any]:
        normalized = str(provider_key or "").strip()
        if not normalized:
            raise ProviderClientError("provider_key is required")
        payload = self._request_json(self._detail_url(normalized), provider_key=normalized)
        if not isinstance(payload, dict):
            raise ProviderClientError(f"provider detail response is invalid: {normalized}")
        return payload

    def _request_json(self, url: str, *, provider_key: str | None) -> dict[str, Any]:
        cfg = get_config().provider_source
        if not cfg.enabled:
            raise ProviderClientError("provider source is disabled")
        try:
            response = self.client.get(url)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404 and provider_key:
                raise ProviderNotFoundError(f"provider not found: {provider_key}") from exc
            detail = exc.response.text.strip() or exc.response.reason_phrase
            if provider_key:
                raise ProviderClientError(
                    f"failed to fetch provider {provider_key}: {exc.response.status_code} {detail}"
                ) from exc
            raise ProviderClientError(
                f"failed to list providers: {exc.response.status_code} {detail}"
            ) from exc
        except httpx.HTTPError as exc:
            if provider_key:
                raise ProviderClientError(f"provider source unavailable for {provider_key}") from exc
            raise ProviderClientError("provider source unavailable") from exc
        payload = response.json()
        return payload if isinstance(payload, dict) else {}

    @staticmethod
    def _join_url(base_url: str, suffix: str) -> str:
        return f"{base_url.rstrip('/')}/{suffix.lstrip('/')}"

    def _list_url(self) -> str:
        cfg = get_config().provider_source
        prefix = cfg.api_prefix.rstrip("/")
        if cfg.backend == "platform_agent":
            return self._join_url(cfg.base_url, prefix)
        return self._join_url(cfg.base_url, f"{prefix}/providers")

    def _detail_url(self, provider_key: str) -> str:
        cfg = get_config().provider_source
        prefix = cfg.api_prefix.rstrip("/")
        encoded = quote(provider_key, safe="")
        if cfg.backend == "platform_agent":
            return self._join_url(cfg.base_url, f"{prefix}/{encoded}")
        return self._join_url(cfg.base_url, f"{prefix}/providers/{encoded}")


_provider_client: ProviderClient | None = None


def get_provider_client() -> ProviderClient:
    global _provider_client
    if _provider_client is None:
        _provider_client = ProviderClient()
    return _provider_client
