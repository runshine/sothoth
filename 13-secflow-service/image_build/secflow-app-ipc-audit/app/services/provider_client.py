from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from app.core.config import get_config


class ProviderClientError(RuntimeError):
    pass


class ProviderNotFoundError(ProviderClientError):
    pass


_ENV_PLACEHOLDER_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}")


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
        try:
            payload = self._request_json(self._list_url(), provider_key=None)
        except ProviderClientError as exc:
            payload = self._load_fallback_provider_list_or_raise(exc)
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
        try:
            payload = self._request_json(self._detail_url(normalized), provider_key=normalized)
        except ProviderClientError as exc:
            payload = self._load_fallback_provider_detail_or_raise(normalized, exc)
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

    def _load_fallback_provider_list(self) -> dict[str, Any]:
        payload = self._load_fallback_payload()
        items = payload.get("items")
        if not isinstance(items, list):
            raise ProviderClientError("provider fallback list payload is invalid")
        return {
            "total": int(payload.get("total") or len(items)),
            "default_provider_key": payload.get("default_provider_key"),
            "items": items,
        }

    def _load_fallback_provider_detail(self, provider_key: str) -> dict[str, Any]:
        payload = self._load_fallback_payload()
        items = payload.get("items")
        if not isinstance(items, list):
            raise ProviderClientError("provider fallback list payload is invalid")
        for item in items:
            if not isinstance(item, dict):
                continue
            if str(item.get("provider_key") or "").strip() == provider_key:
                return item
        raise ProviderNotFoundError(f"provider not found: {provider_key}")

    def _load_fallback_provider_list_or_raise(self, original_error: ProviderClientError) -> dict[str, Any]:
        if not self._has_fallback_file():
            raise original_error
        return self._load_fallback_provider_list()

    def _load_fallback_provider_detail_or_raise(
        self,
        provider_key: str,
        original_error: ProviderClientError,
    ) -> dict[str, Any]:
        if not self._has_fallback_file():
            raise original_error
        return self._load_fallback_provider_detail(provider_key)

    def _load_fallback_payload(self) -> dict[str, Any]:
        cfg = get_config().provider_source
        raw_path = str(cfg.fallback_file_path or "").strip()
        if not raw_path:
            raise ProviderClientError("provider source unavailable and fallback file is not configured")
        path = Path(raw_path)
        if not path.exists() or not path.is_file():
            raise ProviderClientError(f"provider fallback file not found: {path}")
        try:
            raw_payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ProviderClientError(f"failed to parse provider fallback file: {path}") from exc
        payload = self._normalize_fallback_payload(self._expand_env_placeholders(raw_payload))
        items = payload.get("items")
        if not isinstance(items, list):
            raise ProviderClientError(f"provider fallback file has invalid items: {path}")
        return payload

    @staticmethod
    def _has_fallback_file() -> bool:
        raw_path = str(get_config().provider_source.fallback_file_path or "").strip()
        return bool(raw_path)

    @classmethod
    def _normalize_fallback_payload(cls, raw_payload: Any) -> dict[str, Any]:
        default_provider_key: str | None = None
        raw_items: Any = raw_payload
        if isinstance(raw_payload, dict):
            raw_items = raw_payload.get("items")
            if raw_items is None:
                raw_items = raw_payload.get("providers")
            if raw_items is None and {"provider_key", "display_name", "provider_type"} & set(raw_payload.keys()):
                raw_items = [raw_payload]
            default_value = str(raw_payload.get("default_provider_key") or "").strip()
            default_provider_key = default_value or None
        items = cls._normalize_fallback_items(raw_items)
        if default_provider_key is None:
            default_provider_key = next(
                (
                    str(item.get("provider_key") or "").strip()
                    for item in items
                    if item.get("is_default") is True and str(item.get("provider_key") or "").strip()
                ),
                None,
            )
        return {
            "total": len(items),
            "default_provider_key": default_provider_key,
            "items": items,
        }

    @staticmethod
    def _normalize_fallback_items(raw_items: Any) -> list[dict[str, Any]]:
        candidates: list[Any]
        if isinstance(raw_items, list):
            candidates = raw_items
        elif isinstance(raw_items, dict):
            candidates = []
            for provider_key, item in raw_items.items():
                if not isinstance(item, dict):
                    continue
                normalized = dict(item)
                normalized.setdefault("provider_key", str(provider_key))
                candidates.append(normalized)
        else:
            return []
        normalized_items: list[dict[str, Any]] = []
        for item in candidates:
            if not isinstance(item, dict):
                continue
            provider_key = str(item.get("provider_key") or "").strip()
            if not provider_key:
                continue
            normalized = dict(item)
            normalized["provider_key"] = provider_key
            normalized_items.append(normalized)
        return normalized_items

    @classmethod
    def _expand_env_placeholders(cls, value: Any) -> Any:
        if isinstance(value, str):
            return cls._expand_env_string(value)
        if isinstance(value, list):
            return [cls._expand_env_placeholders(item) for item in value]
        if isinstance(value, dict):
            return {str(key): cls._expand_env_placeholders(item) for key, item in value.items()}
        return value

    @staticmethod
    def _expand_env_string(value: str) -> str:
        def replace(match: re.Match[str]) -> str:
            env_key = match.group(1)
            default_value = match.group(2)
            env_value = os.environ.get(env_key)
            if env_value is not None:
                return env_value
            return default_value or ""

        return _ENV_PLACEHOLDER_PATTERN.sub(replace, value)

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
