from __future__ import annotations

from typing import Any

from app.config import get_config

REDACTED_KEYS = {"password", "token", "secret", "api_key", "authorization"}


def _should_redact(key: str | None) -> bool:
    if not key:
        return False
    lowered = key.lower()
    return any(marker in lowered for marker in REDACTED_KEYS)


def _redact(value: Any, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {
            item_key: ("***" if _should_redact(item_key) else _redact(item_value, item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_redact(item, key) for item in value]
    if _should_redact(key) and value not in (None, ""):
        return "***"
    return value


def build_sanitized_service_config() -> dict[str, Any]:
    config = get_config()
    payload = config.model_dump(mode="json")
    return {
        "service_name": config.registry.service_name,
        "api_prefix": config.service.public_api_prefix,
        "config": _redact(payload),
    }
