"""Synchronize platform LLM providers into pi runtime config.

vuln-verify keeps a simple global pi runtime under PI_CODING_AGENT_DIR.  It does
not own model defaults: the platform ConfigCenter default provider/model is
materialized into pi's models.json and settings.json.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_CONTEXT_WINDOW = 128000


@dataclass
class LlmProviderSyncResult:
    ok: bool
    models_json_path: str
    settings_json_path: str | None = None
    provider_count: int = 0
    default_provider_key: str | None = None
    default_model: str | None = None
    default_model_ref: str | None = None
    error: str | None = None


def _provider_api(provider_type: str) -> str:
    normalized = str(provider_type or "").strip().lower()
    if normalized == "anthropic":
        return "anthropic-messages"
    return "openai-completions"


def _as_positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
        return parsed if parsed > 0 else default
    except (TypeError, ValueError):
        return default


def _model_entries(provider: dict[str, Any]) -> list[dict[str, Any]]:
    model_id = str(provider.get("model") or "").strip()
    extra_config = provider.get("extra_config") if isinstance(provider.get("extra_config"), dict) else {}
    context_window = _as_positive_int(
        provider.get("model_context_window")
        or provider.get("context_window")
        or provider.get("contextWindow")
        or provider.get("context_length")
        or provider.get("contextLength")
        or extra_config.get("model_context_window")
        or extra_config.get("contextWindow")
        or extra_config.get("context_length")
        or extra_config.get("contextLength"),
        _DEFAULT_CONTEXT_WINDOW,
    )
    max_tokens = _as_positive_int(
        provider.get("max_tokens")
        or provider.get("maxTokens")
        or extra_config.get("max_tokens")
        or extra_config.get("maxTokens"),
        0,
    )
    pi_models = extra_config.get("pi_models")
    raw_models = pi_models if isinstance(pi_models, list) else ([{"id": model_id, "reasoning": False}] if model_id else [])
    models: list[dict[str, Any]] = []
    for raw in raw_models:
        if not isinstance(raw, dict):
            continue
        entry = dict(raw)
        entry.setdefault("id", model_id)
        entry.setdefault("name", entry.get("id") or model_id)
        entry.setdefault("reasoning", False)
        entry.setdefault("input", ["text"])
        entry.setdefault("contextWindow", context_window)
        if max_tokens > 0:
            entry.setdefault("maxTokens", max_tokens)
        entry.setdefault("cost", {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0})
        if str(entry.get("id") or "").strip():
            models.append(entry)
    return models


def build_models_json(providers: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {"providers": {}}
    for provider in providers:
        if not provider.get("enabled"):
            continue
        key = str(provider.get("provider_key") or "").strip()
        if not key:
            continue
        result["providers"][key] = {
            "baseUrl": provider.get("api_base", ""),
            "api": _provider_api(str(provider.get("provider_type") or "")),
            "apiKey": str(provider.get("api_key") or "").strip(),
            "models": _model_entries(provider),
        }
    return result


def select_default_provider(
    payload: dict[str, Any],
    providers: list[dict[str, Any]],
    *,
    preferred_provider_key: str | None = None,
) -> dict[str, Any] | None:
    enabled = [p for p in providers if isinstance(p, dict) and p.get("enabled")]
    preferred = str(preferred_provider_key or "").strip()
    if preferred:
        for provider in enabled:
            if str(provider.get("provider_key") or "").strip() == preferred:
                return provider
    default_key = str(payload.get("default_provider_key") or "").strip()
    if default_key:
        for provider in enabled:
            if str(provider.get("provider_key") or "").strip() == default_key:
                return provider
    for provider in enabled:
        if provider.get("is_default"):
            return provider
    for provider in enabled:
        if str(provider.get("model") or "").strip():
            return provider
    return enabled[0] if enabled else None


def select_default_model_id(provider: dict[str, Any]) -> str | None:
    models = _model_entries(provider)
    if not models:
        return None
    extra_config = provider.get("extra_config") if isinstance(provider.get("extra_config"), dict) else {}
    preferred = str(extra_config.get("pi_default_model") or "").strip()
    if preferred:
        for model in models:
            if preferred in {str(model.get("id") or "").strip(), str(model.get("name") or "").strip()}:
                return str(model.get("id") or "").strip() or None
    provider_model = str(provider.get("model") or "").strip()
    if provider_model:
        for model in models:
            if provider_model in {str(model.get("id") or "").strip(), str(model.get("name") or "").strip()}:
                return str(model.get("id") or "").strip() or None
    return str(models[0].get("id") or "").strip() or None


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        path.unlink()
    tmp_path = path.with_name(f".{path.name}.tmp")
    tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp_path, path)


def _write_settings_default(settings_path: Path, provider_key: str, model_id: str) -> None:
    existing: dict[str, Any] = {}
    if settings_path.exists() and not settings_path.is_symlink():
        try:
            parsed = json.loads(settings_path.read_text(encoding="utf-8"))
            if isinstance(parsed, dict):
                existing = parsed
        except Exception as exc:
            logger.warning("failed to read existing pi settings %s: %s", settings_path, exc)
    existing["defaultProvider"] = provider_key
    existing["defaultModel"] = model_id
    _atomic_write_json(settings_path, existing)


def sync_providers_to_pi(
    *,
    base_url: str,
    token: str = "",
    timeout: int = 30,
    pi_dir: str | None = None,
    preferred_provider_key: str | None = None,
) -> LlmProviderSyncResult:
    target_dir = Path(pi_dir or os.environ.get("PI_CODING_AGENT_DIR") or "/root/.pi/agent")
    models_path = target_dir / "models.json"
    settings_path = target_dir / "settings.json"
    url = f"{base_url.rstrip('/')}/service/llm/providers"
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get(url, headers=headers)
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:
        logger.warning("failed to fetch LLM providers from ConfigCenter: %s", exc)
        return LlmProviderSyncResult(ok=False, models_json_path=str(models_path), error=str(exc))

    providers = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(providers, list) or not providers:
        message = "ConfigCenter returned empty LLM provider list"
        logger.warning(message)
        return LlmProviderSyncResult(ok=False, models_json_path=str(models_path), error=message)

    try:
        models_json = build_models_json(providers)
        provider_count = len(models_json.get("providers") or {})
        if provider_count <= 0:
            raise RuntimeError("no enabled LLM providers available")
        _atomic_write_json(models_path, models_json)

        default_provider = select_default_provider(
            payload,
            providers,
            preferred_provider_key=preferred_provider_key,
        )
        default_provider_key = str((default_provider or {}).get("provider_key") or "").strip() or None
        default_model = select_default_model_id(default_provider) if default_provider else None
        default_model_ref = f"{default_provider_key}/{default_model}" if default_provider_key and default_model else None
        if default_provider_key and default_model:
            _write_settings_default(settings_path, default_provider_key, default_model)
        else:
            logger.warning("no ConfigCenter default provider/model found; pi settings default not updated")

        logger.info(
            "synced %d LLM providers to %s, default=%s",
            provider_count,
            models_path,
            default_model_ref or "-",
        )
        return LlmProviderSyncResult(
            ok=True,
            models_json_path=str(models_path),
            settings_json_path=str(settings_path),
            provider_count=provider_count,
            default_provider_key=default_provider_key,
            default_model=default_model,
            default_model_ref=default_model_ref,
        )
    except Exception as exc:
        logger.exception("failed to write pi LLM provider config: %s", exc)
        return LlmProviderSyncResult(ok=False, models_json_path=str(models_path), error=str(exc))
