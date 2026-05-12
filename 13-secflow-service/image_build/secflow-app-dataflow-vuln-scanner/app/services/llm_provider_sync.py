"""Sync ConfigCenter LLM providers into pi models.json."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import httpx

from app.config import get_config

logger = logging.getLogger("dataflow_vuln.llm_sync")

_DEFAULT_CONTEXT_WINDOW = 128000
_DEFAULT_MAX_TOKENS = 8192
_LOCAL_PI_PROVIDER_KEY = "local_pi"


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
        _DEFAULT_MAX_TOKENS,
    )
    pi_models = extra_config.get("pi_models")
    raw_models = pi_models if isinstance(pi_models, list) else (
        [{"id": model_id, "reasoning": False}] if model_id else []
    )
    models: list[dict[str, Any]] = []
    for raw in raw_models:
        if isinstance(raw, str):
            entry = {"id": raw}
        elif isinstance(raw, dict):
            entry = dict(raw)
        else:
            continue
        entry.setdefault("id", model_id)
        entry.setdefault("name", entry.get("id") or model_id)
        entry.setdefault("reasoning", False)
        entry.setdefault("input", ["text"])
        entry.setdefault("contextWindow", context_window)
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
        provider_key = str(provider.get("provider_key") or "").strip()
        if not provider_key:
            continue
        result["providers"][provider_key] = {
            "baseUrl": provider.get("api_base", ""),
            "api": _provider_api(str(provider.get("provider_type") or "")),
            "apiKey": provider.get("api_key", ""),
            "models": _model_entries(provider),
        }
    return result


def _is_models_json_binding(binding: dict[str, Any]) -> bool:
    name = str(binding.get("name") or "").strip().lower()
    path = str(binding.get("path") or "").strip().replace("\\", "/").lower()
    return name == "models.json" or path.endswith("/models.json") or path == "models.json"


def _local_pi_injected_models_json(providers: list[dict[str, Any]]) -> str | None:
    for provider in providers:
        if not provider.get("enabled"):
            continue
        provider_key = str(provider.get("provider_key") or "").strip()
        if provider_key != _LOCAL_PI_PROVIDER_KEY:
            continue
        file_bindings = provider.get("file_bindings") if isinstance(provider.get("file_bindings"), list) else []
        for binding in file_bindings:
            if not isinstance(binding, dict) or not binding.get("enabled", True):
                continue
            if not _is_models_json_binding(binding):
                continue
            content = binding.get("content")
            if isinstance(content, str) and content.strip():
                return content
    return None


def _validated_models_json_provider_count(content: str) -> int:
    parsed = json.loads(content)
    if not isinstance(parsed, dict):
        raise ValueError("models.json top-level value must be an object")
    providers = parsed.get("providers")
    if not isinstance(providers, dict) or not providers:
        raise ValueError("models.json must contain a non-empty providers object")
    return len(providers)


def _write_models_json(models_path: Path, content: str) -> None:
    models_path.parent.mkdir(parents=True, exist_ok=True)
    if models_path.is_symlink():
        models_path.unlink()
    tmp_path = models_path.with_suffix(".json.tmp")
    tmp_path.write_text(content, encoding="utf-8")
    os.replace(tmp_path, models_path)


def _models_json_path() -> Path:
    explicit_path = str(os.environ.get("PI_MODELS_JSON") or "").strip()
    if explicit_path:
        return Path(explicit_path).expanduser()
    pi_dir = Path(os.environ.get("PI_CODING_AGENT_DIR", "/root/.pi/agent"))
    return pi_dir / "models.json"


def sync_providers_to_pi() -> bool:
    config = get_config()
    cc = config.configcenter_service
    if not cc.enabled:
        logger.info("configcenter disabled, skip LLM provider sync")
        return False

    url = f"{cc.base_url.rstrip('/')}/service/llm/providers"
    headers: dict[str, str] = {}
    token = os.environ.get("SECFLOW_SERVICE_MACHINE_TOKEN") or config.auth_service.service_machine_token
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        response = httpx.get(url, headers=headers, timeout=cc.timeout)
        if response.status_code != 200:
            logger.warning("ConfigCenter returned HTTP %s, skip LLM provider sync", response.status_code)
            return False
        payload = response.json()
        items = payload.get("items") if isinstance(payload.get("items"), list) else []
        if not items:
            logger.warning("ConfigCenter returned empty LLM provider list, skip sync")
            return False
        models_path = _models_json_path()

        injected_models_json = _local_pi_injected_models_json(items)
        if injected_models_json is not None:
            provider_count = _validated_models_json_provider_count(injected_models_json)
            _write_models_json(models_path, injected_models_json)
            logger.info(
                "copied %s injected models.json with %d providers to %s",
                _LOCAL_PI_PROVIDER_KEY,
                provider_count,
                models_path,
            )
            return True

        models_json = build_models_json(items)
        if not models_json["providers"]:
            logger.warning("ConfigCenter returned no enabled LLM providers, skip sync")
            return False
        _write_models_json(models_path, json.dumps(models_json, ensure_ascii=False, indent=2))
        logger.info("synced %d LLM providers to %s", len(models_json["providers"]), models_path)
        for provider_key, provider_cfg in models_json["providers"].items():
            for model in provider_cfg.get("models", []):
                logger.info(
                    "LLM Provider %s/%s contextWindow=%s maxTokens=%s",
                    provider_key,
                    model.get("id"),
                    model.get("contextWindow"),
                    model.get("maxTokens"),
                )
        return True
    except httpx.RequestError as exc:
        logger.warning("failed to connect ConfigCenter for LLM provider sync: %s", exc)
    except Exception as exc:
        logger.warning("failed to sync LLM providers: %s", exc, exc_info=True)
    return False
