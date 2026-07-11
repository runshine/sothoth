from __future__ import annotations

from typing import Any

from app.models import LlmProviderConfig

_DEFAULT_CONTEXT_WINDOW = 128000
_MIN_CONTEXT_WINDOW = 131072
_MIN_MAX_OUTPUT_TOKENS = 32768


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


def _model_entries(provider: LlmProviderConfig) -> list[dict[str, Any]]:
    model_id = str(provider.model or "").strip()
    extra_config = provider.extra_config if isinstance(provider.extra_config, dict) else {}
    context_window = _as_positive_int(
        extra_config.get("model_context_window")
        or extra_config.get("context_window")
        or extra_config.get("contextWindow")
        or extra_config.get("context_length")
        or extra_config.get("contextLength"),
        _DEFAULT_CONTEXT_WINDOW,
    )
    pi_models = extra_config.get("pi_models")
    raw_models = pi_models if isinstance(pi_models, list) else ([{"id": model_id, "reasoning": False}] if model_id else [])

    models: list[dict[str, Any]] = []
    for raw in raw_models:
        if not isinstance(raw, dict):
            continue
        entry = dict(raw)
        for key in list(entry.keys()):
            if key.lower() in ("maxtokens", "max_tokens", "max_output_tokens", "maxoutputtokens"):
                entry.pop(key, None)
        entry["maxTokens"] = _MIN_MAX_OUTPUT_TOKENS
        entry.setdefault("id", model_id)
        entry.setdefault("name", entry.get("id") or model_id)
        entry.setdefault("reasoning", False)
        entry.setdefault("input", ["text"])
        entry.setdefault("contextWindow", context_window)
        if int(entry.get("contextWindow") or 0) < _MIN_CONTEXT_WINDOW:
            entry["contextWindow"] = _MIN_CONTEXT_WINDOW
        entry.setdefault("contextLength", entry["contextWindow"])
        entry.setdefault("cost", {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0})
        models.append(entry)
    return models


def build_models_json(providers: list[LlmProviderConfig]) -> dict[str, Any]:
    result: dict[str, Any] = {"providers": {}}
    for provider in providers:
        if not provider.enabled:
            continue
        provider_key = str(provider.provider_key or "").strip()
        if not provider_key:
            continue
        models = _model_entries(provider)
        if not models:
            continue
        result["providers"][provider_key] = {
            "baseUrl": str(provider.api_base or "").strip(),
            "api": _provider_api(provider.provider_type),
            "apiKey": str(provider.api_key or "").strip(),
            "models": models,
        }
    return result
