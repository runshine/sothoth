"""Materialize ConfigCenter LLM Provider for pi-re-agent."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

from app.config import get_config
from app.service.configcenter import get_configcenter_client


logger = logging.getLogger(__name__)
_cached_provider: Optional[dict[str, Any]] = None
_cached_providers: dict[str, dict[str, Any]] = {}
_DEFAULT_CONTEXT_WINDOW = 128000
_DEFAULT_MAX_TOKENS = 8192


def _provider_api(provider_type: str) -> str:
    normalized = str(provider_type or "").strip().lower()
    if normalized == "anthropic":
        return "anthropic-messages"
    return "openai-completions"


def _provider_model_name(provider: dict[str, Any]) -> str:
    provider_key = str(provider.get("provider_key") or "").strip()
    model = str(provider.get("model") or "").strip()
    if not provider_key or not model:
        raise ValueError("LLM Provider缺少provider_key或model")
    return f"{provider_key}/{model}"


def _as_positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
        return parsed if parsed > 0 else default
    except (TypeError, ValueError):
        return default


def _build_models_json(provider: dict[str, Any]) -> dict[str, Any]:
    provider_key = str(provider.get("provider_key") or "").strip()
    model = str(provider.get("model") or "").strip()
    api_base = str(provider.get("api_base") or "").strip()
    api_key = str(provider.get("api_key") or "").strip()
    if not provider_key or not model or not api_base or not api_key:
        raise ValueError("LLM Provider缺少provider_key/model/api_base/api_key")
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
        provider.get("max_tokens") or provider.get("maxTokens") or extra_config.get("max_tokens") or extra_config.get("maxTokens"),
        _DEFAULT_MAX_TOKENS,
    )
    return {
        "providers": {
            provider_key: {
                "baseUrl": api_base.rstrip("/"),
                "api": _provider_api(str(provider.get("provider_type") or "")),
                "apiKey": api_key,
                "models": [
                    {
                        "id": model,
                        "name": model,
                        "reasoning": False,
                        "input": ["text"],
                        "contextWindow": context_window,
                        "maxTokens": max_tokens,
                        "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
                    }
                ],
            }
        }
    }


def _build_settings_json(provider: dict[str, Any]) -> dict[str, Any]:
    provider_key = str(provider.get("provider_key") or "").strip()
    model = str(provider.get("model") or "").strip()
    return {
        "defaultProvider": provider_key,
        "defaultModel": model,
        "retry": {"enabled": True},
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _write_file_bindings(config_dir: Path, provider: dict[str, Any]) -> None:
    """Write safe relative copies of ConfigCenter file bindings for diagnostics.

    The pi-re-agent container consumes models.json/settings.json directly.  We do
    not write arbitrary absolute paths from ConfigCenter here because this
    adapter only owns the shared agent config directory.
    """
    bindings = provider.get("file_bindings") if isinstance(provider.get("file_bindings"), list) else []
    if not bindings:
        return
    safe_root = config_dir / "file_bindings"
    safe_root.mkdir(parents=True, exist_ok=True)
    manifest: list[dict[str, str]] = []
    for index, item in enumerate(bindings, start=1):
        if not isinstance(item, dict) or item.get("enabled") is False:
            continue
        name = str(item.get("name") or f"binding-{index}").replace("/", "_").replace("\\", "_")
        content = item.get("content")
        if not isinstance(content, str):
            continue
        target = safe_root / f"{index}-{name}"
        target.write_text(content, encoding="utf-8")
        manifest.append({"source_path": str(item.get("path") or ""), "local_path": str(target)})
    _write_json(safe_root / "manifest.json", {"items": manifest})


async def materialize_llm_provider(provider_key: str | None = None) -> dict[str, Any] | None:
    """Fetch ConfigCenter LLM Provider and write pi-re-agent config files.

    The selected provider can be supplied per task.  This makes provider
    switching dynamic: B2S no longer needs a ConfigMap update or Pod restart to
    use a different ConfigCenter provider.
    """
    global _cached_provider
    cfg = get_config()
    if not cfg.configcenter_service.enabled:
        logger.info("配置中心未启用，跳过LLM Provider物化")
        return None

    requested_key = (provider_key or cfg.pi_re_agent.llm_provider_key or "").strip()
    if requested_key and requested_key in _cached_providers:
        provider = _cached_providers[requested_key]
    else:
        client = get_configcenter_client()
        provider = await client.get_llm_provider(requested_key) if requested_key else await client.get_default_llm_provider()
        resolved_key = str(provider.get("provider_key") or "").strip()
        if resolved_key:
            _cached_providers[resolved_key] = provider

    config_dir = Path(cfg.pi_re_agent.agent_config_dir).resolve()
    _write_json(config_dir / "models.json", _build_models_json(provider))
    _write_json(config_dir / "settings.json", _build_settings_json(provider))
    _write_json(config_dir / "auth.json", {})
    _write_json(config_dir / "provider.snapshot.json", provider)
    _write_file_bindings(config_dir, provider)

    _cached_provider = provider
    logger.info(
        "已从配置中心物化LLM Provider: provider_key=%s model=%s config_dir=%s",
        provider.get("provider_key"),
        provider.get("model"),
        config_dir,
    )
    return provider


def get_cached_provider_model() -> str | None:
    if _cached_provider:
        return _provider_model_name(_cached_provider)
    cfg = get_config()
    if cfg.pi_re_agent.model:
        return cfg.pi_re_agent.model
    if cfg.pi_re_agent.llm_provider_key:
        return None
    return None


async def resolve_job_model(provider_key: str | None = None) -> str | None:
    cfg = get_config()
    if cfg.pi_re_agent.model:
        return cfg.pi_re_agent.model
    requested_key = (provider_key or "").strip()
    if requested_key:
        provider = await materialize_llm_provider(requested_key)
        return _provider_model_name(provider) if provider else None
    if _cached_provider is None and cfg.configcenter_service.enabled:
        await materialize_llm_provider()
    if _cached_provider:
        return _provider_model_name(_cached_provider)
    return None
