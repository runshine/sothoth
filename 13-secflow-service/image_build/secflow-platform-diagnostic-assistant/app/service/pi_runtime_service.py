from __future__ import annotations

import json
import os
from pathlib import Path

from app.config import get_service_yaml
from app.models import LlmProviderConfig
from app.service.llm_provider_sync import build_models_json


def _service_runtime_root() -> Path:
    db_path = Path(get_service_yaml().database.sqlite_path)
    return db_path.parent / "pi_runtime"


def build_session_path(session_id: int) -> Path:
    return _service_runtime_root() / f"session-{session_id}" / "session.jsonl"


def _build_settings_json() -> dict[str, Any]:
    return {
        "defaultThinkingLevel": "off",
        "compaction": {
            "enabled": True,
            "reserveTokens": 8192,
            "keepRecentTokens": 50000,
        },
    }


def _filtered_runtime_env(provider: LlmProviderConfig) -> dict[str, str]:
    env_bindings = provider.extra_config.get("env_bindings") if isinstance(provider.extra_config.get("env_bindings"), dict) else {}
    blocked = {
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_MODEL",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_MODEL",
    }
    payload: dict[str, str] = {}
    for key, value in env_bindings.items():
        key_text = str(key or "").strip()
        if not key_text or key_text in blocked:
            continue
        payload[key_text] = "" if value is None else str(value)
    return payload


def _substitute_secret_into_models_json(models_json: dict[str, object], secret: str | None) -> dict[str, object]:
    normalized_secret = str(secret or "").strip()
    if not normalized_secret:
        return models_json
    providers = models_json.get("providers")
    if not isinstance(providers, dict):
        return models_json
    for provider_cfg in providers.values():
        if isinstance(provider_cfg, dict):
            provider_cfg["apiKey"] = normalized_secret
    return models_json


def _resolve_selected_provider(
    providers: list[LlmProviderConfig],
    selected_provider_key: str | None,
) -> LlmProviderConfig:
    normalized_target = str(selected_provider_key or "").strip()
    fallback_keys = [normalized_target, "share_codex", "local_minimax"]
    for provider_key in fallback_keys:
        if not provider_key:
            continue
        for provider in providers:
            if provider.provider_key != provider_key:
                continue
            if provider.enabled and provider.api_base and provider.api_key and provider.model:
                return provider
    for provider in providers:
        if provider.enabled and provider.api_base and provider.api_key and provider.model:
            return provider
    raise RuntimeError("配置中心没有可用于 pi 的 provider")


def resolve_selected_provider(
    providers: list[LlmProviderConfig],
    selected_provider_key: str | None,
) -> LlmProviderConfig:
    return _resolve_selected_provider(providers, selected_provider_key)


def build_pi_runtime_artifacts(
    runtime_dir: str | Path,
    provider: LlmProviderConfig,
    providers: list[LlmProviderConfig],
    *,
    agent_task_key_secret: str | None = None,
) -> dict[str, Any]:
    runtime_path = Path(runtime_dir)
    runtime_path.mkdir(parents=True, exist_ok=True)
    models_path = runtime_path / "models.json"
    settings_path = runtime_path / "settings.json"

    models_json = _substitute_secret_into_models_json(
        build_models_json(providers),
        agent_task_key_secret,
    )
    models_path.write_text(json.dumps(models_json, ensure_ascii=False, indent=2), encoding="utf-8")
    settings_path.write_text(json.dumps(_build_settings_json(), ensure_ascii=False, indent=2), encoding="utf-8")

    env = os.environ.copy()
    env.update(_filtered_runtime_env(provider))
    env["PI_CODING_AGENT_DIR"] = str(runtime_path)
    env["PI_MODELS_JSON"] = str(models_path)
    return {
        "runtime_dir": str(runtime_path),
        "models_path": str(models_path),
        "settings_path": str(settings_path),
        "model_ref": f"{provider.provider_key}/{provider.model}",
        "provider_key": provider.provider_key,
        "env": env,
    }


def prepare_pi_runtime(
    session_id: int,
    providers: list[LlmProviderConfig],
    *,
    selected_provider_key: str | None = None,
    agent_task_key_secret: str | None = None,
) -> dict[str, Any]:
    selected_provider = _resolve_selected_provider(providers, selected_provider_key)
    runtime_dir = _service_runtime_root() / f"session-{session_id}"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    session_path = build_session_path(session_id)
    session_path.parent.mkdir(parents=True, exist_ok=True)
    session_path.touch(exist_ok=True)
    artifacts = build_pi_runtime_artifacts(
        runtime_dir,
        selected_provider,
        providers,
        agent_task_key_secret=agent_task_key_secret,
    )

    return {**artifacts, "session_path": str(session_path)}
