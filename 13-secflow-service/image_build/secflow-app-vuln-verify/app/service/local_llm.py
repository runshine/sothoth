"""Local pi LLM configuration writer.

This replaces the platform ConfigCenter dependency for local development.  The
service reads OPENAI_API_KEY/OPENAI_BASE_URL/OPENAI_MODEL (or LLM_* aliases) and
materializes pi runtime config under PI_CODING_AGENT_DIR.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from app.config import get_config

logger = logging.getLogger(__name__)


def _provider_api(provider_type: str) -> str:
    return "anthropic-messages" if provider_type.strip().lower() == "anthropic" else "openai-completions"


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        path.unlink()
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def materialize_local_llm_config(*, require_api_key: bool = False) -> bool:
    cfg = get_config().local_llm
    api_key = str(cfg.api_key or "").strip()
    if not api_key:
        message = "未配置 LLM API Key；设置 OPENAI_API_KEY 或 LLM_API_KEY 后任务才能调用 pi/LLM"
        if require_api_key:
            raise RuntimeError(message)
        logger.warning(message)
        return False

    provider_key = str(cfg.provider_key or "local_openai").strip() or "local_openai"
    model = str(cfg.model or "").strip()
    if not model:
        raise RuntimeError("未配置 LLM 模型；请设置 OPENAI_MODEL 或 LLM_MODEL")

    pi_dir = Path(os.environ.get("PI_CODING_AGENT_DIR") or "/root/.pi/agent")
    models_path = pi_dir / "models.json"
    settings_path = pi_dir / "settings.json"
    model_entry: dict[str, Any] = {
        "id": model,
        "name": model,
        "reasoning": False,
        "input": ["text"],
        "contextWindow": int(cfg.context_window or 128000),
        "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
    }
    if cfg.max_tokens:
        model_entry["maxTokens"] = int(cfg.max_tokens)

    _atomic_write_json(models_path, {
        "providers": {
            provider_key: {
                "baseUrl": str(cfg.api_base or "").rstrip("/"),
                "api": _provider_api(str(cfg.provider_type or "openai")),
                "apiKey": api_key,
                "models": [model_entry],
            }
        }
    })
    existing: dict[str, Any] = {}
    if settings_path.exists() and not settings_path.is_symlink():
        try:
            parsed = json.loads(settings_path.read_text(encoding="utf-8"))
            if isinstance(parsed, dict):
                existing = parsed
        except Exception:
            existing = {}
    existing["defaultProvider"] = provider_key
    existing["defaultModel"] = model
    _atomic_write_json(settings_path, existing)
    logger.info("local LLM config written: provider=%s model=%s dir=%s", provider_key, model, pi_dir)
    return True
