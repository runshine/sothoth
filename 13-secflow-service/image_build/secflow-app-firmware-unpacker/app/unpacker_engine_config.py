"""Configuration, prompts, and template helpers for firmware unpacking."""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any


AGENT_DIR = Path(
    os.environ.get(
        "UNPACKER_AGENT_DIR",
        str(Path(__file__).resolve().parent / "agent"),
    )
)

EXEC_AGENT_DEF = str(AGENT_DIR / "firmware-unpacker.md")
VAL_AGENT_DEF = str(AGENT_DIR / "firmware-unpack-reviewer.md")
CLEAN_AGENT_DEF = str(AGENT_DIR / "firmware-extract-cleanup.md")
AUTHOR_AGENT_DEF = str(AGENT_DIR / "firmware-skill-author.md")

EXEC_FIRST_TMPL = AGENT_DIR / "prompt" / "unpack-firmware.md"
EXEC_RETRY_TMPL = AGENT_DIR / "prompt" / "retry-firmware-unpack.md"
VAL_PROMPT_TMPL = AGENT_DIR / "prompt" / "review-firmware-unpack.md"
CLEAN_PROMPT_TMPL = AGENT_DIR / "prompt" / "cleanup-firmware.md"
AUTHOR_PROMPT_TMPL = AGENT_DIR / "prompt" / "author-firmware-skill.md"

TOOLS_DIR = Path(os.environ.get("UNPACKER_TOOLS_DIR", "/data/secflow-app-firmware-unpacker/tools"))
LOG_OUTPUT_DIR = Path(os.environ.get("UNPACKER_LOG_DIR", "/workspace/log_output"))
PI_AGENT_DIR_ENV = "PI_CODING_AGENT_DIR"

ROLE_CONFIG_FILE_KEYS = {
    "executor": "llm_config_file_key_executor",
    "reviewer": "llm_config_file_key_reviewer",
    "cleaner": "llm_config_file_key_cleaner",
    "skill_author": "llm_config_file_key_skill_author",
    "skill_executor": "llm_config_file_key_skill_executor",
}

ROLE_MODEL_CONFIG_KEYS = {
    "executor": "llm_model_executor",
    "reviewer": "llm_model_reviewer",
    "cleaner": "llm_model_cleaner",
    "skill_author": "llm_model_skill_author",
    "skill_executor": "llm_model_skill_executor",
}


def get_max_retries() -> int:
    try:
        from app.model import get_config_value, get_db_session

        db = get_db_session()
        try:
            return get_config_value(db, "max_retries", default=5)
        finally:
            db.close()
    except Exception:
        return 5


def get_max_retries_reached_action() -> str:
    try:
        from app.model import get_config_value, get_db_session

        db = get_db_session()
        try:
            value = str(
                get_config_value(db, "max_retries_reached_action", default="success")
                or "success"
            ).strip().lower()
        finally:
            db.close()
    except Exception:
        value = "success"
    return value if value in {"success", "failed"} else "success"


def preview_text(text: str, limit: int = 240) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[:limit] + "..."


def resolve_provider_model(provider_key: str, configured_model: str, explicit_model: str | None) -> str:
    requested = str(explicit_model or "").strip()
    provider_default_model = str(configured_model or "").strip()
    if not requested:
        if not provider_default_model:
            raise ValueError(f"LLM Provider {provider_key} 缺少默认 model")
        if "/" in provider_default_model:
            _, _, provider_default_model = provider_default_model.partition("/")
        return provider_default_model
    if "/" in requested:
        _, _, model_id = requested.partition("/")
        normalized_model = str(model_id or "").strip()
        if not normalized_model:
            raise ValueError(f"显式模型 {requested} 缺少 model_id")
        return normalized_model
    return requested


def resolve_provider_selector(provider_key: str, configured_model: str, explicit_model: str | None) -> tuple[str, str, str]:
    requested = str(explicit_model or "").strip()
    provider_default_model = str(configured_model or "").strip()
    if requested:
        if "/" in requested:
            selected_provider, _, selected_model = requested.partition("/")
            selected_provider = str(selected_provider or "").strip() or provider_key
            selected_model = str(selected_model or "").strip()
            if not selected_model:
                raise ValueError(f"显式模型 {requested} 缺少 model_id")
            return selected_provider, selected_model, f"{selected_provider}/{selected_model}"
        resolved_model = resolve_provider_model(provider_key, provider_default_model, requested)
        return provider_key, resolved_model, f"{provider_key}/{resolved_model}"
    if provider_default_model:
        if "/" in provider_default_model:
            selected_provider, _, selected_model = provider_default_model.partition("/")
            selected_provider = str(selected_provider or "").strip() or provider_key
            selected_model = str(selected_model or "").strip()
            if not selected_model:
                raise ValueError(f"默认模型 {provider_default_model} 缺少 model_id")
            return selected_provider, selected_model, f"{selected_provider}/{selected_model}"
        resolved_model = resolve_provider_model(provider_key, provider_default_model, None)
        return provider_key, resolved_model, f"{provider_key}/{resolved_model}"
    raise ValueError(f"LLM Provider {provider_key} 缺少默认 model")


def build_settings_json(provider_key: str, resolved_model: str) -> dict[str, Any]:
    return {
        "defaultProvider": provider_key,
        "defaultModel": resolved_model,
        "retry": {"enabled": True},
    }


def load_agent_def(md_path: str) -> dict[str, Any]:
    content = Path(md_path).read_text()
    match = re.match(r"^---\n(.*?)\n---\n(.*)$", content, re.DOTALL)
    if not match:
        raise ValueError(f"Invalid agent definition (missing frontmatter): {md_path}")

    fm: dict[str, str] = {}
    for line in match.group(1).split("\n"):
        if ":" in line:
            key, _, value = line.partition(":")
            fm[key.strip()] = value.strip()

    tools = [item.strip() for item in fm.get("tools", "").split(",") if item.strip()]
    return {
        "name": fm.get("name", Path(md_path).stem),
        "tools": tools,
        "model": fm.get("model") or None,
        "system_prompt": match.group(2).strip(),
    }


def render_prompt(template_path: Path, firmware_path: str, output_path: str) -> str:
    text = template_path.read_text()
    text = text.replace("$input", firmware_path)
    text = text.replace("$output", output_path)
    return text


def render_template(template_path: Path, replacements: dict[str, str]) -> str:
    text = template_path.read_text()
    for key, value in replacements.items():
        text = text.replace(key, value)
    return text


def utc_now_iso() -> str:
    from app.time_utils import isoformat_local, now_local

    return isoformat_local(now_local()) or ""


def slug_session_part(value: str, *, fallback: str) -> str:
    normalized = re.sub(r"[^a-z0-9._-]+", "-", str(value or "").strip().lower())
    normalized = normalized.strip(".-_")
    return normalized or fallback
