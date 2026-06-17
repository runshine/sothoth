"""Runtime service-level configuration for vuln-verify."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.exception import ValidationError
from app.model import VulnVerifyServiceConfig
from app.schemas import TokenUser
from app.time_utils import now_local

CONFIG_KEY = "default"
DEFAULT_CONFIG: dict[str, Any] = {"default_model": None}


def _operator_name(operator: TokenUser | str | None) -> str | None:
    if isinstance(operator, TokenUser):
        return operator.username or operator.user_id
    return str(operator or "").strip() or None


def normalize_default_model(value: str | None) -> str | None:
    raw = str(value or "").strip()
    return raw or None


def validate_default_model(value: str | None) -> str | None:
    model = normalize_default_model(value)
    if not model:
        return None
    if len(model) > 255:
        raise ValidationError("默认模型长度不能超过255")
    if any(ch.isspace() for ch in model):
        raise ValidationError("默认模型不能包含空白字符")
    return model


def normalize_service_config(config: dict[str, Any] | None) -> dict[str, Any]:
    source = dict(DEFAULT_CONFIG)
    if isinstance(config, dict):
        source.update(config)
    return {"default_model": validate_default_model(source.get("default_model"))}


def get_service_config(db: Session) -> tuple[dict[str, Any], VulnVerifyServiceConfig | None]:
    row = db.query(VulnVerifyServiceConfig).filter(VulnVerifyServiceConfig.config_key == CONFIG_KEY).first()
    if not row:
        return dict(DEFAULT_CONFIG), None
    return normalize_service_config(row.config), row


def save_service_config(db: Session, config: dict[str, Any], operator: TokenUser | str | None) -> tuple[dict[str, Any], VulnVerifyServiceConfig]:
    normalized = normalize_service_config(config)
    row = db.query(VulnVerifyServiceConfig).filter(VulnVerifyServiceConfig.config_key == CONFIG_KEY).first()
    now = now_local()
    if row is None:
        row = VulnVerifyServiceConfig(config_key=CONFIG_KEY, created_at=now)
        db.add(row)
    row.config = normalized
    row.updated_by = _operator_name(operator)
    row.updated_at = now
    db.commit()
    db.refresh(row)
    return normalized, row


def get_service_default_model(db: Session) -> str | None:
    config, _ = get_service_config(db)
    return normalize_default_model(config.get("default_model"))


def read_pi_settings_default() -> str | None:
    """Best-effort fallback hint from pi settings.json, without failing config APIs."""
    import os

    settings_path = Path(os.environ.get("PI_CODING_AGENT_DIR") or "/root/.pi/agent") / "settings.json"
    try:
        payload = json.loads(settings_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    provider = str(payload.get("defaultProvider") or "").strip()
    model = str(payload.get("defaultModel") or "").strip()
    return f"{provider}/{model}" if provider and model else None


def resolve_effective_default_model(db: Session) -> tuple[str | None, str]:
    service_default = get_service_default_model(db)
    if service_default:
        return service_default, "service_config"
    pi_default = read_pi_settings_default()
    if pi_default:
        return pi_default, "configcenter_pi_settings"
    return None, "none"
