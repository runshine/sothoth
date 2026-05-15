"""Project-level config service for binary-to-source."""

from __future__ import annotations

from typing import Any, Dict

from sqlalchemy.orm import Session

from app.model import B2SProjectConfig


_DEFAULT_CONFIG: Dict[str, Any] = {
    "budget_exhausted_action": "treat_as_passed",
    "llm_provider_key": None,
}

_VALID_ACTIONS = {"treat_as_passed", "treat_as_failed"}


def normalize_budget_exhausted_action(value: str | None) -> str:
    candidate = str(value or "").strip().lower()
    if candidate in _VALID_ACTIONS:
        return candidate
    return "treat_as_passed"


class ConfigService:
    def get_config(self, db: Session, project_id: str) -> dict:
        row = db.query(B2SProjectConfig).filter_by(project_id=project_id).first()
        if row and row.config:
            data = {**_DEFAULT_CONFIG, **row.config}
        else:
            data = dict(_DEFAULT_CONFIG)
        data["budget_exhausted_action"] = normalize_budget_exhausted_action(
            data.get("budget_exhausted_action")
        )
        data["llm_provider_key"] = _normalize_provider_key(data.get("llm_provider_key"))
        data["project_id"] = project_id
        data["updated_at"] = row.updated_at.isoformat() if (row and row.updated_at) else None
        return data

    def save_config(self, db: Session, project_id: str, config_data: dict) -> dict:
        blob = {k: v for k, v in config_data.items() if k not in {"project_id", "updated_at", "effective_llm_provider"}}
        blob["budget_exhausted_action"] = normalize_budget_exhausted_action(
            blob.get("budget_exhausted_action")
        )
        blob["llm_provider_key"] = _normalize_provider_key(blob.get("llm_provider_key"))
        row = db.query(B2SProjectConfig).filter_by(project_id=project_id).first()
        if row:
            row.config = blob
        else:
            row = B2SProjectConfig(project_id=project_id)
            row.config = blob
            db.add(row)
        db.commit()
        db.refresh(row)
        result = {**_DEFAULT_CONFIG, **blob}
        result["budget_exhausted_action"] = normalize_budget_exhausted_action(
            result.get("budget_exhausted_action")
        )
        result["llm_provider_key"] = _normalize_provider_key(result.get("llm_provider_key"))
        result["project_id"] = project_id
        result["updated_at"] = row.updated_at.isoformat() if row.updated_at else None
        return result


def _normalize_provider_key(value: Any) -> str | None:
    key = str(value or "").strip()
    return key or None


_config_service: ConfigService | None = None


def get_config_service() -> ConfigService:
    global _config_service
    if _config_service is None:
        _config_service = ConfigService()
    return _config_service
