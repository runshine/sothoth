"""Global config service for binary-to-source."""

from __future__ import annotations

from typing import Any, Dict

from sqlalchemy.orm import Session

from app.model import B2SProjectConfig

_GLOBAL_CONFIG_PROJECT_ID = "__global__"

_DEFAULT_CONFIG: Dict[str, Any] = {
    "budget_exhausted_action": "treat_as_passed",
    "concurrency": 8,
    "llm_provider_key": None,
    "default_mode": "turbo",
}

_VALID_ACTIONS = {"treat_as_passed", "treat_as_failed"}
_VALID_MODES = {"turbo", "fast", "deep"}
_LEGACY_MODE_MAP = {
    "hybrid": "fast",
    "agent": "deep",
    "ida_only": "turbo",
}


def normalize_budget_exhausted_action(value: str | None) -> str:
    candidate = str(value or "").strip().lower()
    if candidate in _VALID_ACTIONS:
        return candidate
    return "treat_as_passed"


def normalize_concurrency(value: Any) -> int:
    try:
        normalized = int(value)
    except (TypeError, ValueError):
        return 8
    return max(1, min(16, normalized))


def normalize_b2s_mode(value: Any) -> str:
    candidate = str(value or "").strip().lower()
    candidate = _LEGACY_MODE_MAP.get(candidate, candidate)
    if candidate in _VALID_MODES:
        return candidate
    return "turbo"


class ConfigService:
    def _latest_legacy_project_row(self, db: Session) -> B2SProjectConfig | None:
        return (
            db.query(B2SProjectConfig)
            .filter(B2SProjectConfig.project_id != _GLOBAL_CONFIG_PROJECT_ID)
            .order_by(B2SProjectConfig.updated_at.desc())
            .first()
        )

    def _ensure_global_config_row(self, db: Session) -> B2SProjectConfig | None:
        row = db.query(B2SProjectConfig).filter_by(project_id=_GLOBAL_CONFIG_PROJECT_ID).first()
        if row is not None:
            return row
        legacy_row = self._latest_legacy_project_row(db)
        if legacy_row is None:
            return None
        migrated = B2SProjectConfig(project_id=_GLOBAL_CONFIG_PROJECT_ID)
        migrated.config = dict(legacy_row.config or {})
        db.add(migrated)
        db.commit()
        db.refresh(migrated)
        return migrated

    def get_config(self, db: Session, project_id: str | None = None) -> dict:
        row = self._ensure_global_config_row(db)
        if row and row.config:
            data = {**_DEFAULT_CONFIG, **row.config}
        else:
            data = dict(_DEFAULT_CONFIG)
        data["budget_exhausted_action"] = normalize_budget_exhausted_action(
            data.get("budget_exhausted_action")
        )
        data["concurrency"] = normalize_concurrency(data.get("concurrency"))
        data["default_mode"] = normalize_b2s_mode(data.get("default_mode"))
        data["llm_provider_key"] = _normalize_provider_key(data.get("llm_provider_key"))
        data["project_id"] = _GLOBAL_CONFIG_PROJECT_ID
        data["updated_at"] = row.updated_at.isoformat() if (row and row.updated_at) else None
        return data

    def save_config(self, db: Session, config_data: dict, project_id: str | None = None) -> dict:
        # Backward-compatible with the old call style:
        # save_config(db, project_id, config_data). Runtime API uses the new
        # global config style: save_config(db, config_data).
        if isinstance(config_data, str) and isinstance(project_id, dict):
            config_data = project_id
        blob = {k: v for k, v in (config_data or {}).items() if k not in {"project_id", "updated_at", "effective_llm_provider"}}
        blob["budget_exhausted_action"] = normalize_budget_exhausted_action(
            blob.get("budget_exhausted_action")
        )
        blob["concurrency"] = normalize_concurrency(blob.get("concurrency"))
        blob["default_mode"] = normalize_b2s_mode(blob.get("default_mode"))
        blob["llm_provider_key"] = _normalize_provider_key(blob.get("llm_provider_key"))
        row = self._ensure_global_config_row(db)
        if row:
            row.config = blob
        else:
            row = B2SProjectConfig(project_id=_GLOBAL_CONFIG_PROJECT_ID)
            row.config = blob
            db.add(row)
        db.commit()
        db.refresh(row)
        result = {**_DEFAULT_CONFIG, **blob}
        result["budget_exhausted_action"] = normalize_budget_exhausted_action(
            result.get("budget_exhausted_action")
        )
        result["concurrency"] = normalize_concurrency(result.get("concurrency"))
        result["default_mode"] = normalize_b2s_mode(result.get("default_mode"))
        result["llm_provider_key"] = _normalize_provider_key(result.get("llm_provider_key"))
        result["project_id"] = _GLOBAL_CONFIG_PROJECT_ID
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
