"""Service-level config: project-level overrides + global singleton.

Stores config blobs in DB table secflow_app_poc_project_configs.
project_id="" is the global singleton (default model/effort for all projects).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.db.models import AppPocProjectConfig
from app.time_utils import isoformat_local, now_local

logger = logging.getLogger("poc.config_service")

AVAILABLE_MODELS = [
    {"value": "glm-5.2", "label": "GLM-5.2 (默认)"},
    {"value": "glm-4.6", "label": "GLM-4.6"},
]
AVAILABLE_EFFORTS = ["low", "medium", "high", "xhigh", "max"]
DEFAULTS: Dict[str, Any] = {
    "default_model": "glm-5.2",
    "default_effort": "medium",
}


def get_config(db: Session, project_id: str = "") -> Dict[str, Any]:
    """Get merged config: defaults ← global singleton ← project override."""
    merged = dict(DEFAULTS)
    for pid in ("", project_id):
        if pid is None:
            continue
        row = db.query(AppPocProjectConfig).filter_by(project_id=pid).first()
        if row and row.config_json:
            merged.update(row.config_json)
    merged["available_models"] = AVAILABLE_MODELS
    merged["available_efforts"] = AVAILABLE_EFFORTS
    if project_id:
        global_row = db.query(AppPocProjectConfig).filter_by(project_id="").first()
        if global_row:
            merged["updated_at"] = isoformat_local(global_row.updated_at)
    else:
        row = db.query(AppPocProjectConfig).filter_by(project_id="").first()
        if row:
            merged["updated_at"] = isoformat_local(row.updated_at)
    return merged


def save_config(db: Session, project_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Upsert config blob for a project (or global if project_id='')."""
    row = db.query(AppPocProjectConfig).filter_by(project_id=project_id).first()
    if row is None:
        row = AppPocProjectConfig(project_id=project_id, config_json=config)
        db.add(row)
    else:
        merged = dict(row.config_json or {})
        merged.update(config)
        row.config_json = merged
    row.updated_at = now_local()
    db.commit()
    db.refresh(row)
    logger.info("saved config for project_id=%s", project_id or "<global>")
    return get_config(db, project_id)
