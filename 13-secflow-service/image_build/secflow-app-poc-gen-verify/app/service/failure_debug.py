"""Failure debug: LLM-powered auto-diagnosis for failed tasks.

When a task fails (status=failed, returncode!=0), the dispatcher can trigger
a debugger session that uses the LLM to analyze the failure root cause.

For now, this is a lightweight stub that records the failure in the DB table
secflow_app_poc_failure_debug. A full LLM-powered debugger can be added later
as a separate debugger pod role.

The API pod provides CRUD endpoints for these reports.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models import AppPocFailureDebug, AppPocTask
from app.time_utils import isoformat_local, now_local

logger = logging.getLogger("poc.failure_debug")


def _row_to_dict(row: AppPocFailureDebug) -> dict:
    return {
        "id": row.id,
        "task_id": row.task_id,
        "project_id": row.project_id,
        "task_name": row.task_name,
        "status": row.status,
        "error_kind": row.error_kind,
        "failing_stage": row.failing_stage,
        "summary": row.summary,
        "report_path": row.report_path,
        "report_json": row.report_json,
        "debug_error": row.debug_error,
        "created_at": isoformat_local(row.created_at),
        "updated_at": isoformat_local(row.updated_at),
    }


def list_reports(db: Session, *, project_id: Optional[str] = None,
                 status: Optional[str] = None, page: int = 1, per_page: int = 50) -> dict:
    q = db.query(AppPocFailureDebug)
    if project_id:
        q = q.filter(AppPocFailureDebug.project_id == project_id)
    if status:
        q = q.filter(AppPocFailureDebug.status == status)
    total = q.count()
    rows = q.order_by(AppPocFailureDebug.id.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return {"items": [_row_to_dict(r) for r in rows], "total": total, "page": page, "per_page": per_page}


def get_report(db: Session, report_id: int) -> dict:
    row = db.query(AppPocFailureDebug).filter_by(id=report_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Failure debug report not found: {report_id}")
    return _row_to_dict(row)


def get_report_content(db: Session, report_id: int) -> str:
    row = db.query(AppPocFailureDebug).filter_by(id=report_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Failure debug report not found: {report_id}")
    if not row.report_path:
        raise HTTPException(status_code=404, detail="Report file path is empty")
    p = Path(row.report_path)
    if not p.is_file():
        raise HTTPException(status_code=404, detail=f"Report file not found: {p}")
    return p.read_text(encoding="utf-8", errors="replace")


def delete_report(db: Session, report_id: int) -> dict:
    row = db.query(AppPocFailureDebug).filter_by(id=report_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Failure debug report not found: {report_id}")
    if row.report_path:
        try:
            p = Path(row.report_path)
            if p.is_file():
                p.unlink()
        except Exception as exc:
            logger.warning("failed to delete report file: %s", exc)
    db.delete(row)
    db.commit()
    return {"status": "ok", "id": report_id, "message": "deleted"}


def create_or_update_for_task(db: Session, task: AppPocTask) -> AppPocFailureDebug:
    """Create or update a failure debug record for a failed task.

    Called by the dispatcher when a task reaches failed state.
    """
    existing = db.query(AppPocFailureDebug).filter_by(task_id=task.task_id).first()
    if existing:
        existing.task_name = task.task_name
        existing.status = "pending"
        existing.error_kind = str(task.error or "")[:64] if task.error else None
        existing.debug_error = None
        db.commit()
        db.refresh(existing)
        return existing
    row = AppPocFailureDebug(
        task_id=task.task_id,
        project_id=task.project_id,
        task_name=task.task_name,
        status="pending",
        error_kind=str(task.error or "")[:64] if task.error else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    logger.info("created failure debug record for task=%s", task.task_id)
    return row


# ─── Debug config (singleton) ───────────────────────────────────────────────

def get_debug_config(db: Session) -> dict:
    from app.db.models import AppPocDebugConfig
    row = db.query(AppPocDebugConfig).filter_by(config_key="global").first()
    config = {"model": "glm-5.2", "available_models": [
        {"value": "glm-5.2", "label": "GLM-5.2 (默认)"},
        {"value": "glm-4.6", "label": "GLM-4.6"},
    ]}
    if row and row.config_json:
        config.update(row.config_json)
        config["updated_at"] = isoformat_local(row.updated_at)
    return config


def save_debug_config(db: Session, model: str) -> dict:
    from app.db.models import AppPocDebugConfig
    row = db.query(AppPocDebugConfig).filter_by(config_key="global").first()
    if row is None:
        row = AppPocDebugConfig(config_key="global", config_json={"model": model})
        db.add(row)
    else:
        merged = dict(row.config_json or {})
        merged["model"] = model
        row.config_json = merged
    row.updated_at = now_local()
    db.commit()
    db.refresh(row)
    return get_debug_config(db)
