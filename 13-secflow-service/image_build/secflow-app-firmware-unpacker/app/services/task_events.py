"""Persistent task event storage for firmware unpacker tasks."""

from __future__ import annotations

import json
from typing import Any, Optional

from app.model import UnpackTaskEvent, generate_id, get_db_session

DB_TIMELINE_EVENT_LIMIT = 10_000


def _trim_task_timeline_events(db, task_id: str, *, limit: int | None = None) -> int:
    normalized_limit = max(0, int(DB_TIMELINE_EVENT_LIMIT if limit is None else limit))
    if normalized_limit <= 0:
        return 0
    total = int(
        db.query(UnpackTaskEvent)
        .filter(UnpackTaskEvent.task_id == task_id)
        .count()
        or 0
    )
    trim_count = max(0, total - normalized_limit)
    if trim_count <= 0:
        return 0
    old_event_ids = [
        row.id
        for row in (
            db.query(UnpackTaskEvent.id)
            .filter(UnpackTaskEvent.task_id == task_id)
            .order_by(UnpackTaskEvent.created_at.asc(), UnpackTaskEvent.id.asc())
            .limit(trim_count)
            .all()
        )
    ]
    if not old_event_ids:
        return 0
    deleted = (
        db.query(UnpackTaskEvent)
        .filter(UnpackTaskEvent.id.in_(old_event_ids))
        .delete(synchronize_session=False)
    )
    return int(deleted or 0)


def record_task_event(
    task_id: str,
    *,
    project_id: Optional[str],
    event_type: str,
    summary: str,
    stage_key: Optional[str] = None,
    status: Optional[str] = None,
    detail: Optional[dict[str, Any]] = None,
    owner_id: Optional[str] = None,
    created_by: Optional[str] = None,
) -> str:
    db = get_db_session()
    try:
        event_id = generate_id()
        db.add(
            UnpackTaskEvent(
                id=event_id,
                task_id=task_id,
                project_id=str(project_id or "").strip() or None,
                event_type=str(event_type or "").strip() or "event",
                stage_key=str(stage_key or "").strip() or None,
                status=str(status or "").strip() or None,
                summary=str(summary or "").strip() or event_type,
                detail_json=json.dumps(detail, ensure_ascii=False) if detail else None,
                owner_id=str(owner_id or "").strip() or None,
                created_by=str(created_by or "").strip() or None,
            )
        )
        db.flush()
        _trim_task_timeline_events(db, task_id)
        db.commit()
        return event_id
    finally:
        db.close()


def list_task_events(task_id: str, *, limit: int = 200) -> dict[str, Any]:
    db = get_db_session()
    try:
        total = (
            db.query(UnpackTaskEvent)
            .filter(UnpackTaskEvent.task_id == task_id)
            .count()
        )
        rows = (
            db.query(UnpackTaskEvent)
            .filter(UnpackTaskEvent.task_id == task_id)
            .order_by(UnpackTaskEvent.created_at.asc())
            .limit(max(1, min(int(limit), 200)))
            .all()
        )
        return {
            "total": total,
            "items": [row.to_dict() for row in rows],
        }
    finally:
        db.close()
