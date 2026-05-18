from __future__ import annotations

import json
import sqlite3

from app.core.ids import new_event_id
from app.core.time_utils import utc_now_z
from app.db.database import get_database


class EventService:
    def append_event(
        self,
        conn: sqlite3.Connection,
        *,
        task_id: str,
        attempt_id: str | None,
        stage_name: str | None,
        event_type: str,
        level: str,
        message: str,
        payload: dict | None = None,
    ) -> str:
        event_id = new_event_id()
        conn.execute(
            """
            insert into kernel_scan_events
              (event_id, task_id, attempt_id, stage_name, event_type, level, message, payload_json, created_at)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                task_id,
                attempt_id,
                stage_name,
                event_type,
                level,
                message,
                json.dumps(payload or {}, ensure_ascii=False),
                utc_now_z(),
            ),
        )
        return event_id

    def list_events(self, task_id: str, *, after_seq: int = 0, limit: int = 100) -> list[dict]:
        with get_database().connect() as conn:
            rows = conn.execute(
                """
                select event_seq, event_id, task_id, attempt_id, stage_name,
                       event_type, level, message, payload_json, created_at
                from kernel_scan_events
                where task_id = ? and event_seq > ?
                order by event_seq asc
                limit ?
                """,
                (task_id, after_seq, limit),
            ).fetchall()
        return [dict(r) for r in rows]


_event_service: EventService | None = None


def get_event_service() -> EventService:
    global _event_service
    if _event_service is None:
        _event_service = EventService()
    return _event_service
