from __future__ import annotations

import json
from typing import Any

from app.core.ids import new_event_id
from app.core.time_utils import utc_now_z
from app.db.database import DatabaseConnection, DatabaseRow, get_database
from app.schemas import EventPageResponse, EventResponse


class EventService:
    def append_event(
        self,
        conn: DatabaseConnection,
        *,
        task_id: str,
        attempt_id: str | None,
        stage_name: str | None,
        event_type: str,
        level: str,
        message: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        now = utc_now_z()
        conn.execute(
            """
            insert into ipc_audit_task_events (
              event_id, task_id, attempt_id, stage_name, event_type,
              level, message, payload_json, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_event_id(),
                task_id,
                attempt_id,
                stage_name,
                event_type,
                level,
                message,
                json.dumps(payload or {}, ensure_ascii=False),
                now,
            ),
        )

    def list_events(
        self,
        *,
        task_id: str,
        attempt_id: str | None,
        cursor: int | None,
        limit: int,
    ) -> EventPageResponse:
        sql = """
            select event_seq, event_id, task_id, attempt_id, stage_name, event_type, level, message, payload_json, created_at
            from ipc_audit_task_events
            where task_id = ?
        """
        params: list[object] = [task_id]
        if attempt_id:
            sql += " and attempt_id = ?"
            params.append(attempt_id)
        if cursor is not None:
            sql += " and event_seq > ?"
            params.append(cursor)
        sql += " order by event_seq asc limit ?"
        params.append(limit)
        with get_database().connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        items = [self._row_to_model(row) for row in rows]
        next_cursor = items[-1].event_seq if items else cursor
        return EventPageResponse(items=items, next_cursor=next_cursor)

    @staticmethod
    def _row_to_model(row: DatabaseRow) -> EventResponse:
        return EventResponse(
            event_seq=row["event_seq"],
            event_id=row["event_id"],
            task_id=row["task_id"],
            attempt_id=row["attempt_id"],
            stage_name=row["stage_name"],
            event_type=row["event_type"],
            level=row["level"],
            message=row["message"],
            payload=json.loads(row["payload_json"] or "{}"),
            created_at=row["created_at"],
        )


_event_service: EventService | None = None


def get_event_service() -> EventService:
    global _event_service
    if _event_service is None:
        _event_service = EventService()
    return _event_service
