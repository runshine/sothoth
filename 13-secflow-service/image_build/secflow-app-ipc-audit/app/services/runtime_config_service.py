from __future__ import annotations

import json
from typing import Any

from app.core.config import get_config
from app.core.time_utils import utc_now_z
from app.db.database import get_database
from app.schemas import RuntimeConfigResponse

MAX_PARALLEL_TASKS_KEY = "max_parallel_tasks"


class RuntimeConfigService:
    def get_config(self) -> RuntimeConfigResponse:
        value, updated_at, updated_by = self._read_max_parallel_tasks()
        return RuntimeConfigResponse(
            max_parallel_tasks=value,
            default_max_parallel_tasks=self.default_max_parallel_tasks(),
            active_attempts=self._active_attempt_count(),
            updated_at=updated_at,
            updated_by=updated_by,
        )

    def get_max_parallel_tasks(self) -> int:
        value, _, _ = self._read_max_parallel_tasks()
        return value

    def update_max_parallel_tasks(self, value: int, *, updated_by: str) -> RuntimeConfigResponse:
        normalized = max(int(value), 1)
        now = utc_now_z()
        database = get_database()
        self._ensure_table()
        with database.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if database.backend == "mysql":
                conn.execute(
                    """
                    insert into ipc_audit_runtime_config (
                      config_key, config_value_json, updated_at, updated_by
                    ) values (?, ?, ?, ?)
                    on duplicate key update
                      config_value_json = values(config_value_json),
                      updated_at = values(updated_at),
                      updated_by = values(updated_by)
                    """,
                    (MAX_PARALLEL_TASKS_KEY, json.dumps(normalized), now, updated_by or "anonymous"),
                )
            else:
                conn.execute(
                    """
                    insert into ipc_audit_runtime_config (
                      config_key, config_value_json, updated_at, updated_by
                    ) values (?, ?, ?, ?)
                    on conflict(config_key) do update set
                      config_value_json = excluded.config_value_json,
                      updated_at = excluded.updated_at,
                      updated_by = excluded.updated_by
                    """,
                    (MAX_PARALLEL_TASKS_KEY, json.dumps(normalized), now, updated_by or "anonymous"),
                )
            conn.commit()
        self._notify_scheduler_config_changed()
        return self.get_config()

    @staticmethod
    def default_max_parallel_tasks() -> int:
        return max(int(get_config().execution.max_parallel_tasks), 1)

    def _read_max_parallel_tasks(self) -> tuple[int, str | None, str | None]:
        self._ensure_table()
        with get_database().connect() as conn:
            row = conn.execute(
                """
                select config_value_json, updated_at, updated_by
                from ipc_audit_runtime_config
                where config_key = ?
                """,
                (MAX_PARALLEL_TASKS_KEY,),
            ).fetchone()
        if row is None:
            return self.default_max_parallel_tasks(), None, None
        return (
            self._parse_positive_int(row["config_value_json"], self.default_max_parallel_tasks()),
            row["updated_at"],
            row["updated_by"],
        )

    @staticmethod
    def _ensure_table() -> None:
        database = get_database()
        with database.connect() as conn:
            if database.backend == "mysql":
                conn.execute(
                    """
                    create table if not exists ipc_audit_runtime_config (
                      config_key varchar(128) primary key,
                      config_value_json longtext not null,
                      updated_at varchar(64) not null,
                      updated_by varchar(128) not null
                    )
                    """
                )
            else:
                conn.execute(
                    """
                    create table if not exists ipc_audit_runtime_config (
                      config_key text primary key,
                      config_value_json text not null,
                      updated_at text not null,
                      updated_by text not null
                    )
                    """
                )

    @staticmethod
    def _parse_positive_int(value: Any, fallback: int) -> int:
        try:
            parsed = json.loads(str(value))
            number = int(parsed)
        except Exception:
            return fallback
        return number if number >= 1 else fallback

    @staticmethod
    def _active_attempt_count() -> int:
        from app.workers.scheduler import get_scheduler_service

        return get_scheduler_service().active_attempt_count

    @staticmethod
    def _notify_scheduler_config_changed() -> None:
        from app.workers.scheduler import get_scheduler_service

        get_scheduler_service().notify_config_changed()


_runtime_config_service: RuntimeConfigService | None = None


def get_runtime_config_service() -> RuntimeConfigService:
    global _runtime_config_service
    if _runtime_config_service is None:
        _runtime_config_service = RuntimeConfigService()
    return _runtime_config_service
