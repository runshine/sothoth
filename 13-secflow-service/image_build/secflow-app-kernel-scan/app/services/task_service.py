from __future__ import annotations

import json
import logging
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.core.config import get_config
from app.core.ids import new_attempt_id, new_stage_run_id, new_task_id
from app.core.time_utils import utc_now_z
from app.db.database import get_database

logger = logging.getLogger(__name__)

PIPELINE_STAGES = {
    "entry_only": ["entry"],
    "audit_only": ["audit"],
    "poc_only": ["poc"],
    "entry_audit_poc": ["entry", "audit", "poc"],
}

TERMINAL_TASK_STATUSES = {"succeeded", "partial_success", "failed", "cancelled"}


class TaskService:
    def create_task(
        self,
        *,
        title: str,
        pipeline_mode: str,
        kernel_dir: str | None = None,
        report_dir: str | None = None,
        device_ip: str | None = None,
        entrylist: str | None = None,
        notes: str | None = None,
        created_by: str = "api",
        entry_threads: int | None = None,
        audit_threads: int | None = None,
        poc_threads: int | None = None,
    ) -> dict:
        task_id = new_task_id()
        now = utc_now_z()
        effective_kernel_dir = (kernel_dir.strip() if kernel_dir else None) or get_config().kernel_dir
        effective_report_dir = report_dir.strip() if report_dir else None

        effective_config: dict = {}
        if entry_threads is not None:
            effective_config["entry_threads"] = entry_threads
        if audit_threads is not None:
            effective_config["audit_threads"] = audit_threads
        if poc_threads is not None:
            effective_config["poc_threads"] = poc_threads
        if effective_report_dir:
            effective_config["report_dir"] = effective_report_dir
        effective_config_json = json.dumps(effective_config, ensure_ascii=False) if effective_config else "{}"

        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                insert into kernel_scan_tasks
                  (task_id, title, pipeline_mode, kernel_dir, devlist_json, status,
                   attempt_count, notes, created_by, created_at, updated_at)
                values (?, ?, ?, ?, ?, 'queued', 0, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    title,
                    pipeline_mode,
                    effective_kernel_dir,
                    entrylist or None,
                    notes,
                    created_by,
                    now,
                    now,
                ),
            )
            attempt_id = self._create_attempt(conn, task_id, 1, effective_config_json=effective_config_json)
            conn.execute(
                "update kernel_scan_tasks set latest_attempt_id = ?, attempt_count = 1 where task_id = ?",
                (attempt_id, task_id),
            )
            conn.commit()

        return {"task_id": task_id, "attempt_id": attempt_id, "status": "queued"}

    def get_task(self, task_id: str) -> dict | None:
        with get_database().connect() as conn:
            row = conn.execute("select * from kernel_scan_tasks where task_id = ?", (task_id,)).fetchone()
        return dict(row) if row else None

    def list_tasks(self, *, page: int = 1, per_page: int = 20) -> tuple[list[dict], int]:
        offset = (page - 1) * per_page
        with get_database().connect() as conn:
            total = conn.execute("select count(*) from kernel_scan_tasks").fetchone()[0]
            rows = conn.execute(
                "select * from kernel_scan_tasks order by created_at desc limit ? offset ?",
                (per_page, offset),
            ).fetchall()
        return [dict(r) for r in rows], total

    def cancel_task(self, task_id: str) -> bool:
        now = utc_now_z()
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("select status from kernel_scan_tasks where task_id = ?", (task_id,)).fetchone()
            if not row or row["status"] not in ("queued", "running"):
                conn.execute("ROLLBACK")
                return False
            conn.execute(
                "update kernel_scan_tasks set status = 'cancel_requested', updated_at = ? where task_id = ?",
                (now, task_id),
            )
            conn.commit()
        return True

    def delete_task(self, task_id: str) -> str:
        """Delete a task and all its attempts/stage runs/events/artifacts.

        Returns:
          - "deleted"   : task removed
          - "not_found" : task does not exist
          - "busy"      : task is still queued/running/cancel_requested — refuse
        """
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "select status from kernel_scan_tasks where task_id = ?", (task_id,)
            ).fetchone()
            if not row:
                conn.execute("ROLLBACK")
                return "not_found"
            if row["status"] not in TERMINAL_TASK_STATUSES:
                conn.execute("ROLLBACK")
                return "busy"
            conn.execute("delete from kernel_scan_tasks where task_id = ?", (task_id,))
            conn.commit()

        state_root = Path(get_config().state_root)
        task_dir = state_root / "tasks" / task_id
        if task_dir.exists():
            try:
                shutil.rmtree(task_dir)
            except OSError as exc:
                logger.warning("failed to remove task state dir %s: %s", task_dir, exc)

        workspace_root = Path(get_config().workspace_root)
        for rel in ("entry", "audit", "poc"):
            task_ws_dir = workspace_root / rel / task_id
            if task_ws_dir.exists():
                try:
                    shutil.rmtree(task_ws_dir)
                except OSError as exc:
                    logger.warning("failed to remove task workspace dir %s: %s", task_ws_dir, exc)
        return "deleted"

    def restart_task(self, task_id: str) -> dict | str:
        """Restart a terminal task by enqueuing a new attempt.

        Returns:
          - dict {task_id, attempt_id, status} on success
          - "not_found" : task does not exist
          - "busy"      : task is not in a terminal state
        """
        now = utc_now_z()
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "select status, attempt_count, latest_attempt_id from kernel_scan_tasks where task_id = ?",
                (task_id,),
            ).fetchone()
            if not row:
                conn.execute("ROLLBACK")
                return "not_found"
            if row["status"] not in TERMINAL_TASK_STATUSES:
                conn.execute("ROLLBACK")
                return "busy"

            orphan = conn.execute(
                """
                select attempt_id from kernel_scan_attempts
                where task_id = ?
                  and status in ('queued','claimed','running','cancel_requested')
                limit 1
                """,
                (task_id,),
            ).fetchone()
            if orphan:
                conn.execute("ROLLBACK")
                return "busy"

            effective_config_json = "{}"
            if row["latest_attempt_id"]:
                prev = conn.execute(
                    "select effective_config_json from kernel_scan_attempts where attempt_id = ?",
                    (row["latest_attempt_id"],),
                ).fetchone()
                if prev and prev["effective_config_json"]:
                    effective_config_json = prev["effective_config_json"]

            next_no = (row["attempt_count"] or 0) + 1
            attempt_id = self._create_attempt(
                conn, task_id, next_no, effective_config_json=effective_config_json
            )
            conn.execute(
                """
                update kernel_scan_tasks
                set status = 'queued',
                    current_stage = NULL,
                    latest_attempt_id = ?,
                    attempt_count = ?,
                    started_at = NULL,
                    finished_at = NULL,
                    message = NULL,
                    updated_at = ?
                where task_id = ?
                """,
                (attempt_id, next_no, now, task_id),
            )
            conn.commit()
        return {"task_id": task_id, "attempt_id": attempt_id, "status": "queued"}

    def claim_next_attempt(self, worker_id: str) -> str | None:
        now = utc_now_z()
        lease = self._future_time(get_config().execution.lease_duration_seconds)
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                select a.attempt_id, a.task_id
                from kernel_scan_attempts a
                join kernel_scan_tasks t on t.task_id = a.task_id
                where a.status = 'queued' and t.status = 'queued'
                order by a.created_at asc
                limit 1
                """,
            ).fetchone()
            if not row:
                conn.execute("ROLLBACK")
                return None
            attempt_id = row["attempt_id"]
            task_id = row["task_id"]
            conn.execute(
                """
                update kernel_scan_attempts
                set status = 'claimed', worker_id = ?, claimed_at = ?, heartbeat_at = ?,
                    lease_expires_at = ?, updated_at = ?
                where attempt_id = ?
                """,
                (worker_id, now, now, lease, now, attempt_id),
            )
            conn.execute(
                "update kernel_scan_tasks set status = 'running', updated_at = ?, started_at = coalesce(started_at, ?) where task_id = ?",
                (now, now, task_id),
            )
            conn.commit()
        return attempt_id

    def recover_expired_attempts(self) -> None:
        now = utc_now_z()
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                """
                select attempt_id, task_id from kernel_scan_attempts
                where status in ('claimed', 'running') and lease_expires_at < ?
                """,
                (now,),
            ).fetchall()
            for row in rows:
                conn.execute(
                    "update kernel_scan_attempts set status = 'lost', updated_at = ?, failure_reason = 'lease expired' where attempt_id = ?",
                    (now, row["attempt_id"]),
                )
                conn.execute(
                    "update kernel_scan_tasks set status = 'failed', updated_at = ?, message = 'attempt lost (lease expired)' where task_id = ? and status = 'running'",
                    (now, row["task_id"]),
                )
            conn.commit()

    def get_attempt_context(self, attempt_id: str) -> dict | None:
        with get_database().connect() as conn:
            row = conn.execute(
                """
                select a.attempt_id, a.task_id, a.attempt_no, a.effective_config_json,
                       t.pipeline_mode, t.kernel_dir, t.devlist_json, t.status as task_status
                from kernel_scan_attempts a
                join kernel_scan_tasks t on t.task_id = a.task_id
                where a.attempt_id = ?
                """,
                (attempt_id,),
            ).fetchone()
        if not row:
            return None
        return dict(row)

    def _create_attempt(self, conn, task_id: str, attempt_no: int, *, effective_config_json: str = "{}") -> str:
        attempt_id = new_attempt_id()
        now = utc_now_z()
        conn.execute(
            """
            insert into kernel_scan_attempts
              (attempt_id, task_id, attempt_no, status, created_at, updated_at, effective_config_json)
            values (?, ?, ?, 'queued', ?, ?, ?)
            """,
            (attempt_id, task_id, attempt_no, now, now, effective_config_json),
        )
        stages = PIPELINE_STAGES.get(
            conn.execute("select pipeline_mode from kernel_scan_tasks where task_id = ?", (task_id,)).fetchone()["pipeline_mode"],
            ["entry", "audit", "poc"],
        )
        for stage_name in stages:
            conn.execute(
                """
                insert into kernel_scan_stage_runs
                  (stage_run_id, attempt_id, stage_name, status, created_at, updated_at)
                values (?, ?, ?, 'pending', ?, ?)
                """,
                (new_stage_run_id(), attempt_id, stage_name, now, now),
            )
        return attempt_id

    @staticmethod
    def _future_time(seconds: int) -> str:
        value = datetime.now(timezone.utc) + timedelta(seconds=seconds)
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")


_task_service: TaskService | None = None


def get_task_service() -> TaskService:
    global _task_service
    if _task_service is None:
        _task_service = TaskService()
    return _task_service
