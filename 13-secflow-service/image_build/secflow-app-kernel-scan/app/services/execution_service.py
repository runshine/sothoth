from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

from app.core.config import get_config
from app.core.time_utils import utc_now_z
from app.db.database import get_database
from app.services.event_service import get_event_service
from app.services.task_service import PIPELINE_STAGES
from app.workers.runner import StageContext, StageExecutionResult, StageHooks
from app.workers.stage_audit import run_audit_stage
from app.workers.stage_entry import run_entry_stage
from app.workers.stage_poc import run_poc_stage

logger = logging.getLogger(__name__)


class ExecutionService:
    def run_attempt(self, attempt_id: str) -> None:
        context = self._load_context(attempt_id)
        if not context:
            logger.error("attempt not found: %s", attempt_id)
            return

        task_id = context["task_id"]
        pipeline_mode = context["pipeline_mode"]
        kernel_dir = context["kernel_dir"]
        stages = PIPELINE_STAGES.get(pipeline_mode, [])

        try:
            entry_results: list[dict] | None = None

            if "entry" in stages:
                entry_result = self._run_stage(context, "entry")
                if entry_result.status == "cancelled":
                    raise _CancelledError()
                if entry_result.status != "succeeded":
                    raise _StageFailedError("entry", entry_result.message)
                if entry_result.output_path and entry_result.output_path.exists():
                    data = json.loads(entry_result.output_path.read_text(encoding="utf-8"))
                    entry_results = data.get("entries", [])

            if self._is_cancel_requested(task_id, attempt_id):
                raise _CancelledError()

            if "audit" in stages:
                entrylist_path_str = (context.get("devlist_json") or "").strip() or None
                audit_result = self._run_stage(
                    context, "audit",
                    entry_results=entry_results,
                    entrylist_path=entrylist_path_str,
                )
                if audit_result.status == "cancelled":
                    raise _CancelledError()
                if audit_result.status != "succeeded":
                    raise _StageFailedError("audit", audit_result.message)

            if self._is_cancel_requested(task_id, attempt_id):
                raise _CancelledError()

            if "poc" in stages:
                poc_result = self._run_stage(context, "poc")
                if poc_result.status == "cancelled":
                    raise _CancelledError()
                if poc_result.status != "succeeded":
                    self._complete_attempt(task_id, attempt_id, "partial_success", poc_result.message)
                    return

            self._complete_attempt(task_id, attempt_id, "succeeded", "task completed")

        except _CancelledError:
            self._cancel_attempt(task_id, attempt_id)
        except _StageFailedError as exc:
            logger.warning("attempt %s stage %s failed: %s", attempt_id, exc.stage_name, exc.message)
            self._fail_attempt(task_id, attempt_id, exc.message)
        except Exception as exc:
            logger.exception("attempt %s failed: %s", attempt_id, exc)
            self._fail_attempt(task_id, attempt_id, str(exc))

    def _run_stage(
        self,
        context: dict,
        stage_name: str,
        *,
        entry_results: list[dict] | None = None,
        entrylist_path: str | None = None,
    ) -> StageExecutionResult:
        task_id = context["task_id"]
        attempt_id = context["attempt_id"]
        self._set_stage_running(task_id, attempt_id, stage_name)

        stage_context = self._build_stage_context(context, stage_name)
        hooks = StageHooks(
            heartbeat=lambda: self._heartbeat(attempt_id),
            is_cancel_requested=lambda: self._is_cancel_requested(task_id, attempt_id),
        )
        hooks.heartbeat()

        stop_event = threading.Event()
        pump = threading.Thread(
            target=self._heartbeat_pump,
            args=(attempt_id, stop_event),
            name=f"heartbeat-pump-{attempt_id}",
            daemon=True,
        )
        pump.start()
        try:
            if stage_name == "entry":
                result = run_entry_stage(stage_context, hooks)
            elif stage_name == "audit":
                result = run_audit_stage(
                    stage_context, hooks,
                    entry_results=entry_results,
                    entrylist_path=Path(entrylist_path) if entrylist_path else None,
                )
            else:
                result = run_poc_stage(stage_context, hooks)
        finally:
            stop_event.set()
            pump.join(timeout=5.0)

        self._persist_stage_result(task_id, attempt_id, stage_name, result)
        return result

    def _heartbeat_pump(self, attempt_id: str, stop_event: threading.Event) -> None:
        interval = max(float(get_config().execution.heartbeat_interval_seconds), 1.0)
        while not stop_event.wait(interval):
            try:
                self._heartbeat(attempt_id)
            except Exception:
                logger.exception("heartbeat pump failed for attempt %s", attempt_id)

    def _build_stage_context(self, context: dict, stage_name: str) -> StageContext:
        task_id = context["task_id"]
        attempt_id = context["attempt_id"]
        cfg = get_config()
        state_root = Path(cfg.state_root)
        attempt_root = state_root / "tasks" / task_id / "attempts" / attempt_id
        attempt_root.mkdir(parents=True, exist_ok=True)
        logs_dir = attempt_root / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        artifacts_dir = attempt_root / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        return StageContext(
            task_id=task_id,
            attempt_id=attempt_id,
            stage_name=stage_name,
            pipeline_mode=context["pipeline_mode"],
            kernel_dir=context["kernel_dir"],
            attempt_root=attempt_root,
            logs_dir=logs_dir,
            artifacts_dir=artifacts_dir,
            effective_config=json.loads(context.get("effective_config_json") or "{}"),
        )

    def _load_context(self, attempt_id: str) -> dict | None:
        from app.services.task_service import get_task_service
        return get_task_service().get_attempt_context(attempt_id)

    def _set_stage_running(self, task_id: str, attempt_id: str, stage_name: str) -> None:
        now = utc_now_z()
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "update kernel_scan_tasks set current_stage = ?, updated_at = ? where task_id = ?",
                (stage_name, now, task_id),
            )
            conn.execute(
                "update kernel_scan_attempts set status = 'running', started_at = coalesce(started_at, ?), updated_at = ? where attempt_id = ?",
                (now, now, attempt_id),
            )
            conn.execute(
                "update kernel_scan_stage_runs set status = 'running', started_at = ?, updated_at = ? where attempt_id = ? and stage_name = ?",
                (now, now, attempt_id, stage_name),
            )
            get_event_service().append_event(
                conn, task_id=task_id, attempt_id=attempt_id, stage_name=stage_name,
                event_type="stage.started", level="info", message=f"{stage_name} stage started",
            )
            conn.commit()

    def _persist_stage_result(self, task_id: str, attempt_id: str, stage_name: str, result: StageExecutionResult) -> None:
        now = utc_now_z()
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                update kernel_scan_stage_runs
                set status = ?, return_code = ?, finished_at = ?, updated_at = ?,
                    message = ?, metadata_json = ?
                where attempt_id = ? and stage_name = ?
                """,
                (
                    result.status, result.return_code, now, now,
                    result.message, json.dumps(result.metadata, ensure_ascii=False),
                    attempt_id, stage_name,
                ),
            )
            get_event_service().append_event(
                conn, task_id=task_id, attempt_id=attempt_id, stage_name=stage_name,
                event_type="stage.completed", level="info" if result.status == "succeeded" else "error",
                message=result.message, payload=result.metadata,
            )
            conn.commit()

    def _complete_attempt(self, task_id: str, attempt_id: str, status: str, message: str) -> None:
        now = utc_now_z()
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "update kernel_scan_attempts set status = ?, finished_at = ?, updated_at = ? where attempt_id = ?",
                (status, now, now, attempt_id),
            )
            conn.execute(
                "update kernel_scan_tasks set status = ?, current_stage = null, finished_at = ?, updated_at = ?, message = ? where task_id = ?",
                (status, now, now, message, task_id),
            )
            get_event_service().append_event(
                conn, task_id=task_id, attempt_id=attempt_id, stage_name=None,
                event_type="task.completed", level="info", message=message,
            )
            conn.commit()

    def _fail_attempt(self, task_id: str, attempt_id: str, message: str) -> None:
        now = utc_now_z()
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "update kernel_scan_attempts set status = 'failed', failure_reason = ?, finished_at = ?, updated_at = ? where attempt_id = ?",
                (message, now, now, attempt_id),
            )
            conn.execute(
                "update kernel_scan_tasks set status = 'failed', current_stage = null, finished_at = ?, updated_at = ?, message = ? where task_id = ?",
                (now, now, message, task_id),
            )
            get_event_service().append_event(
                conn, task_id=task_id, attempt_id=attempt_id, stage_name=None,
                event_type="task.failed", level="error", message=message,
            )
            conn.commit()

    def _cancel_attempt(self, task_id: str, attempt_id: str) -> None:
        now = utc_now_z()
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "update kernel_scan_attempts set status = 'cancelled', finished_at = ?, updated_at = ? where attempt_id = ?",
                (now, now, attempt_id),
            )
            conn.execute(
                "update kernel_scan_tasks set status = 'cancelled', current_stage = null, finished_at = ?, updated_at = ?, message = 'cancelled' where task_id = ?",
                (now, now, task_id),
            )
            get_event_service().append_event(
                conn, task_id=task_id, attempt_id=attempt_id, stage_name=None,
                event_type="task.cancelled", level="warning", message="task cancelled",
            )
            conn.commit()

    def _heartbeat(self, attempt_id: str) -> None:
        now = utc_now_z()
        from app.services.task_service import TaskService
        lease = TaskService._future_time(get_config().execution.lease_duration_seconds)
        with get_database().connect() as conn:
            conn.execute(
                "update kernel_scan_attempts set heartbeat_at = ?, lease_expires_at = ?, updated_at = ? where attempt_id = ?",
                (now, lease, now, attempt_id),
            )

    def _is_cancel_requested(self, task_id: str, attempt_id: str) -> bool:
        with get_database().connect() as conn:
            row = conn.execute(
                "select status from kernel_scan_tasks where task_id = ?", (task_id,)
            ).fetchone()
        return row is not None and row["status"] == "cancel_requested"


class _CancelledError(Exception):
    pass


class _StageFailedError(Exception):
    def __init__(self, stage_name: str, message: str) -> None:
        super().__init__(message)
        self.stage_name = stage_name
        self.message = message


_execution_service: ExecutionService | None = None


def get_execution_service() -> ExecutionService:
    global _execution_service
    if _execution_service is None:
        _execution_service = ExecutionService()
    return _execution_service
