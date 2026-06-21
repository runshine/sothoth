from __future__ import annotations

import asyncio
import json
import shutil
import time
import uuid
from contextlib import suppress
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from app.exception import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.model import BinarySecurityTask, BinarySecurityTaskOperation
from app.service import task_manager as task_manager_module
from . import shared as task_shared

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class TaskOperationServiceMixin:
    def _capture_blocking_operation_task_snapshot(
        self: TaskManager,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
    ) -> None:
        if not self._operation_blocks_runtime_resume(operation):
            return
        payload = dict(getattr(operation, "request_payload", None) or {})
        if isinstance(payload.get("task_state_snapshot"), dict):
            return
        payload["task_state_snapshot"] = {
            "status": str(getattr(task, "status", "") or "").strip() or None,
            "current_stage": str(getattr(task, "current_stage", "") or "").strip() or None,
            "runtime_phase": self._task_runtime_phase(task),
            "last_error": str(getattr(task, "last_error", "") or "").strip() or None,
            "finished_at": task_shared._isoformat_or_none(getattr(task, "finished_at", None)),
            "execution_mode": str(getattr(task, "execution_mode", "") or "").strip() or None,
            "target_stage_name": str(getattr(task, "target_stage_name", "") or "").strip() or None,
        }
        operation.request_payload = payload

    def _restore_failed_blocking_operation_task_snapshot(
        self: TaskManager,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
    ) -> None:
        from app.service import task_manager as task_manager_module

        if not self._operation_blocks_runtime_resume(operation):
            return
        payload = dict(getattr(operation, "request_payload", None) or {})
        snapshot = dict(payload.get("task_state_snapshot") or {})
        if not snapshot:
            return
        previous_status = str(snapshot.get("status") or "").strip() or None
        if previous_status:
            task.status = previous_status
        task.current_stage = str(snapshot.get("current_stage") or getattr(task, "current_stage", "") or "").strip() or None
        self._set_task_runtime_phase(task, str(snapshot.get("runtime_phase") or self._task_runtime_phase(task) or "").strip())
        task.last_error = str(snapshot.get("last_error") or "").strip() or str(getattr(operation, "error_message", "") or "").strip() or None
        task.execution_mode = str(snapshot.get("execution_mode") or "").strip() or None
        task.target_stage_name = str(snapshot.get("target_stage_name") or "").strip() or None
        if str(previous_status or "").strip().lower() in task_manager_module.TASK_TERMINAL_STATUSES:
            task.finished_at = task.finished_at or task_manager_module._now()

    @staticmethod
    def _commit_or_rollback(db: Session) -> None:
        try:
            db.commit()
        except Exception:
            db.rollback()
            raise

    @staticmethod
    def _cancel_target_observation_status(payload: dict[str, Any] | None) -> str:
        status = str((payload or {}).get("status") or "").strip().lower()
        if status in {"succeeded", "passed", "completed", "complete", "done"}:
            return "success"
        if status in {"success", "failed", "cancelled", "missing", "downstream_missing", "running", "pending", "queued", "dispatching"}:
            return status
        return "unknown"

    def _is_old_child_already_terminal_and_superseded(
        self: TaskManager,
        item: task_manager_module.BinarySecurityStageItem,
        downstream_task_id: str | None,
    ) -> bool:
        task_id = str(downstream_task_id or "").strip()
        if not task_id:
            return False
        replacement_state = self._replacement_in_progress_state(item)
        old_task_id = str(replacement_state.get("old_downstream_task_id") or "").strip()
        if old_task_id != task_id:
            return False
        result = self._load_stage_item_result_payload(item)
        sync_observation = dict(result.get("sync_observation") or {})
        superseded_task_id = str(
            sync_observation.get("superseded_downstream_task_id")
            or sync_observation.get("old_downstream_task_id")
            or ""
        ).strip()
        if superseded_task_id != task_id:
            return False
        terminal_status = self._normalize_downstream_status(
            sync_observation.get("mapped_status")
            or sync_observation.get("downstream_status")
            or sync_observation.get("status_raw")
        )
        verification_status = str(sync_observation.get("verification_status") or "").strip().lower()
        if terminal_status in {"success", "failed", "cancelled", "downstream_missing"} and verification_status in {"succeeded", "deleted", "absent"}:
            return True
        if verification_status in {"succeeded", "deleted", "absent"} and not replacement_state.get("replacement_in_progress"):
            return True
        return False

    def _collect_cancel_targets(self: TaskManager, db: Session, task: BinarySecurityTask) -> list[dict[str, Any]]:
        targets: list[dict[str, Any]] = []
        stage_items = db.query(task_manager_module.BinarySecurityStageItem).filter(
            task_manager_module.BinarySecurityStageItem.task_id == task.id
        ).order_by(
            task_manager_module.BinarySecurityStageItem.created_at.asc(),
            task_manager_module.BinarySecurityStageItem.id.asc(),
        ).all()
        active_child_keys = {
            (
                str(item.downstream_service or "").strip(),
                str(item.downstream_task_id or "").strip(),
            )
            for item in stage_items
            if str(item.downstream_service or "").strip() and str(item.downstream_task_id or "").strip()
        }
        for item in stage_items:
            normalized_status = self._normalize_item_status(item.status)
            if normalized_status in {"pending", "queued", "running", "dispatching"}:
                targets.append(
                    {
                        "target_type": "stage_item",
                        "stage_name": item.stage_name,
                        "item_id": item.id,
                        "item_key": item.item_key,
                        "blocking": True,
                    }
                )
            downstream_service = str(item.downstream_service or "").strip()
            downstream_task_id = str(item.downstream_task_id or "").strip()
            if downstream_service and downstream_task_id:
                targets.append(
                    {
                        "target_type": "downstream_task",
                        "stage_name": item.stage_name,
                        "item_id": item.id,
                        "item_key": item.item_key,
                        "project_id": task.project_id,
                        "downstream_service": downstream_service,
                        "downstream_task_id": downstream_task_id,
                        "blocking": True,
                    }
                )
            replacement_state = self._replacement_in_progress_state(item)
            old_downstream_task_id = str(replacement_state.get("old_downstream_task_id") or "").strip()
            if (
                downstream_service
                and old_downstream_task_id
                and not self._is_old_child_already_terminal_and_superseded(item, old_downstream_task_id)
            ):
                targets.append(
                    {
                        "target_type": "downstream_task",
                        "stage_name": item.stage_name,
                        "item_id": item.id,
                        "item_key": item.item_key,
                        "project_id": task.project_id,
                        "downstream_service": downstream_service,
                        "downstream_task_id": old_downstream_task_id,
                        "blocking": True,
                        "superseded": True,
                    }
                )
        orphan_refs = []
        try:
            orphan_refs = self._discover_parent_linked_downstream_refs(db, task)
        except Exception:
            orphan_refs = []
        for ref in orphan_refs:
            key = (
                str(ref.get("service") or "").strip(),
                str(ref.get("task_id") or "").strip(),
            )
            if not all(key) or key in active_child_keys:
                continue
            continue
        deduped: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str, str]] = set()
        for target in targets:
            dedupe_key = (
                str(target.get("target_type") or "").strip(),
                str(target.get("stage_name") or "").strip(),
                str(target.get("item_id") or "").strip(),
                str(target.get("downstream_task_id") or "").strip(),
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            deduped.append(target)
        return deduped

    @staticmethod
    def _cancel_verify_timeout_seconds() -> int:
        return 30

    def _store_cancel_targets(
        self: TaskManager,
        operation: BinarySecurityTaskOperation,
        targets: list[dict[str, Any]],
        *,
        workspace_root: str | None = None,
    ) -> dict[str, Any]:
        del workspace_root
        return self._update_operation_result_payload(
            operation,
            {"cancel_targets": [dict(target) for target in targets if isinstance(target, dict)]},
        )

    @staticmethod
    def _cancel_target_display(target: dict[str, Any]) -> str:
        service = str(target.get("downstream_service") or "").strip()
        task_id = str(target.get("downstream_task_id") or "").strip()
        stage_name = str(target.get("stage_name") or "").strip()
        return ":".join(part for part in (service, task_id or stage_name) if part)

    @staticmethod
    def _cancel_target_is_terminal(status: str | None) -> bool:
        return str(status or "").strip().lower() in {
            "success",
            "failed",
            "cancelled",
            "missing",
            "downstream_missing",
            "passed",
            "completed",
            "complete",
            "done",
        }

    async def _request_local_worker_cancel(
        self: TaskManager,
        task_id: str,
        *,
        wait_for_runner: bool,
    ) -> None:
        async with self._worker_lock:
            handle = self._workers.get(task_id)
        if handle is None or handle.done():
            return
        current_task = asyncio.current_task()
        handle.cancel_requested = True
        if handle.heartbeat_task is not None and handle.heartbeat_task is not current_task and not handle.heartbeat_task.done():
            handle.heartbeat_task.cancel()
        if handle.runner_task is not current_task and not handle.runner_task.done():
            handle.runner_task.cancel()
        tasks: list[asyncio.Task] = []
        if wait_for_runner and handle.runner_task is not current_task:
            tasks.append(handle.runner_task)
        if handle.heartbeat_task is not None and handle.heartbeat_task is not current_task:
            tasks.append(handle.heartbeat_task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _find_retry_created_child_payload(
        self: TaskManager,
        task: BinarySecurityTask,
        item,
    ) -> dict[str, Any] | None:
        task_id = str(getattr(item, "downstream_task_id", "") or "").strip()
        if not task_id:
            return None
        try:
            payload = await self._fetch_downstream_task_payload(task, item, self._service_token())
        except Exception:
            return None
        if not isinstance(payload, dict):
            return None
        observed_task_id = str(payload.get("task_id") or payload.get("id") or "").strip()
        if observed_task_id and observed_task_id != task_id:
            return payload
        mapped_status = self._map_downstream_status(str(payload.get("status") or ""))
        if mapped_status in {"pending", "queued", "dispatching", "running", "success"}:
            return payload
        return None

    def _latest_cancel_operation(self: TaskManager, db: Session, task_id: str):
        from app.service import task_manager as task_manager_module

        return (
            db.query(task_manager_module.BinarySecurityTaskOperation)
            .filter(
                task_manager_module.BinarySecurityTaskOperation.task_id == task_id,
                task_manager_module.BinarySecurityTaskOperation.operation_type == task_manager_module.TASK_ACTION_CANCEL,
            )
            .order_by(
                task_manager_module.BinarySecurityTaskOperation.created_at.desc(),
                task_manager_module.BinarySecurityTaskOperation.id.desc(),
            )
            .first()
        )

    def _create_task_operation(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        operation_type: str,
        target_stage: str | None,
        requested_by: str | None,
        request_source: str = "api",
        request_payload: dict[str, Any] | None = None,
    ) -> BinarySecurityTaskOperation:
        from app.service import task_manager as task_manager_module

        active_operation = self._active_operation(db, task.id)
        if active_operation is not None:
            active_operation_type = str(active_operation.operation_type or "").strip()
            if (
                active_operation_type == task_manager_module.TASK_ACTION_DELETE
                and str(operation_type or "").strip() != task_manager_module.TASK_ACTION_DELETE
            ):
                raise ValidationError("任务删除已受理，后台正在清理任务及下游资源，暂不支持其它操作")
            raise ValidationError(f"当前任务已有进行中的操作: {active_operation.operation_type}")
        operation = task_manager_module.BinarySecurityTaskOperation(
            id=f"op_{uuid.uuid4().hex[:24]}",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=operation_type,
            target_stage=target_stage,
            requested_by=requested_by,
            request_source=request_source,
            status="accepted",
            operation_token=uuid.uuid4().hex[:32],
            current_step=None,
            created_at=task_manager_module._now(),
            updated_at=task_manager_module._now(),
        )
        self._persist_operation_request_payload(
            operation,
            dict(request_payload or {}),
            workspace_root=task.workspace_root,
        )
        db.add(operation)
        task.current_operation_id = operation.id
        self._record_operation_event(
            db,
            task,
            operation,
            "operation_accepted",
            f"操作已受理: {operation_type}",
            stage_name=target_stage,
            payload={"request_payload": dict(operation.request_payload or {})},
        )
        task_manager_module.observe_control_operation(operation_type, "accepted")
        return operation

    def _queue_task_operation(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        operation_type: str,
        target_stage: str | None,
        requested_by: str | None,
        request_payload: dict[str, Any] | None = None,
        accepted_event_type: str,
        accepted_message: str,
    ) -> BinarySecurityTaskOperation:
        from app.service import task_manager as task_manager_module

        operation = self._create_task_operation(
            db,
            task,
            operation_type=operation_type,
            target_stage=target_stage,
            requested_by=requested_by,
            request_payload=request_payload,
        )
        operation.status = "queued"
        task.current_operation_id = operation.id
        self._record_operation_event(
            db,
            task,
            operation,
            accepted_event_type,
            accepted_message,
            stage_name=target_stage,
            payload={"request_payload": dict(operation.request_payload or {})},
        )
        db.flush()
        db.commit()
        self._enqueue_task(task.id)
        task_manager_module.observe_control_operation(operation.operation_type, "queued")
        return operation

    def _active_cancel_operation(self: TaskManager, db: Session, task_id: str):
        from app.service import task_manager as task_manager_module

        active_operation = self._active_operation(db, task_id)
        if active_operation is not None and str(active_operation.operation_type or "").strip() == task_manager_module.TASK_ACTION_CANCEL:
            return active_operation
        return None

    def _task_has_active_cancel_operation(self: TaskManager, db: Session, task: BinarySecurityTask) -> bool:
        return self._active_cancel_operation(db, task.id) is not None

    def _task_operation_token(self: TaskManager) -> str:
        import uuid

        return uuid.uuid4().hex

    def _task_operation_lock_expires_at(
        self: TaskManager,
        *,
        now_value=None,
        ttl_seconds: int = 60,
    ):
        from app.service import task_manager as task_manager_module

        base = now_value or task_manager_module._now()
        effective_ttl = self._task_operation_lock_ttl_seconds() if int(ttl_seconds) == 60 else max(30, int(ttl_seconds))
        return base + timedelta(seconds=effective_ttl)

    def _raise_task_operation_locked(self: TaskManager, task_id: str) -> None:
        from app.service import task_manager as task_manager_module

        connection = task_manager_module.get_engine().connect()
        try:
            row = connection.execute(
                text(
                    f"SELECT operation_lock_type, operation_lock_owner, operation_lock_expires_at "
                    f"FROM {BinarySecurityTask.__tablename__} WHERE id = :task_id"
                ),
                {"task_id": task_id},
            ).first()
        finally:
            connection.close()
        if row:
            lock_type = str(row[0] or "unknown").strip() or "unknown"
            owner = str(row[1] or "").strip()
            expires_at = row[2]
            owner_suffix = f"，持有实例 {owner}" if owner else ""
            expires_suffix = f"，预计释放时间 {expires_at}" if expires_at else ""
            raise ValidationError(f"当前任务正在执行 {lock_type} 操作{owner_suffix}{expires_suffix}，请稍后重试")
        raise ValidationError("当前任务正被其他操作修改，请稍后重试")

    def _acquire_task_operation_lease(
        self: TaskManager,
        db: Session,
        task_id: str,
        *,
        operation: str,
        ttl_seconds: int = 180,
    ) -> str:
        from app.service import task_manager as task_manager_module

        if not isinstance(db, Session):
            connection_factory = getattr(db, "connection", None)
            if not callable(connection_factory):
                return "test-operation-token"
            connection = connection_factory()
            lock_name = f"secflow_binary_security_task_lock:{task_id}"
            acquired = bool(
                connection.execute(
                    text("SELECT GET_LOCK(:name, :timeout)"),
                    {"name": lock_name, "timeout": 1},
                ).scalar()
            )
            if not acquired:
                raise ValidationError("当前任务正被其他操作修改，请稍后重试")
            return lock_name

        now_value = task_manager_module._now()
        expires_at = self._task_operation_lock_expires_at(now_value=now_value, ttl_seconds=ttl_seconds)
        token = self._task_operation_token()
        with task_manager_module.get_engine().begin() as connection:
            result = connection.execute(
                text(
                    f"""
                    UPDATE {BinarySecurityTask.__tablename__}
                       SET operation_lock_owner = :owner,
                           operation_lock_token = :token,
                           operation_lock_type = :operation,
                           operation_lock_acquired_at = :now_value,
                           operation_lock_heartbeat_at = :now_value,
                           operation_lock_expires_at = :expires_at,
                           updated_at = :now_value
                     WHERE id = :task_id
                       AND (
                            operation_lock_expires_at IS NULL
                            OR operation_lock_expires_at < :now_value
                       )
                    """
                ),
                {
                    "owner": self.instance_id,
                    "token": token,
                    "operation": operation,
                    "now_value": now_value,
                    "expires_at": expires_at,
                    "task_id": task_id,
                },
            )
        if int(getattr(result, "rowcount", 0) or 0) != 1:
            self._raise_task_operation_locked(task_id)
        return token

    def _renew_task_operation_lease(
        self: TaskManager,
        task_id: str,
        *,
        token: str,
        operation: str,
        ttl_seconds: int = 180,
    ) -> bool:
        from app.service import task_manager as task_manager_module

        now_value = task_manager_module._now()
        expires_at = self._task_operation_lock_expires_at(now_value=now_value, ttl_seconds=ttl_seconds)
        with task_manager_module.get_engine().begin() as connection:
            result = connection.execute(
                text(
                    f"""
                    UPDATE {BinarySecurityTask.__tablename__}
                       SET operation_lock_owner = :owner,
                           operation_lock_type = :operation,
                           operation_lock_heartbeat_at = :now_value,
                           operation_lock_expires_at = :expires_at,
                           updated_at = :now_value
                     WHERE id = :task_id
                       AND operation_lock_token = :token
                    """
                ),
                {
                    "owner": self.instance_id,
                    "operation": operation,
                    "now_value": now_value,
                    "expires_at": expires_at,
                    "task_id": task_id,
                    "token": token,
                },
            )
        return int(getattr(result, "rowcount", 0) or 0) == 1

    def _release_task_operation_lease(self: TaskManager, db: Session, task_id: str, *, token: str) -> None:
        from app.service import task_manager as task_manager_module

        if not isinstance(db, Session):
            connection_factory = getattr(db, "connection", None)
            if not callable(connection_factory):
                return
            connection = connection_factory()
            try:
                connection.execute(
                    text("SELECT RELEASE_LOCK(:name)"),
                    {"name": token},
                )
            finally:
                close_fn = getattr(connection, "close", None)
                if callable(close_fn):
                    close_fn()
            return

        now_value = task_manager_module._now()
        with task_manager_module.get_engine().begin() as connection:
            connection.execute(
                text(
                    f"""
                    UPDATE {BinarySecurityTask.__tablename__}
                       SET operation_lock_owner = NULL,
                           operation_lock_token = NULL,
                           operation_lock_type = NULL,
                           operation_lock_acquired_at = NULL,
                           operation_lock_heartbeat_at = NULL,
                           operation_lock_expires_at = NULL,
                           updated_at = :now_value
                     WHERE id = :task_id
                       AND operation_lock_token = :token
                    """
                ),
                {
                    "now_value": now_value,
                    "task_id": task_id,
                    "token": token,
                },
            )

    def _task_operation_lock(
        self: TaskManager,
        db: Session,
        task_id: str,
        *,
        operation: str,
        ttl_seconds: int = 180,
    ):
        from contextlib import contextmanager

        @contextmanager
        def _cm():
            token = self._acquire_task_operation_lease(db, task_id, operation=operation, ttl_seconds=ttl_seconds)
            try:
                yield token
            finally:
                self._release_task_operation_lease(db, task_id, token=token)

        return _cm()

    def _savepoint(self: TaskManager, db: Session):
        from contextlib import contextmanager

        @contextmanager
        def _cm():
            begin_nested = getattr(db, "begin_nested", None)
            if not callable(begin_nested):
                yield None
                return
            nested = begin_nested()
            try:
                yield nested
            except Exception:
                # Preserve the original write failure when the DB connection has
                # already been invalidated and savepoint cleanup cannot run.
                with suppress(Exception):
                    nested.rollback()
                raise

        return _cm()

    def _is_retryable_lock_error(self: TaskManager, exc: BaseException) -> bool:
        current: BaseException | None = exc
        while current is not None:
            if isinstance(current, OperationalError):
                args = getattr(getattr(current, "orig", None), "args", ()) or ()
                code = args[0] if args else None
                message = str(current).lower()
                if code in {1205, 1213}:
                    return True
                if "lock wait timeout" in message or "deadlock found" in message:
                    return True
            current = getattr(current, "__cause__", None) or getattr(current, "orig", None)
        return False

    def _retryable_write_attempts(self: TaskManager, max_retries: int | None = None) -> int:
        retries = 3 if max_retries is None else int(max_retries)
        return max(1, retries)

    def _sleep_after_retryable_lock_error(self: TaskManager, attempt: int) -> None:
        attempt_no = max(1, int(attempt))
        backoff_seconds = {1: 1.0, 2: 3.0, 3: 5.0}.get(attempt_no, 5.0)
        time.sleep(backoff_seconds)

    def _run_sync(self: TaskManager, coro):
        return asyncio.run(coro)

    def _raise_if_restart_cleanup_incomplete(
        self: TaskManager,
        *,
        cleanup_partial_failed: bool,
        remaining_refs: list[dict[str, Any]] | None = None,
        deferred_refs: list[dict[str, Any]] | None = None,
        blocking_refs: list[dict[str, Any]] | None = None,
        context: str,
    ) -> None:
        if not cleanup_partial_failed:
            return
        remaining_count = len([row for row in list(remaining_refs or []) if isinstance(row, dict)])
        deferred_count = len([row for row in list(deferred_refs or []) if isinstance(row, dict)])
        blocking_count = len([row for row in list(blocking_refs or []) if isinstance(row, dict)])
        raise ValidationError(
            f"{context} cleanup left downstream bindings behind; "
            f"remaining_downstream_count={remaining_count} deferred_cleanup_count={deferred_count} "
            f"blocking_cleanup_count={blocking_count}"
        )

    async def _prepare_hard_restart_task(self: TaskManager, db: Session, task: BinarySecurityTask) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        stage_sequence = self._stage_sequence_for_task(task)
        cleanup_snapshot: dict[str, Any] = {
            "requested_at": task_manager_module._isoformat_or_none(task_manager_module._now()),
            "previous_epoch": int(getattr(task, "execution_epoch", 0) or 0),
            "stage_sequence": stage_sequence,
            "downstream_refs": [],
            "cleanup_counts": {},
        }
        self._invalidate_task_execution(task)
        refs, _parent_linked_refs, scan_errors = self._retry_cleanup_refs_for_hard_restart(db, task, stage_sequence)
        cleanup_snapshot["downstream_refs"] = refs
        if scan_errors:
            cleanup_snapshot["service_scan_unavailable"] = [dict(row) for row in scan_errors if isinstance(row, dict)]
        if refs:
            await self._cleanup_downstream_refs(db, task, refs, self._service_token())
        remaining_parent_linked_refs = self._verify_remaining_parent_linked_downstream_refs(db, task, refs)
        if remaining_parent_linked_refs:
            cleanup_snapshot["cleanup_partial_failed"] = True
            cleanup_snapshot["remaining_downstream_refs"] = [dict(row) for row in remaining_parent_linked_refs if isinstance(row, dict)]
            cleanup_snapshot["remaining_downstream_count"] = len(cleanup_snapshot["remaining_downstream_refs"])
        else:
            cleanup_snapshot["cleanup_partial_failed"] = False
            cleanup_snapshot["remaining_downstream_refs"] = []
            cleanup_snapshot["remaining_downstream_count"] = 0
        self._clear_stage_outputs_from(task, stage_sequence[0], mark_stale=False)
        cleanup_snapshot["cleanup_counts"]["archive_jobs_deleted"] = self._delete_archive_children_for_stages(db, task, stage_sequence)
        cleanup_snapshot["cleanup_counts"]["stage_items_deleted"] = self._delete_stage_items_for_stages(db, task.id, stage_sequence)
        cleanup_snapshot["cleanup_counts"]["stage_runs_deleted"] = self._delete_stage_run_rows(db, task.id)
        self._delete_task_event_payload_dirs(task)
        self._delete_workspace_runtime_children(task)
        self._delete_task_summary_file(task)
        cleanup_snapshot["cleanup_counts"]["timeline_events_deleted"] = self._delete_task_timeline_rows(db, task.id)
        cleanup_snapshot["cleanup_counts"]["state_events_deleted"] = self._delete_task_state_event_rows(db, task.id)
        task.cleanup_snapshot = cleanup_snapshot
        self._validate_hard_restart_cleanup(db, task)
        self._raise_if_restart_cleanup_incomplete(
            cleanup_partial_failed=bool(cleanup_snapshot.get("cleanup_partial_failed")),
            remaining_refs=[
                dict(row)
                for row in list(cleanup_snapshot.get("remaining_downstream_refs") or [])
                if isinstance(row, dict)
            ],
            context="full retry hard restart",
        )
        self._reset_task_for_hard_restart(task)
        task.cleanup_snapshot = cleanup_snapshot
        return cleanup_snapshot

    async def _prepare_continue_task(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        target_stage: str,
    ) -> list[str]:
        from app.service import task_manager as task_manager_module

        stage_sequence = self._stage_sequence_for_task(task)
        stage_runs = {
            row.stage_name: row
            for row in db.query(task_manager_module.BinarySecurityStageRun).filter(
                task_manager_module.BinarySecurityStageRun.task_id == task.id,
            ).all()
        }
        target_index = stage_sequence.index(target_stage)
        affected_stages = stage_sequence[target_index:]
        preserve_target_stage_refs = any(
            self._should_preserve_target_stage_downstream_ref(db, task, item)
            for item in self._stage_items(db, task.id, target_stage)
        )
        self._invalidate_task_execution(task)
        db.flush()
        downstream_refs = self._downstream_refs_for_stages(db, task, affected_stages)
        if preserve_target_stage_refs:
            downstream_refs = [
                ref
                for ref in downstream_refs
                if str(ref.get("stage_name") or "").strip() != target_stage
            ]
        if downstream_refs:
            await self._cleanup_downstream_refs(db, task, downstream_refs, self._service_token())
        self._clear_stage_outputs_from(task, target_stage, mark_stale=False)
        self._delete_archive_children_for_stages(db, task, affected_stages)
        self._delete_stage_items_for_stages(
            db,
            task.id,
            [stage_name for stage_name in affected_stages if stage_name != target_stage],
        )
        for stage_name in affected_stages:
            stage_run = stage_runs.get(stage_name)
            if stage_run:
                self._reset_stage_run_for_retry(task, stage_run, increment_retry=False)
        return affected_stages

    async def _prepare_retry_task(self: TaskManager, db: Session, task: BinarySecurityTask) -> list[str]:
        cleanup_snapshot = await self._prepare_hard_restart_task(db, task)
        self._set_retry_plan(
            task,
            {
                **self._retry_plan(task),
                "mode": "retry",
                "cleanup_mode": "hard_reset",
                "cleanup_verification": {
                    "validated": False,
                    "issues": [{"issue": "cleanup_verification_pending"}],
                },
            },
        )
        return list(cleanup_snapshot.get("stage_sequence") or self._stage_sequence_for_task(task))

    def _build_retry_prepare_result(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        target_stage: str,
        phase: str = "prepare",
    ) -> dict[str, Any]:
        plan = self._retry_plan(task)
        retry_item_keys = [str(item_key).strip() for item_key in list(plan.get("retry_item_keys") or []) if str(item_key).strip()]
        item_actions = [dict(row) for row in list(plan.get("item_actions") or []) if isinstance(row, dict)]
        affected_stages = [str(stage).strip() for stage in list(plan.get("affected_stages") or []) if str(stage).strip()]
        validation = self._validate_retry_prepare_state(
            db,
            task,
            target_stage=target_stage,
            retry_item_keys=retry_item_keys,
            item_actions=item_actions,
            affected_stages=affected_stages,
            phase=phase,
        )
        return {
            "target_stage": target_stage,
            "retry_item_keys": retry_item_keys,
            "item_actions": item_actions,
            "affected_stages": affected_stages,
            "cleanup_mode": self._retry_cleanup_mode(task),
            "cleanup_verification": dict((self._retry_plan(task).get("cleanup_verification") or {})),
            "validation": validation,
        }

    async def _operation_verify_retry_cleanup_state(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
    ) -> dict[str, Any]:
        verification = self._build_hard_restart_cleanup_verification(db, task)
        self._set_retry_plan(
            task,
            {
                **self._retry_plan(task),
                "mode": "retry",
                "cleanup_mode": "hard_reset",
                "cleanup_verification": verification,
            },
        )
        self._update_operation_result_payload(
            operation,
            {"cleanup_verification": verification},
            workspace_root=task.workspace_root,
        )
        self._record_operation_event(
            db,
            task,
            operation,
            "retry_cleanup_verification_finished" if verification.get("validated") else "retry_cleanup_verification_failed",
            "清空校验完成" if verification.get("validated") else "清空校验失败",
            level="info" if verification.get("validated") else "error",
            stage_name=operation.target_stage or task.current_stage,
            payload=verification,
        )
        if not verification.get("validated"):
            raise ValidationError("清空校验失败，禁止继续重试")
        return verification

    def _retry_target_items(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        target_stage: str,
    ):
        retry_item_keys = {
            str(item_key).strip()
            for item_key in list(self._retry_plan(task).get("retry_item_keys") or [])
            if str(item_key).strip()
        }
        if not retry_item_keys:
            return []
        items = [
            item
            for item in self._stage_items(db, task.id, target_stage)
            if self._stage_item_identity(item.item_key, item.parent_key) in retry_item_keys
        ]
        if self._streaming_mode_enabled(task) and target_stage == "dataflow_vuln_scan":
            grouped: dict[str, list[Any]] = {}
            for item in items:
                grouped.setdefault(self._stage_item_identity(item.item_key, item.parent_key), []).append(item)
            narrowed: list[Any] = []
            for identity_items in grouped.values():
                retryable = [
                    item for item in identity_items
                    if self._normalize_downstream_status(item.status) not in {"success", "partial_success"}
                ]
                narrowed.extend(retryable or identity_items)
            return narrowed
        return items

    def _sync_retry_operation_result_payload(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
        *,
        target_stage: str | None = None,
        phase: str = "prepare",
        extra_updates: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        resolved_target_stage = str(target_stage or operation.target_stage or "").strip() or None
        payload_updates: dict[str, Any] = {
            "target_stage": resolved_target_stage,
            "retry_item_keys": [
                str(item_key).strip()
                for item_key in list(self._retry_plan(task).get("retry_item_keys") or [])
                if str(item_key).strip()
            ],
            "item_actions": self._retry_item_actions(task),
        }
        if resolved_target_stage:
            payload_updates.update(
                self._build_retry_prepare_result(
                    db,
                    task,
                    target_stage=resolved_target_stage,
                    phase=phase,
                )
            )
        payload_updates.update(dict(extra_updates or {}))
        return self._update_operation_result_payload(
            operation,
            payload_updates,
            workspace_root=task.workspace_root,
        )

    async def _collect_retry_item_actions(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        target_stage: str,
        token: str | None,
    ) -> list[dict[str, Any]]:
        from app.service import task_manager as task_manager_module

        actions: list[dict[str, Any]] = []
        abnormal_statuses = set(getattr(task_manager_module, "RETRY_CHILD_ABNORMAL_STATUSES", {"failed", "cancelled", "downstream_missing"}))
        recreate_strategy = getattr(task_manager_module, "RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL", "recreate_from_abnormal")
        for item in self._retry_target_items(db, task, target_stage=target_stage):
            active_payload = None
            if str(item.downstream_task_id or "").strip():
                try:
                    active_payload = await self._active_downstream_payload(task, item, token)
                except Exception:
                    active_payload = None
            strategy, observed_status = self._classify_retry_downstream_strategy(
                item,
                task=task,
                active_payload=active_payload,
            )
            if active_payload is None and str(item.downstream_task_id or "").strip():
                normalized_current_status = (
                    self._map_downstream_status(str(item.status or ""))
                    or self._latest_observed_downstream_status(item)
                    or (str(item.status or "").strip().lower() or None)
                )
                if normalized_current_status in abnormal_statuses:
                    strategy = recreate_strategy
                    observed_status = normalized_current_status
            action = self._retry_item_action_snapshot(
                item,
                strategy=strategy,
                observed_status=observed_status,
                old_downstream_task_id=str(item.downstream_task_id or "").strip() or None,
                cleanup_performed=False,
                binding_cleared=False,
            )
            actions.append(action)
        self._set_retry_item_actions(task, actions)
        return actions

    async def _operation_collect_retry_stage_full_plan(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
    ) -> dict[str, Any]:
        target_stage = str(operation.target_stage or "").strip()
        affected_stages = await self._prepare_retry_stage_full(db, task, target_stage)
        downstream_refs = self._retry_downstream_refs_for_stages(db, task, affected_stages)
        plan = {
            "operation_type": operation.operation_type,
            "target_stage": target_stage,
            "affected_stages": list(affected_stages),
            "downstream_refs": [dict(ref) for ref in downstream_refs],
            "downstream_ref_count": len(downstream_refs),
        }
        self._update_operation_result_payload(
            operation,
            {"cleanup_plan": plan},
            workspace_root=task.workspace_root,
        )
        return plan

    async def _operation_execute_retry_stage_full_cleanup(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        phase = "prepare"
        plan = dict(self._operation_result_data(operation).get("cleanup_plan") or {})
        target_stage = str(plan.get("target_stage") or operation.target_stage or "").strip()
        affected_stages = [str(stage).strip() for stage in (plan.get("affected_stages") or []) if str(stage).strip()]
        if not affected_stages:
            affected_stages = await self._prepare_retry_stage_full(db, task, target_stage)
        downstream_refs = [dict(ref) for ref in (plan.get("downstream_refs") or []) if isinstance(ref, dict)]
        if not downstream_refs:
            downstream_refs, orphan_refs = self._retry_cleanup_refs(db, task, affected_stages)
        else:
            _, orphan_refs = self._retry_cleanup_refs(db, task, affected_stages)

        cleared_output_roots: list[str] = []
        output_root = Path(str(task.output_root or "")).resolve()
        for stage_name in affected_stages:
            for downstream_service in task_manager_module.STAGE_OUTPUT_SERVICES.get(stage_name, []):
                folder = task_manager_module.SERVICE_OUTPUT_FOLDERS.get(downstream_service, downstream_service.replace("_", "-"))
                cleared_output_roots.append(str(output_root / folder))

        self._record_event(
            db,
            task,
            "stage_retry_full_cleanup_started",
            f"阶段完全重试开始清理: {target_stage}",
            payload={
                "target_stage": target_stage,
                "affected_stages": list(affected_stages),
                "old_retry_mode": task.execution_mode,
                "new_retry_mode": task_manager_module.TASK_ACTION_RETRY_STAGE_FULL,
            },
            operation_id=operation.id,
        )
        self._invalidate_task_execution(task)
        for ref in orphan_refs:
            self._record_event(
                db,
                task,
                "retry_cleanup_orphan_child_detected",
                "阶段完全重试识别到历史 orphan 下游子任务",
                stage_name=target_stage,
                level="warning",
                payload=ref,
                operation_id=operation.id,
            )
        if downstream_refs:
            await self._cleanup_downstream_refs(db, task, downstream_refs, self._service_token())

        downstream_cleanup_results = [
            dict(result)
            for result in list(getattr(self, "_last_downstream_cleanup_results", []) or [])
            if isinstance(result, dict)
        ]
        downstream_cleanup_blocking_refs = [
            dict(result)
            for result in downstream_cleanup_results
            if bool(result.get("blocking"))
        ]
        downstream_cleanup_deferred_refs = [
            dict(result)
            for result in downstream_cleanup_results
            if bool(result.get("deferred"))
        ]

        self._clear_stage_outputs_from(task, target_stage, mark_stale=False)
        deleted_archive_job_count = self._delete_archive_children_for_stages(db, task, affected_stages)
        deleted_stage_item_count = self._delete_stage_items_for_stages(db, task.id, affected_stages)
        deleted_state_event_count = self._delete_state_event_rows_for_stages(db, task.id, affected_stages)
        deleted_timeline_event_count = self._delete_timeline_rows_for_stages(db, task.id, affected_stages)
        for stage_name in affected_stages:
            if (
                phase == "prepare"
                and self._streaming_mode_enabled(task)
                and target_stage in task_manager_module.STREAMING_TAIL_STAGES
                and stage_name != target_stage
            ):
                continue
            stage_run = db.query(task_manager_module.BinarySecurityStageRun).filter(
                task_manager_module.BinarySecurityStageRun.task_id == task.id,
                task_manager_module.BinarySecurityStageRun.stage_name == stage_name,
            ).first()
            if stage_run:
                self._reset_stage_run_for_retry(task, stage_run, increment_retry=(stage_name == target_stage))

        # Remove stale failure summary fields from in-memory and file-backed task summaries.
        summary = dict(task.summary or {})
        for key in ("failure_code", "failure_category", "failure_message", "error"):
            summary.pop(key, None)
        task.summary = summary
        task.last_error = None
        summary_path = Path(task.workspace_root) / task_manager_module.BinarySecurityTask.SUMMARY_FILENAME
        try:
            if summary_path.exists():
                persisted = json.loads(summary_path.read_text(encoding="utf-8"))
                if isinstance(persisted, dict):
                    for key in ("failure_code", "failure_category", "failure_message", "error"):
                        persisted.pop(key, None)
                    summary_path.write_text(json.dumps(persisted, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

        retry_plan = self._retry_plan(task)
        self._set_retry_plan(
            task,
            {
                **retry_plan,
                "target_stage": target_stage,
                "mode": task_manager_module.TASK_ACTION_RETRY_STAGE_FULL,
                "cleared_business_stages": list(affected_stages),
                "cleared_archive_stages": list(affected_stages),
            },
        )
        reconciled_stages = list(self._reconcile_retry_affected_stages_in_session(db, task, stage_names=affected_stages) or [])
        cleanup_summary = {
            "target_stage": target_stage,
            "affected_stages": list(affected_stages),
            "downstream_ref_count": len(downstream_refs),
            "deleted_stage_item_count": deleted_stage_item_count,
            "deleted_archive_job_count": deleted_archive_job_count,
            "deleted_state_event_count": deleted_state_event_count,
            "deleted_timeline_event_count": deleted_timeline_event_count,
            "cleared_output_roots": cleared_output_roots,
            "downstream_cleanup_results": downstream_cleanup_results,
            "downstream_cleanup_blocking_refs": downstream_cleanup_blocking_refs,
            "downstream_cleanup_deferred_refs": downstream_cleanup_deferred_refs,
            "cleanup_partial_failed": bool(downstream_cleanup_deferred_refs or downstream_cleanup_blocking_refs),
            "reconciled_stages": reconciled_stages,
        }
        self._update_operation_result_payload(
            operation,
            {
                "cleanup_plan": {
                    **plan,
                    "target_stage": target_stage,
                    "affected_stages": list(affected_stages),
                    "downstream_refs": downstream_refs,
                },
                "cleanup_result": cleanup_summary,
            },
            workspace_root=task.workspace_root,
        )
        self._raise_if_restart_cleanup_incomplete(
            cleanup_partial_failed=bool(cleanup_summary.get("cleanup_partial_failed")),
            deferred_refs=downstream_cleanup_deferred_refs,
            blocking_refs=downstream_cleanup_blocking_refs,
            context="retry_stage_full",
        )
        self._record_event(
            db,
            task,
            "stage_retry_full_cleanup_finished",
            f"阶段完全重试清理完成: {target_stage}",
            stage_name=target_stage,
            payload={
                **cleanup_summary,
                "old_retry_mode": task.execution_mode,
                "new_retry_mode": task_manager_module.TASK_ACTION_RETRY_STAGE_FULL,
            },
            operation_id=operation.id,
        )
        return cleanup_summary

    async def _operation_collect_retry_failed_items_plan(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
    ) -> dict[str, Any]:
        target_stage = str(operation.target_stage or "").strip()
        await self._collect_retry_item_actions(db, task, target_stage=target_stage, token=self._service_token())
        return self._sync_retry_operation_result_payload(
            db,
            task,
            operation,
            target_stage=target_stage,
            phase="prepare",
        )

    async def _operation_sync_retry_target_stage_state(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        target_stage = str(operation.target_stage or "").strip()
        item_ids = [
            str(action.get("item_id") or "").strip()
            for action in self._retry_item_actions(task)
            if str(action.get("item_id") or "").strip()
        ]
        batch_size = self._operation_step_batch_size()
        cursor = dict(operation.resume_cursor or {})
        step_cursor = dict(cursor.get(task_manager_module.TASK_OPERATION_STEP_SYNC_TARGET_STAGE_STATE) or {})
        offset = max(0, int(step_cursor.get("offset") or 0))
        synced_count = 0
        for batch_start in range(offset, len(item_ids), batch_size):
            batch_item_ids = item_ids[batch_start:batch_start + batch_size]
            try:
                await self.sync_downstream_status(
                    db,
                    project_id=task.project_id,
                    task_id=task.id,
                    stage_name=target_stage,
                    item_ids=batch_item_ids,
                    force=True,
                    token=self._service_token(),
                    record_request_event=False,
                    record_noop_events=False,
                    apply_state=(target_stage != "entry_analysis"),
                )
            except AttributeError:
                matched_items = {
                    str(item.id or "").strip(): item
                    for item in self._stage_items(db, task.id, target_stage)
                    if str(item.id or "").strip() in set(batch_item_ids)
                }
                for current_item_id in batch_item_ids:
                    item = matched_items.get(str(current_item_id or "").strip())
                    if item is None:
                        continue
                    payload = None
                    if str(item.downstream_task_id or "").strip():
                        try:
                            payload = await self._active_downstream_payload(task, item, self._service_token())
                        except Exception:
                            payload = None
                    strategy, observed_status = self._classify_retry_downstream_strategy(
                        item,
                        task=task,
                        active_payload=payload,
                    )
                    self._update_retry_item_action(
                        task,
                        item_id=item.id,
                        updates={
                            "strategy": strategy,
                            "observed_status": observed_status,
                            "current_downstream_task_id": str(item.downstream_task_id or "").strip() or None,
                        },
                    )
            synced_count += len(batch_item_ids)
            next_offset = batch_start + len(batch_item_ids)
            try:
                await self._operation_progress_heartbeat(
                    db,
                    task,
                    operation,
                    step_name=task_manager_module.TASK_OPERATION_STEP_SYNC_TARGET_STAGE_STATE,
                    resume_cursor={
                        "current_step": task_manager_module.TASK_OPERATION_STEP_SYNC_TARGET_STAGE_STATE,
                        task_manager_module.TASK_OPERATION_STEP_SYNC_TARGET_STAGE_STATE: {
                            "offset": next_offset,
                            "processed_count": next_offset,
                            "total_count": len(item_ids),
                        },
                    },
                    payload={
                        "batch_size": len(batch_item_ids),
                        "processed_count": next_offset,
                        "remaining_count": max(0, len(item_ids) - next_offset),
                        "total_count": len(item_ids),
                    },
                )
            except AttributeError:
                pass
        payload = {
            "target_stage": target_stage,
            "synced": True,
            "synced_items": synced_count,
            "total_items": len(item_ids),
        }
        self._update_operation_result_payload(
            operation,
            {"sync_target_stage_state": payload},
            workspace_root=task.workspace_root,
        )
        return payload

    async def _prepare_retry_failed_items(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        target_stage: str,
    ) -> list[str]:
        from app.service import task_manager as task_manager_module

        stage_sequence = self._stage_sequence_for_task(task)
        if target_stage not in stage_sequence:
            raise ValidationError(f"无效阶段: {target_stage}")
        plan = self._retry_plan(task)
        retry_item_keys = set(plan.get("retry_item_keys") or [])
        if not retry_item_keys:
            raise ValidationError("失败项重试缺少目标子任务")
        stage_items = self._stage_items(db, task.id, target_stage)
        retry_items = [
            item for item in stage_items
            if self._stage_item_identity(item.item_key, item.parent_key) in retry_item_keys
        ]
        if self._streaming_mode_enabled(task) and target_stage == "dataflow_vuln_scan":
            non_success_retry_items = [
                item for item in retry_items
                if self._normalize_downstream_status(item.status) not in {"success", "partial_success"}
            ]
            if non_success_retry_items:
                retry_items = non_success_retry_items
        if not retry_items:
            raise ValidationError("失败项重试未找到目标阶段子任务")
        sync_apply_state = target_stage != "entry_analysis"
        try:
            await self.sync_downstream_status(
                db,
                project_id=task.project_id,
                task_id=task.id,
                stage_name=target_stage,
                force=True,
                token=self._service_token(),
                record_request_event=False,
                record_noop_events=False,
                apply_state=sync_apply_state,
            )
        except AttributeError:
            pass
        if target_stage == "entry_analysis":
            for item in retry_items:
                result = self._load_stage_item_result_payload(item)
                sync_observation = dict(result.get("sync_observation") or {})
                item.status = "pending"
                item.finished_at = None
                self._mark_stage_item_sync_observation(
                    item,
                    sync_status=self._string_or_none(sync_observation.get("sync_status")) or "observed",
                    synced_at=task_manager_module._now(),
                    error_message=None,
                    http_status=None,
                    error_type=None,
                    status_raw=None,
                    mapped_status=None,
                    downstream_status=None,
                    state_applied=False,
                )
        target_index = stage_sequence.index(target_stage)
        affected_stages = stage_sequence[target_index:]
        validation_affected_stages = list(affected_stages)
        downstream_stages = stage_sequence[target_index + 1:]
        all_downstream_refs = self._retry_downstream_refs_for_stages(db, task, downstream_stages)
        summary_snapshot_before_reset = dict(task.summary or {})
        self._invalidate_task_execution(task)
        self._clear_single_stage_runtime_state(task, target_stage)
        cleared_business_stages: list[str] = []
        cleared_archive_stages: list[str] = []
        if self._streaming_mode_enabled(task) and target_stage in task_manager_module.STREAMING_TAIL_STAGES:
            cleared_business_stages = await self._cleanup_streaming_retry_descendants(
                db,
                task,
                target_stage,
                retry_items,
                summary_snapshot=summary_snapshot_before_reset,
            )
            cleared_archive_stages = list(cleared_business_stages)
            validation_affected_stages = [target_stage]
            for downstream_stage in cleared_business_stages:
                downstream_run = db.query(task_manager_module.BinarySecurityStageRun).filter(
                    task_manager_module.BinarySecurityStageRun.task_id == task.id,
                    task_manager_module.BinarySecurityStageRun.stage_name == downstream_stage,
                ).first()
                if downstream_run:
                    self._reset_stage_run_for_retry(task, downstream_run, increment_retry=False)
        else:
            if all_downstream_refs:
                await self._cleanup_downstream_refs(db, task, all_downstream_refs, self._service_token())
            retry_item_ids = [item.id for item in retry_items if str(item.id or "").strip()]
            if retry_item_ids:
                target_archive_jobs = self._archive_jobs_for_stage_items(db, task.id, target_stage, retry_item_ids)
                self._delete_archive_roots_for_jobs(task, target_archive_jobs)
                clear_archive_jobs_for_stage_items = getattr(self, "_clear_archive_jobs_for_stage_items", None)
                if callable(clear_archive_jobs_for_stage_items):
                    clear_archive_jobs_for_stage_items(db, task.id, target_stage, retry_item_ids)
                elif hasattr(db, "archive_jobs") and isinstance(getattr(db, "archive_jobs"), list):
                    target_item_ids = set(retry_item_ids)
                    db.archive_jobs = [
                        row
                        for row in db.archive_jobs
                        if not (
                            str(getattr(row, "task_id", "") or "").strip() == task.id
                            and str(getattr(row, "stage_name", "") or "").strip() == target_stage
                            and str(getattr(row, "item_id", "") or "").strip() in target_item_ids
                        )
                    ]
            if downstream_stages:
                self._clear_stage_outputs_from(task, downstream_stages[0], mark_stale=False)
                self._delete_archive_children_for_stages(db, task, downstream_stages)
                self._delete_stage_items_for_stages(db, task.id, downstream_stages)
                cleared_business_stages = list(downstream_stages)
                cleared_archive_stages = list(downstream_stages)
        target_run = db.query(task_manager_module.BinarySecurityStageRun).filter(
            task_manager_module.BinarySecurityStageRun.task_id == task.id,
            task_manager_module.BinarySecurityStageRun.stage_name == target_stage,
        ).first()
        if target_run:
            self._reset_stage_run_for_retry(task, target_run, increment_retry=True)
        if not (self._streaming_mode_enabled(task) and target_stage in task_manager_module.STREAMING_TAIL_STAGES):
            for downstream_stage in downstream_stages:
                downstream_run = db.query(task_manager_module.BinarySecurityStageRun).filter(
                    task_manager_module.BinarySecurityStageRun.task_id == task.id,
                    task_manager_module.BinarySecurityStageRun.stage_name == downstream_stage,
                ).first()
                if downstream_run:
                    self._reset_stage_run_for_retry(task, downstream_run, increment_retry=False)
        self._set_retry_plan(
            task,
            {
                **plan,
                "cleared_business_stages": cleared_business_stages,
                "cleared_archive_stages": cleared_archive_stages,
                "retry_item_keys": sorted(retry_item_keys),
                "item_actions": self._retry_item_actions(task),
                "affected_stages": validation_affected_stages,
            },
        )
        if downstream_stages:
            self._reconcile_retry_affected_stages_in_session(
                db,
                task,
                stage_names=list(downstream_stages),
            )
        return affected_stages

    async def _cleanup_streaming_retry_descendants(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        target_stage: str,
        retry_items: list,
        *,
        summary_snapshot: dict[str, Any] | None = None,
    ) -> list[str]:
        normalized_target = str(target_stage or "").strip()
        if normalized_target not in {"entry_analysis", "dataflow_vuln_scan"}:
            return []

        retry_item_ids = {
            str(item.id or "").strip()
            for item in retry_items
            if str(item.id or "").strip()
        }
        if not retry_item_ids:
            return []

        all_tail_items = list(self._stage_items(db, task.id, "dataflow_vuln_scan"))
        delete_queue = set(retry_item_ids)
        protected_item_ids = set(retry_item_ids if normalized_target == "dataflow_vuln_scan" else [])
        to_delete_ids: list[str] = []
        refs_to_cleanup: list[dict[str, Any]] = []
        direct_descendant_entry_keys: set[str] = set()
        discovered = True
        while discovered:
            discovered = False
            for item in all_tail_items:
                input_ref = dict(item.input_ref or {})
                upstream_item_id = str(input_ref.get("upstream_item_id") or "").strip()
                item_id = str(item.id or "").strip()
                if not item_id or upstream_item_id not in delete_queue or item_id in delete_queue:
                    continue
                delete_queue.add(item_id)
                if upstream_item_id in retry_item_ids:
                    entry_key = str(input_ref.get("entry_key") or item.item_key or "").strip()
                    if entry_key:
                        direct_descendant_entry_keys.add(entry_key)
                discovered = True

        for item in all_tail_items:
            item_id = str(item.id or "").strip()
            if item_id not in delete_queue or item_id in protected_item_ids:
                continue
            to_delete_ids.append(item_id)
            downstream_task_id = str(item.downstream_task_id or "").strip()
            if downstream_task_id:
                refs_to_cleanup.append(
                    {
                        "service": item.downstream_service,
                        "task_id": downstream_task_id,
                        "project_id": task.project_id,
                        "stage_name": item.stage_name,
                        "item_id": item.id,
                        "item_key": item.item_key,
                    }
                )

        if refs_to_cleanup:
            await self._cleanup_downstream_refs(db, task, refs_to_cleanup, self._service_token())
        if to_delete_ids:
            target_archive_jobs = self._archive_jobs_for_stage_items(db, task.id, "dataflow_vuln_scan", to_delete_ids)
            self._delete_archive_roots_for_jobs(task, target_archive_jobs)
            clear_archive_jobs_for_stage_items = getattr(self, "_clear_archive_jobs_for_stage_items", None)
            if callable(clear_archive_jobs_for_stage_items):
                clear_archive_jobs_for_stage_items(db, task.id, "dataflow_vuln_scan", to_delete_ids)
            self._delete_stage_items_by_ids(db, to_delete_ids)
            self._delete_timeline_rows_for_stages(db, task.id, ["dataflow_vuln_scan"])
            self._delete_state_event_rows_for_stages(db, task.id, ["dataflow_vuln_scan"])
            if normalized_target == "entry_analysis":
                entry_root = Path(str(task.output_root or "")) / "entry-analysis"
                if entry_root.exists():
                    for entry_key in direct_descendant_entry_keys:
                        for child in entry_root.glob(f"{entry_key}__*"):
                            shutil.rmtree(child, ignore_errors=True)

        surviving_tail_items = list(self._stage_items(db, task.id, "dataflow_vuln_scan"))
        surviving_entry_keys = {
            str(dict(item.result or {}).get("entry_key") or item.item_key or "").strip()
            for item in surviving_tail_items
            if str(dict(item.result or {}).get("entry_key") or item.item_key or "").strip()
        }
        surviving_vuln_entry_keys = {
            str(dict(item.result or {}).get("entry_key") or dict(item.input_ref or {}).get("entry_key") or item.item_key or "").strip()
            for item in surviving_tail_items
            if str(dict(item.input_ref or {}).get("upstream_item_id") or "").strip()
            and str(dict(item.result or {}).get("entry_key") or dict(item.input_ref or {}).get("entry_key") or item.item_key or "").strip()
        }
        task_summary = dict(summary_snapshot or task.summary or {})
        if normalized_target == "entry_analysis":
            task_summary["dataflow_results"] = [
                row
                for row in list(task_summary.get("dataflow_results") or [])
                if str(dict(row).get("entry_key") or "").strip() in surviving_entry_keys
            ]
        task_summary["vuln_results"] = [
            row
            for row in list(task_summary.get("vuln_results") or [])
            if str(dict(row).get("entry_key") or "").strip() in surviving_vuln_entry_keys
        ]
        metrics = dict(task.metrics or {})
        metrics["vuln_result_count"] = len(task_summary.get("vuln_results") or [])
        task.metrics = metrics
        task.summary = task_summary
        return ["dataflow_vuln_scan"] if to_delete_ids else []

    async def _operation_prepare_retry_items(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
    ) -> dict[str, Any]:
        target_stage = str(operation.target_stage or "").strip()
        affected_stages = await self._prepare_retry_failed_items(db, task, target_stage)
        prepare_result = self._build_retry_prepare_result(db, task, target_stage=target_stage)
        prepare_result["affected_stages"] = affected_stages
        self._sync_retry_operation_result_payload(
            db,
            task,
            operation,
            target_stage=target_stage,
            phase="prepare",
            extra_updates=prepare_result,
        )
        validation = dict(prepare_result.get("validation") or {})
        if not bool(validation.get("validated")):
            self._record_operation_event(
                db,
                task,
                operation,
                "retry_prepare_validation_failed",
                "失败项重试准备校验失败",
                level="error",
                stage_name=operation.target_stage,
                payload=prepare_result,
            )
            raise ValidationError("失败项重试准备校验失败")
        self._record_operation_event(
            db,
            task,
            operation,
            "retry_prepare_validation_succeeded",
            "失败项重试准备校验通过",
            stage_name=operation.target_stage,
            payload=prepare_result,
        )
        return prepare_result

    async def _operation_cleanup_retry_abnormal_children(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        target_stage = str(operation.target_stage or "").strip()
        recreate_strategy = getattr(task_manager_module, "RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL", "recreate_from_abnormal")
        cleaned_item_ids: list[str] = []
        cleanup_errors: list[dict[str, Any]] = []
        actions = self._retry_item_actions(task)
        stage_items_by_id = {
            str(item.id or "").strip(): item
            for item in self._stage_items(db, task.id, target_stage)
        }
        for action in actions:
            item_id = str(action.get("item_id") or "").strip()
            if not item_id:
                continue
            if str(action.get("strategy") or "").strip() != recreate_strategy:
                continue
            item = stage_items_by_id.get(item_id)
            if item is None:
                self._update_retry_item_action(
                    task,
                    item_id=item_id,
                    updates={"cleanup_status": "failed", "error": "retry_item_missing"},
                )
                cleanup_errors.append({"item_id": item_id, "error": "retry_item_missing"})
                continue
            old_task_id = str(action.get("old_downstream_task_id") or item.downstream_task_id or "").strip() or None
            if not old_task_id:
                self._clear_item_downstream_runtime_state(item)
                item.finished_at = None
                self._mark_replacement_in_progress(
                    item,
                    old_downstream_task_id=None,
                    binding_cleared=True,
                    verification_status="pending",
                    transition_type=self.CHILD_TRANSITION_DESTRUCTIVE_REBUILD,
                )
                self._update_retry_item_action(
                    task,
                    item_id=item_id,
                    updates={
                        "cleanup_performed": True,
                        "binding_cleared": True,
                        "cleanup_status": "succeeded",
                        "current_downstream_task_id": None,
                    },
                )
                cleaned_item_ids.append(item_id)
                continue
            try:
                refs = [
                    {
                        "service": item.downstream_service,
                        "task_id": old_task_id,
                        "project_id": task.project_id,
                        "stage_name": item.stage_name,
                        "item_id": item.id,
                        "item_key": item.item_key,
                    }
                ]
                await self._delete_downstream_refs(db, task, refs, self._service_token())
                self._clear_item_downstream_runtime_state(item)
                item.finished_at = None
                self._mark_replacement_in_progress(
                    item,
                    old_downstream_task_id=old_task_id,
                    binding_cleared=True,
                    verification_status="pending",
                    transition_type=self.CHILD_TRANSITION_DESTRUCTIVE_REBUILD,
                )
                updated = {
                    "cleanup_performed": True,
                    "binding_cleared": True,
                    "cleanup_status": "succeeded",
                    "current_downstream_task_id": None,
                    "new_downstream_task_id": None,
                }
                self._update_retry_item_action(task, item_id=item_id, updates=updated)
                cleaned_item_ids.append(item_id)
            except Exception as exc:
                self._update_retry_item_action(
                    task,
                    item_id=item_id,
                    updates={"cleanup_status": "failed", "error": str(exc)},
                )
                cleanup_errors.append({"item_id": item_id, "error": str(exc)})
                raise
        payload = {
            "target_stage": target_stage,
            "cleaned_item_ids": cleaned_item_ids,
            "cleaned_count": len(cleaned_item_ids),
            "error_count": len(cleanup_errors),
        }
        self._sync_retry_operation_result_payload(
            db,
            task,
            operation,
            target_stage=target_stage,
            phase="prepare",
            extra_updates={"cleanup_abnormal_children": payload},
        )
        return payload

    async def _operation_create_retry_children(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
    ) -> dict[str, Any]:
        target_stage = str(operation.target_stage or "").strip()
        stage_items_by_id = {
            str(item.id or "").strip(): item
            for item in self._stage_items(db, task.id, target_stage)
        }
        created_item_ids: list[str] = []
        actions = self._retry_item_actions(task)
        for action in actions:
            item_id = str(action.get("item_id") or "").strip()
            if not item_id:
                continue
            if not bool(action.get("binding_cleared")):
                continue
            if str(action.get("create_status") or "").strip() == "succeeded":
                continue
            item = stage_items_by_id.get(item_id)
            if item is None:
                continue
            recovered_payload = await self._find_retry_created_child_payload(task, item)
            if recovered_payload:
                item.downstream_task_id = str(recovered_payload.get("task_id") or item.downstream_task_id or "").strip() or None
                item.status = self._map_downstream_status(str(recovered_payload.get("status") or "")) or "pending"
                self._update_retry_item_action(
                    task,
                    item_id=item_id,
                    updates={
                        "current_downstream_task_id": item.downstream_task_id,
                        "new_downstream_task_id": item.downstream_task_id,
                        "create_status": "succeeded",
                    },
                )
                created_item_ids.append(item_id)
                continue
            try:
                created = await self._downstream_create_task(
                    db,
                    task,
                    item,
                    service=str(item.downstream_service or "").strip(),
                    token=self._service_token(),
                    payload=dict(item.input_ref or {}),
                )
                item.downstream_task_id = str(created.get("task_id") or item.downstream_task_id or "").strip() or None
                item.status = self._map_downstream_status(str(created.get("status") or "")) or "pending"
                self._update_retry_item_action(
                    task,
                    item_id=item_id,
                    updates={
                        "current_downstream_task_id": item.downstream_task_id,
                        "new_downstream_task_id": item.downstream_task_id,
                        "create_status": "succeeded",
                    },
                )
                created_item_ids.append(item_id)
            except Exception as exc:
                self._update_retry_item_action(
                    task,
                    item_id=item_id,
                    updates={"create_status": "failed", "error": str(exc)},
                )
                raise
        payload = {
            "target_stage": target_stage,
            "created_item_ids": created_item_ids,
            "created_count": len(created_item_ids),
        }
        self._sync_retry_operation_result_payload(
            db,
            task,
            operation,
            target_stage=target_stage,
            phase="prepare",
            extra_updates={"create_retry_children": payload},
        )
        return payload

    async def _operation_verify_retry_bindings(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
    ) -> dict[str, Any]:
        target_stage = str(operation.target_stage or "").strip()
        actions = self._retry_item_actions(task)
        stage_items_by_id = {
            str(item.id or "").strip(): item
            for stage_name in ([target_stage] + [str(name).strip() for name in list(self._retry_plan(task).get("affected_stages") or []) if str(name).strip()])
            for item in self._stage_items(db, task.id, stage_name)
        }
        issues: list[dict[str, Any]] = []
        for action in actions:
            item_id = str(action.get("item_id") or "").strip()
            if not item_id:
                continue
            item = stage_items_by_id.get(item_id)
            if item is None:
                issues.append({"item_id": item_id, "issue": "retry_item_missing"})
                self._update_retry_item_action(task, item_id=item_id, updates={"verification_status": "failed", "error": "retry_item_missing"})
                continue
            strategy = str(action.get("strategy") or "").strip()
            if strategy != "recreate_from_abnormal":
                if (
                    strategy == "adopt_active"
                    and str(item.downstream_task_id or "").strip()
                    and hasattr(self, "_downstream_control_existing_task")
                ):
                    control = await self._downstream_control_existing_task(
                        db,
                        stage_name=target_stage,
                        task=task,
                        item=item,
                        token=self._service_token(),
                    )
                    control_payload = dict(control.get("payload") or {})
                    control_status = self._map_downstream_status(str(control_payload.get("status") or "")) or str(item.status or "").strip().lower()
                    if control_status in {"failed", "cancelled", "downstream_missing"}:
                        old_task_id = str(item.downstream_task_id or "").strip() or None
                        refs = []
                        if old_task_id:
                            refs.append(
                                {
                                    "service": item.downstream_service,
                                    "task_id": old_task_id,
                                    "project_id": task.project_id,
                                    "stage_name": item.stage_name,
                                    "item_id": item.id,
                                    "item_key": item.item_key,
                                }
                            )
                        if refs:
                            await self._delete_downstream_refs(db, task, refs, self._service_token())
                        self._clear_item_downstream_runtime_state(item)
                        item.finished_at = None
                        self._mark_replacement_in_progress(
                            item,
                            old_downstream_task_id=old_task_id,
                            binding_cleared=True,
                            verification_status="pending",
                            transition_type=self.CHILD_TRANSITION_DESTRUCTIVE_REBUILD,
                        )
                        created = await self._downstream_create_task(
                            db,
                            task,
                            item,
                            service=str(item.downstream_service or "").strip(),
                            token=self._service_token(),
                            payload=dict(item.input_ref or {}),
                        )
                        item.downstream_task_id = str(created.get("task_id") or item.downstream_task_id or "").strip() or None
                        item.status = self._map_downstream_status(str(created.get("status") or "")) or "pending"
                        self._clear_replacement_in_progress(item)
                        self._update_retry_item_action(
                            task,
                            item_id=item_id,
                            updates={
                                "strategy": "recreate_from_abnormal",
                                "observed_status": control_status,
                                "cleanup_performed": True,
                                "binding_cleared": True,
                                "cleanup_status": "succeeded",
                                "create_required": True,
                                "create_status": "succeeded",
                                "current_downstream_task_id": item.downstream_task_id,
                                "new_downstream_task_id": item.downstream_task_id,
                                "verification_status": "succeeded",
                            },
                        )
                        continue
                self._update_retry_item_action(task, item_id=item_id, updates={"verification_status": "succeeded"})
                continue
            current_task_id = str(item.downstream_task_id or "").strip() or None
            old_task_id = str(action.get("old_downstream_task_id") or "").strip() or None
            if not current_task_id:
                issues.append({"item_id": item_id, "issue": "replacement_binding_missing"})
                self._update_retry_item_action(task, item_id=item_id, updates={"verification_status": "failed", "error": "replacement_binding_missing"})
                continue
            if old_task_id and current_task_id == old_task_id:
                issues.append({"item_id": item_id, "issue": "replacement_reused_old_child", "downstream_task_id": current_task_id})
                self._update_retry_item_action(task, item_id=item_id, updates={"verification_status": "failed", "error": "replacement_reused_old_child"})
                continue
            self._clear_replacement_in_progress(item)
            self._update_retry_item_action(
                task,
                item_id=item_id,
                updates={
                    "current_downstream_task_id": current_task_id,
                    "new_downstream_task_id": current_task_id,
                    "verification_status": "succeeded",
                },
            )
        validation = {
            "validated": not issues,
            "issues": issues,
        }
        payload = {
            "target_stage": target_stage,
            "validation": validation,
            "item_actions": self._retry_item_actions(task),
        }
        self._sync_retry_operation_result_payload(
            db,
            task,
            operation,
            target_stage=target_stage,
            phase="verify",
            extra_updates=payload,
        )
        if issues:
            self._record_operation_event(
                db,
                task,
                operation,
                "retry_item_binding_verification_failed",
                "失败项重试绑定校验失败",
                level="error",
                stage_name=operation.target_stage,
                payload=payload,
            )
            raise ValidationError("失败项重试绑定校验失败")
        return payload

    async def _operation_finalize_retry_failed_items(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
    ) -> dict[str, Any]:
        affected_stages = [
            str(stage_name).strip()
            for stage_name in list(self._retry_plan(task).get("affected_stages") or [])
            if str(stage_name).strip()
        ]
        if affected_stages:
            self._reconcile_retry_affected_stages_in_session(
                db,
                task,
                stage_names=affected_stages,
            )
        decision = self._decide_task_resume_after_stage_reset(
            db,
            task,
            next_stage=str(operation.target_stage or "").strip() or None,
            resume_reason="retry_failed_items_finalize",
            source="retry_failed_items_finalize",
            message="失败项重试阶段已完成收口，父任务恢复后续推进",
            payload={"affected_stages": affected_stages},
        )
        self._apply_task_layer_decision(db, task, decision)
        payload = {
            "finalized": True,
            "target_stage": operation.target_stage,
            "affected_stages": affected_stages,
            "resume_decision": {
                "requeue": bool(getattr(decision, "owned_execution_requeue_required", False)),
                "next_stage": str(getattr(decision, "next_stage", "") or "").strip() or None,
                "resume_reason": str(getattr(decision, "resume_reason", "") or "").strip() or None,
            },
        }
        self._sync_retry_operation_result_payload(
            db,
            task,
            operation,
            target_stage=str(operation.target_stage or "").strip(),
            phase="verify",
            extra_updates={"finalize": payload},
        )
        self._record_operation_event(
            db,
            task,
            operation,
            "retry_operation_succeeded",
            "失败项重试控制面已收敛",
            stage_name=operation.target_stage,
            payload=payload,
        )
        return payload

    async def _prepare_cancel_task(self: TaskManager, db: Session, task: BinarySecurityTask) -> list[str]:
        from app.service import task_manager as task_manager_module

        token = self._service_token()
        target_stage = str(task.current_stage or "").strip() or None
        if task.status == "cancelled":
            running_items = db.query(task_manager_module.BinarySecurityStageItem).filter(
                task_manager_module.BinarySecurityStageItem.task_id == task.id,
                task_manager_module.BinarySecurityStageItem.status.in_(["pending", "queued", "dispatching", "running"]),
            ).all()
            for item in running_items:
                item.status = "cancelled"
                item.finished_at = item.finished_at or task_manager_module._now()
            active_stage_runs = db.query(task_manager_module.BinarySecurityStageRun).filter(
                task_manager_module.BinarySecurityStageRun.task_id == task.id,
                task_manager_module.BinarySecurityStageRun.status.in_(["pending", "dispatching", "queued", "running"]),
            ).all()
            for stage_run in active_stage_runs:
                stage_run.status = "cancelled"
                stage_run.finished_at = stage_run.finished_at or task_manager_module._now()
            downstream_refs = self._dedupe_downstream_refs(self._collect_downstream_refs(task, running_items))
            orphan_refs = self._dedupe_downstream_refs(self._discover_parent_linked_downstream_refs(db, task))
            self._record_event(
                db,
                task,
                "manual_cancel_noop",
                "任务已经是取消状态，已归一化仍活跃的阶段与子任务",
                stage_name=target_stage,
                payload={
                    "cancelled_item_count": len(running_items),
                    "cancelled_stage_run_count": len(active_stage_runs),
                    "downstream_ref_count": len(downstream_refs),
                    "orphan_downstream_ref_count": len(orphan_refs),
                },
            )
            db.commit()
            cancel_refs = downstream_refs or orphan_refs
            if cancel_refs:
                await self._cancel_downstream_refs(db, task, cancel_refs, token)
            return [stage.stage_name for stage in active_stage_runs]

        self._set_task_status(
            db,
            task,
            task_manager_module.TASK_STATUS_CANCELLING,
            reason="取消操作进入执行，任务切换为取消中",
            source="task_operation",
            stage_name=target_stage,
        )
        self._invalidate_task_execution(task)
        task.finished_at = None
        running_items = db.query(task_manager_module.BinarySecurityStageItem).filter(
            task_manager_module.BinarySecurityStageItem.task_id == task.id,
            task_manager_module.BinarySecurityStageItem.status.in_(["pending", "queued", "dispatching", "running"]),
        ).all()
        for item in running_items:
            item.status = "cancelled"
            item.finished_at = task_manager_module._now()
        active_stage_runs = db.query(task_manager_module.BinarySecurityStageRun).filter(
            task_manager_module.BinarySecurityStageRun.task_id == task.id,
            task_manager_module.BinarySecurityStageRun.status.in_(["pending", "dispatching", "queued", "running"]),
        ).all()
        for stage_run in active_stage_runs:
            stage_run.status = "cancelled"
            stage_run.finished_at = stage_run.finished_at or task_manager_module._now()
        downstream_refs = self._dedupe_downstream_refs(self._collect_downstream_refs(task, running_items))
        orphan_refs = self._dedupe_downstream_refs(self._discover_parent_linked_downstream_refs(db, task))
        self._record_event(
            db,
            task,
            "task_cancelling",
            "任务进入取消中，后台正在停止下游执行并等待收敛",
            stage_name=target_stage,
            payload={
                "cancelled_item_count": len(running_items),
                "cancelled_downstream_count": len(downstream_refs),
                "orphan_downstream_ref_count": len(orphan_refs),
            },
        )
        task_manager_module.observe_task_error("cancel", stage=str(task.current_stage or "none"), result="accepted")
        db.commit()
        await self._write_task_metadata_async(
            task,
            Path(task.workspace_root) / "input" / "task-metadata.json",
            status=task_manager_module.TASK_STATUS_CANCELLING,
        )
        await self._request_local_worker_cancel(task.id, wait_for_runner=False)
        for item in running_items:
            if str(item.downstream_task_id or "").strip():
                await self._cancel_downstream(item, token)
        if downstream_refs:
            await self._cancel_downstream_refs(db, task, downstream_refs, token)
        return sorted(
            {
                str(stage_run.stage_name or "").strip()
                for stage_run in active_stage_runs
                if str(stage_run.stage_name or "").strip()
            }
        )

    async def _prepare_delete_task(self: TaskManager, db: Session, task: BinarySecurityTask) -> None:
        from app.service import task_manager as task_manager_module

        operation = None
        current_operation_id = str(getattr(task, "current_operation_id", "") or "").strip()
        if current_operation_id:
            operation = db.query(task_manager_module.BinarySecurityTaskOperation).filter(
                task_manager_module.BinarySecurityTaskOperation.id == current_operation_id
            ).first()
        request_payload = dict(getattr(operation, "request_payload", None) or {})
        force_delete = bool(request_payload.get("force_delete") or request_payload.get("force"))
        event_prefix = "task_force_delete" if force_delete else "task_delete"
        stage_names = list(self._stage_sequence_for_task(task))
        token = self._service_token()
        task.last_error = None

        stage_items = db.query(task_manager_module.BinarySecurityStageItem).filter(
            task_manager_module.BinarySecurityStageItem.task_id == task.id
        ).all()
        downstream_refs = self._dedupe_downstream_refs(
            self._collect_downstream_refs(task, stage_items) + self._discover_parent_linked_downstream_refs(db, task)
        )
        task_manager_module.logger.info(
            "binary-security prepare_delete_task starting cleanup: task_id=%s stage_item_count=%s downstream_ref_count=%s force_delete=%s",
            task.id,
            len(stage_items),
            len(downstream_refs),
            force_delete,
        )
        await self._request_local_worker_cancel(task.id, wait_for_runner=False)
        if downstream_refs:
            with suppress(Exception):
                task_manager_module.logger.info(
                    "binary-security prepare_delete_task requesting downstream cancellation: task_id=%s downstream_ref_count=%s",
                    task.id,
                    len(downstream_refs),
                )
                await self._cancel_downstream_refs(db, task, downstream_refs, token)
            task_manager_module.logger.info(
                "binary-security prepare_delete_task requesting downstream deletion: task_id=%s downstream_ref_count=%s",
                task.id,
                len(downstream_refs),
            )
            await self._delete_downstream_refs(
                db,
                task,
                downstream_refs,
                token,
                force_delete=force_delete,
                cleanup_scope="task_delete",
            )
            task_manager_module.logger.info(
                "binary-security prepare_delete_task downstream cleanup returned: task_id=%s cleanup_result_count=%s",
                task.id,
                len(list(getattr(self, "_last_downstream_cleanup_results", []) or [])),
            )

        downstream_cleanup_results = [
            dict(result)
            for result in list(getattr(self, "_last_downstream_cleanup_results", []) or [])
            if isinstance(result, dict)
        ]
        downstream_cleanup_deferred_refs = [
            dict(result)
            for result in downstream_cleanup_results
            if bool(result.get("deferred"))
        ]
        downstream_cleanup_blocking_refs = [
            dict(result)
            for result in downstream_cleanup_results
            if bool(result.get("blocking"))
        ]

        cleanup_counts = {
            "archive_jobs_deleted": self._delete_archive_children_for_stages(db, task, stage_names),
            "stage_items_deleted": self._delete_stage_items_for_stages(db, task.id, stage_names),
            "stage_runs_deleted": self._delete_stage_run_rows(db, task.id),
            "timeline_events_deleted": self._delete_task_timeline_rows(db, task.id),
            "state_events_deleted": self._delete_task_state_event_rows(db, task.id),
        }
        self._record_event(
            db,
            task,
            f"{event_prefix}_requested",
            "后台已开始删除任务及其下游痕迹",
            stage_name=task.current_stage,
            payload={
                "force_delete": force_delete,
                "downstream_ref_count": len(downstream_refs),
                "stage_item_count": len(stage_items),
                "cleanup_counts": cleanup_counts,
            },
        )
        db.commit()

        cleanup_status = await self._cleanup_task_workspace(task, token=token)
        if cleanup_status != "deleted":
            self._set_task_status(
                db,
                task,
                task_manager_module.TASK_STATUS_DELETE_FAILED,
                reason="删除任务时任务目录清理失败",
                source="task_operation",
                stage_name=task.current_stage,
            )
            task.finished_at = task_manager_module._now()
            task.last_error = "任务目录清理失败"
            self._record_event(
                db,
                task,
                "task_delete_failed",
                "删除失败，任务目录清理失败",
                stage_name=task.current_stage,
                level="error",
                payload={
                    "force_delete": force_delete,
                    "workspace_cleanup_status": cleanup_status,
                },
            )
            db.commit()
            raise ValidationError("任务目录清理失败")

        deleted_downstream_count = sum(
            1
            for result in downstream_cleanup_results
            if str(result.get("delete_status") or "").strip().lower() in {"succeeded", "missing", "not_found"}
            and not bool(result.get("deferred"))
        )
        cleanup_result = {
            "downstream_cleanup_results": downstream_cleanup_results,
            "downstream_cleanup_deferred_refs": downstream_cleanup_deferred_refs,
            "downstream_cleanup_blocking_refs": downstream_cleanup_blocking_refs,
            "cleanup_partial_failed": bool(downstream_cleanup_deferred_refs or downstream_cleanup_blocking_refs),
            "deleted_downstream_count": deleted_downstream_count,
            "cleanup_counts": cleanup_counts,
            "workspace_cleanup_status": cleanup_status,
        }
        if operation is not None:
            self._update_operation_result_payload(
                operation,
                {"cleanup_result": cleanup_result},
                workspace_root=task.workspace_root,
            )

        if downstream_cleanup_deferred_refs or downstream_cleanup_blocking_refs:
            cleanup_error = next(
                (
                    str(row.get("error") or row.get("deferred_reason") or "").strip()
                    for row in downstream_cleanup_deferred_refs + downstream_cleanup_blocking_refs
                    if str(row.get("error") or row.get("deferred_reason") or "").strip()
                ),
                None,
            ) or "下游删除未完成"
            self._set_task_status(
                db,
                task,
                task_manager_module.TASK_STATUS_DELETE_FAILED,
                reason="删除任务时下游子任务尚未完成删除确认",
                source="task_operation",
                stage_name=task.current_stage,
            )
            task.finished_at = task_manager_module._now()
            task.last_error = cleanup_error
            self._record_event(
                db,
                task,
                "task_delete_failed",
                "删除失败，下游子任务尚未完成删除确认",
                stage_name=task.current_stage,
                level="error",
                payload=cleanup_result,
            )
            db.commit()
            raise ValidationError("删除失败，下游子任务尚未完成删除确认")

        db.delete(task)
        self._record_event(
            db,
            task,
            f"{event_prefix}_completed",
            "任务删除完成",
            stage_name=task.current_stage,
            payload={
                "force_delete": force_delete,
                "deleted_downstream_count": deleted_downstream_count,
                "cleanup_counts": cleanup_counts,
            },
        )
        db.commit()

    async def _run_scheduled_coroutine(self: TaskManager, coro, *, label: str) -> None:
        from app.service import task_manager as task_manager_module

        try:
            await coro
        except Exception:
            task_manager_module.logger.exception("binary-security scheduled coroutine failed: %s", label)

    def _repair_active_operations_for_task(self: TaskManager, db: Session, task) -> bool:
        from app.service import task_manager as task_manager_module

        active_operations = [
            operation
            for operation in db.query(task_manager_module.BinarySecurityTaskOperation)
            .filter(task_manager_module.BinarySecurityTaskOperation.task_id == task.id)
            .all()
            if str(getattr(operation, "status", "") or "").strip().lower() not in task_manager_module.TASK_OPERATION_TERMINAL_STATUSES
        ]
        if not active_operations:
            return False

        active_operations.sort(
            key=lambda operation: (
                getattr(operation, "updated_at", None) or getattr(operation, "created_at", None) or task_manager_module._now(),
                getattr(operation, "created_at", None) or task_manager_module._now(),
                str(getattr(operation, "id", "") or ""),
            ),
            reverse=True,
        )
        authoritative = active_operations[0]
        changed = False
        if str(getattr(task, "current_operation_id", "") or "").strip() != str(getattr(authoritative, "id", "") or "").strip():
            task.current_operation_id = authoritative.id
            changed = True

        for superseded in active_operations[1:]:
            if str(getattr(superseded, "status", "") or "").strip().lower() == "superseded":
                continue
            superseded.status = "superseded"
            superseded.finished_at = task_manager_module._now()
            superseded.superseded_by_operation_id = authoritative.id
            self._record_operation_event(
                db,
                task,
                superseded,
                "operation_superseded",
                f"后台操作已被新的 authoritative operation 收口: {authoritative.operation_type}",
                stage_name=superseded.target_stage,
                level="warning",
                payload={
                    "source": "task_owner",
                    "superseded_by_operation_id": authoritative.id,
                    "superseded_by_operation_type": authoritative.operation_type,
                },
            )
            task_manager_module.observe_control_operation_superseded(str(superseded.operation_type or "").strip() or "unknown")
            changed = True

        if changed:
            self._record_event(
                db,
                task,
                "task_operation_binding_repaired",
                "任务 owner 已修复 active operation 绑定",
                stage_name=getattr(authoritative, "target_stage", None),
                payload={
                    "source": "task_owner",
                    "current_operation_id": authoritative.id,
                    "active_operation_count": len(active_operations),
                },
            )
        return changed

    def _repair_replacement_binding_state_for_task(self: TaskManager, db: Session, task) -> bool:
        from app.service import task_manager as task_manager_module

        changed = False
        for item in db.query(task_manager_module.BinarySecurityStageItem).filter(
            task_manager_module.BinarySecurityStageItem.task_id == task.id
        ).all():
            replacement_state = self._replacement_in_progress_state(item)
            if not replacement_state["replacement_in_progress"]:
                continue
            current_task_id = str(getattr(item, "downstream_task_id", "") or "").strip() or None
            old_task_id = replacement_state["old_downstream_task_id"]
            if current_task_id and old_task_id and current_task_id != old_task_id:
                self._clear_replacement_in_progress(item)
                self._record_event(
                    db,
                    task,
                    "replacement_binding_repaired",
                    "任务 owner 已修复 replacement 脏状态并确认新的 authoritative child 绑定",
                    stage_name=item.stage_name,
                    item=item,
                    payload={
                        "source": "task_owner",
                        "old_downstream_task_id": old_task_id,
                        "current_downstream_task_id": current_task_id,
                        "repair_action": "clear_replacement_state",
                    },
                )
                changed = True
                continue
            if current_task_id and old_task_id and current_task_id == old_task_id and not replacement_state["binding_cleared"]:
                explicit_transition_type = str(replacement_state.get("transition_type") or "").strip().lower()
                if explicit_transition_type == self.CHILD_TRANSITION_DESTRUCTIVE_REBUILD:
                    self._mark_replacement_in_progress(
                        item,
                        old_downstream_task_id=old_task_id,
                        binding_cleared=True,
                        verification_status="pending",
                        transition_type=self.CHILD_TRANSITION_DESTRUCTIVE_REBUILD,
                    )
                    self._record_event(
                        db,
                        task,
                        "replacement_binding_repaired",
                        "任务 owner 已清理 replacement 残留，旧 child 绑定已标记为可重建",
                        stage_name=item.stage_name,
                        item=item,
                        payload={
                            "source": "task_owner",
                            "old_downstream_task_id": old_task_id,
                            "current_downstream_task_id": current_task_id,
                            "repair_action": "mark_binding_cleared",
                            "transition_type": self.CHILD_TRANSITION_DESTRUCTIVE_REBUILD,
                        },
                    )
                    changed = True
                else:
                    self._mark_in_place_child_restart(
                        item,
                        downstream_task_id=old_task_id,
                        verification_status=replacement_state["verification_status"] or "pending",
                    )
                    self._record_event(
                        db,
                        task,
                        "replacement_binding_repaired",
                        "任务 owner 已确认当前 child 为原地重启中的 authoritative child",
                        stage_name=item.stage_name,
                        item=item,
                        payload={
                            "source": "task_owner",
                            "old_downstream_task_id": old_task_id,
                            "current_downstream_task_id": current_task_id,
                            "repair_action": "preserve_in_place_binding",
                            "transition_type": self.CHILD_TRANSITION_IN_PLACE_RESTART,
                        },
                    )
                    changed = True
        return changed

    async def _run_task_runtime_signals(self: TaskManager, task_id: str) -> bool:
        from app.service import task_manager as task_manager_module

        session_factory = task_manager_module.get_session_factory()
        db = session_factory()
        try:
            task = (
                db.query(task_manager_module.BinarySecurityTask)
                .filter(task_manager_module.BinarySecurityTask.id == task_id)
                .first()
            )
            if task is None:
                return False
            self._ensure_task_write_ownership(task, db=db, allow_dispatching=True)
            workset = self._task_runtime_workset(task)
            if not workset:
                return False
            if workset.get("pending_operation_repair"):
                self._clear_task_runtime_signal(task, "pending_operation_repair")
                changed = self._repair_active_operations_for_task(db, task)
                db.commit()
                return changed
            if workset.get("pending_cleanup_retry"):
                self._clear_task_runtime_signal(task, "pending_cleanup_retry")
                db.commit()
                await self._reconcile_deferred_cleanup_task_ref(
                    {"project_id": task.project_id, "task_id": task.id},
                    self._service_token(),
                )
                return True
            if workset.get("pending_archive_rebuild"):
                signal = dict(workset.get("pending_archive_rebuild") or {})
                stage_name = str(signal.get("stage_name") or "").strip() or None
                self._clear_task_runtime_signal(task, "pending_archive_rebuild")
                db.commit()
                if not stage_name:
                    return True
                rebuild_db = session_factory()
                try:
                    rebuild_task = (
                        rebuild_db.query(task_manager_module.BinarySecurityTask)
                        .filter(task_manager_module.BinarySecurityTask.id == task.id)
                        .first()
                    )
                    if rebuild_task is None:
                        return False
                    self._ensure_task_write_ownership(rebuild_task, db=rebuild_db, allow_dispatching=True)
                    await self._prepare_archive_retry_full(rebuild_db, rebuild_task, stage_name)
                    rebuild_db.commit()
                finally:
                    rebuild_db.close()
                return True
            if workset.get("pending_tail_finalize"):
                self._clear_task_runtime_signal(task, "pending_tail_finalize")
                db.commit()
                finalize_db = session_factory()
                try:
                    finalize_task = (
                        finalize_db.query(task_manager_module.BinarySecurityTask)
                        .filter(task_manager_module.BinarySecurityTask.id == task.id)
                        .first()
                    )
                    if finalize_task is None:
                        return False
                    self._ensure_task_write_ownership(finalize_task, db=finalize_db, allow_dispatching=True)
                    self._finalize_task(finalize_db, finalize_task)
                    finalize_db.commit()
                finally:
                    finalize_db.close()
                return True
            if workset.get("pending_binding_repair") or workset.get("pending_downstream_sync"):
                signal = dict(workset.get("pending_binding_repair") or workset.get("pending_downstream_sync") or {})
                stage_name = str(signal.get("stage_name") or "").strip() or None
                item_ids = [
                    str(item_id).strip()
                    for item_id in list(signal.get("item_ids") or [])
                    if str(item_id).strip()
                ]
                force = bool(signal.get("force"))
                self._clear_task_runtime_signal(task, "pending_binding_repair")
                self._clear_task_runtime_signal(task, "pending_downstream_sync")
                repaired = self._repair_replacement_binding_state_for_task(db, task)
                db.commit()
                if repaired:
                    return True
                sync_db = session_factory()
                try:
                    await self.sync_downstream_status(
                        sync_db,
                        project_id=task.project_id,
                        task_id=task.id,
                        stage_name=stage_name,
                        item_ids=item_ids or None,
                        force=force,
                        token=self._service_token(),
                        record_request_event=False,
                        apply_state=True,
                    )
                finally:
                    sync_db.close()
                return True
            return False
        except task_manager_module.StaleTaskExecution:
            db.rollback()
            return False
        finally:
            db.close()

    async def _run_current_task_operation(self: TaskManager, task_id: str) -> bool:
        from app.service import task_manager as task_manager_module

        session_factory = task_manager_module.get_session_factory()
        db = session_factory()
        started = time.perf_counter()
        operation_type = "unknown"
        task_deleted = False
        try:
            task = (
                db.query(task_manager_module.BinarySecurityTask)
                .filter(task_manager_module.BinarySecurityTask.id == task_id)
                .first()
            )
            if task is None:
                return False
            self._ensure_task_write_ownership(task, db=db, allow_dispatching=True)
            current_operation_id = str(getattr(task, "current_operation_id", "") or "").strip()
            task_manager_module.logger.info(
                "binary-security task owner evaluating current operation: "
                "task_id=%s current_operation_id=%s status=%s runtime_phase=%s dispatcher_instance_id=%s",
                task_id,
                current_operation_id or None,
                str(getattr(task, "status", "") or "").strip(),
                self._task_runtime_phase(task),
                str(getattr(task, "dispatcher_instance_id", "") or "").strip() or None,
            )
            if not current_operation_id:
                if self._repair_active_operations_for_task(db, task):
                    task_manager_module.logger.warning(
                        "binary-security task owner repaired active operation binding before execution: "
                        "task_id=%s repaired_current_operation_id=%s",
                        task_id,
                        str(getattr(task, "current_operation_id", "") or "").strip() or None,
                    )
                    db.commit()
                    return True
                return False
            operation = (
                db.query(task_manager_module.BinarySecurityTaskOperation)
                .filter(task_manager_module.BinarySecurityTaskOperation.id == current_operation_id)
                .first()
            )
            if operation is None:
                task_manager_module.logger.warning(
                    "binary-security task owner found dangling current_operation_id and cleared it: "
                    "task_id=%s current_operation_id=%s",
                    task_id,
                    current_operation_id,
                )
                task.current_operation_id = None
                db.commit()
                return False
            if str(getattr(operation, "status", "") or "").strip().lower() in task_manager_module.TASK_OPERATION_TERMINAL_STATUSES:
                if str(getattr(task, "current_operation_id", "") or "").strip() == operation.id:
                    task_manager_module.logger.info(
                        "binary-security task owner observed terminal operation and cleared binding: "
                        "task_id=%s operation_id=%s operation_status=%s",
                        task_id,
                        operation.id,
                        str(getattr(operation, "status", "") or "").strip().lower(),
                    )
                    task.current_operation_id = None
                    db.commit()
                return False

            operation_type = operation.operation_type
            should_record_start = str(getattr(operation, "status", "") or "").strip().lower() != "running"
            now_value = task_manager_module._now()
            self._capture_blocking_operation_task_snapshot(task, operation)
            operation.status = "running"
            operation.updated_at = now_value
            if getattr(operation, "started_at", None) is None:
                operation.started_at = now_value
            task.current_operation_id = operation.id
            if should_record_start:
                self._record_operation_event(
                    db,
                    task,
                    operation,
                    "operation_started",
                    f"任务 owner 已开始串行执行后台操作: {operation.operation_type}",
                    stage_name=operation.target_stage,
                    payload={"source": "task_owner"},
                )
            db.commit()
            task_manager_module.logger.info(
                "binary-security task owner started operation execution: "
                "task_id=%s operation_id=%s operation_type=%s operation_status=%s current_step=%s",
                task_id,
                operation.id,
                str(operation.operation_type or "").strip(),
                str(operation.status or "").strip(),
                str(getattr(operation, "current_step", "") or "").strip() or None,
            )

            await self._run_task_operation_steps(db, task, operation)
            try:
                self._ensure_task_write_ownership(task, db=db, allow_dispatching=True)
            except task_manager_module.StaleTaskExecution:
                if operation.operation_type in self._operation_requeue_family_types() and self._finalize_task_operation_after_requeue(
                    db,
                    task_id=task_id,
                    operation_id=operation.id,
                    finalize_event_type="operation_finalize_after_owner_handoff",
                    finalize_message="后台操作在 owner 切换后已完成控制面收口",
                    source="task_owner_handoff",
                ):
                    db.commit()
                    task_manager_module.logger.info(
                        "binary-security task owner finalized operation after ownership handoff: "
                        "task_id=%s operation_id=%s operation_type=%s",
                        task_id,
                        operation.id,
                        str(operation.operation_type or "").strip(),
                    )
                    task_manager_module.observe_control_operation(operation_type, "succeeded")
                    return True
                raise

            if operation.operation_type == task_manager_module.TASK_ACTION_DELETE:
                task_deleted = (
                    db.query(task_manager_module.BinarySecurityTask.id)
                    .filter(task_manager_module.BinarySecurityTask.id == operation.task_id)
                    .first()
                    is None
                )

            operation.status = "succeeded"
            operation.current_step = task_manager_module.TASK_OPERATION_STEP_SUCCEEDED
            operation.finished_at = task_manager_module._now()
            if not task_deleted:
                refreshed_task = (
                    db.query(task_manager_module.BinarySecurityTask)
                    .filter(task_manager_module.BinarySecurityTask.id == task_id)
                    .first()
                )
                if refreshed_task is not None and str(getattr(refreshed_task, "current_operation_id", "") or "").strip() == operation.id:
                    refreshed_task.current_operation_id = None
                if refreshed_task is not None:
                    if operation.operation_type in self._operation_requeue_family_types():
                        self._record_operation_event(
                            db,
                            refreshed_task,
                            operation,
                            "operation_finalize_after_requeue",
                            "后台操作已在重排队后完成控制面收口",
                            stage_name=operation.target_stage,
                            payload={"source": "task_owner", "auto_reconciled": False},
                        )
                    self._record_operation_event(
                        db,
                        refreshed_task,
                        operation,
                        "operation_succeeded",
                        f"任务 owner 已完成后台操作: {operation.operation_type}",
                        stage_name=operation.target_stage,
                        payload={"source": "task_owner", "auto_reconciled": False},
                    )
            db.commit()
            task_manager_module.logger.info(
                "binary-security task owner finished operation execution: "
                "task_id=%s operation_id=%s operation_type=%s final_status=%s current_step=%s",
                task_id,
                operation.id,
                str(operation.operation_type or "").strip(),
                str(operation.status or "").strip(),
                str(getattr(operation, "current_step", "") or "").strip() or None,
            )
            task_manager_module.observe_control_operation(operation_type, "succeeded")
            return True
        except task_manager_module.StaleTaskExecution:
            task_manager_module.logger.warning(
                "binary-security task owner stopped operation consumption because task ownership became stale: "
                "task_id=%s current_operation_id=%s",
                task_id,
                str(current_operation_id if "current_operation_id" in locals() else "") or None,
            )
            return False
        except Exception as exc:
            db.rollback()
            task_manager_module.logger.exception(
                "binary-security task owner operation execution crashed: task_id=%s current_operation_id=%s",
                task_id,
                str(current_operation_id if "current_operation_id" in locals() else "") or None,
            )
            operation = (
                db.query(task_manager_module.BinarySecurityTaskOperation)
                .filter(task_manager_module.BinarySecurityTaskOperation.id == str(current_operation_id if 'current_operation_id' in locals() else ""))
                .first()
                if 'current_operation_id' in locals() and current_operation_id
                else None
            )
            if operation is not None:
                operation_type = operation.operation_type
                operation.status = "failed"
                operation.error_code = "operation_failed"
                operation.error_message = str(exc)
                operation.finished_at = task_manager_module._now()
            task = (
                db.query(task_manager_module.BinarySecurityTask)
                .filter(task_manager_module.BinarySecurityTask.id == getattr(operation, "task_id", task_id))
                .first()
            )
            if task is not None:
                if operation is not None and operation.operation_type == task_manager_module.TASK_ACTION_DELETE:
                    self._set_task_status(
                        db,
                        task,
                        task_manager_module.TASK_STATUS_DELETE_FAILED,
                        reason="后台操作执行异常，删除任务失败",
                        source="task_operation",
                        stage_name=task.current_stage,
                    )
                    task.finished_at = task_manager_module._now()
                    task.current_operation_id = operation.id
                elif operation is not None and str(getattr(task, "current_operation_id", "") or "").strip() == operation.id:
                    task.current_operation_id = None
                if operation is not None:
                    self._restore_failed_blocking_operation_task_snapshot(task, operation)
                task.last_error = str(exc)
                if operation is not None:
                    self._record_operation_event(
                        db,
                        task,
                        operation,
                        "operation_failed",
                        f"任务 owner 执行后台操作失败: {exc}",
                        level="error",
                        stage_name=operation.target_stage,
                        payload={"source": "task_owner"},
                    )
                if operation is not None and operation.operation_type == task_manager_module.TASK_ACTION_DELETE:
                    self._record_event(
                        db,
                        task,
                        "task_delete_failed",
                        "删除失败，任务已保留为 delete_failed",
                        stage_name=operation.target_stage,
                        level="error",
                        payload={
                            "failure_reason": "delete_operation_failed",
                            "operation_id": operation.id,
                            "operation_error": str(exc),
                            "force_delete": bool(dict(operation.request_payload or {}).get("force_delete")),
                            "source": "task_owner",
                        },
                    )
            db.commit()
            task_manager_module.observe_control_operation(operation_type, "failed")
            return True
        finally:
            task_manager_module.observe_control_operation_duration(
                operation_type=operation_type,
                status="finished",
                duration_seconds=time.perf_counter() - started,
            )
            db.close()

    def _operation_requeue_family_types(self: TaskManager) -> set[str]:
        from app.service import task_manager as task_manager_module

        return {
            task_manager_module.TASK_ACTION_CONTINUE,
            task_manager_module.TASK_ACTION_RETRY,
            task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS,
            task_manager_module.TASK_ACTION_RETRY_STAGE_FULL,
            task_manager_module.TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
        }

    def _operation_stale_threshold_seconds(self: TaskManager) -> int:
        configured = int(getattr(self.cfg.scheduler, "stale_operation_requeue_interval_seconds", 30) or 30)
        return max(15, configured)

    def _task_operation_age_seconds(self: TaskManager, operation: BinarySecurityTaskOperation) -> float | None:
        started_at = getattr(operation, "updated_at", None) or getattr(operation, "started_at", None) or getattr(operation, "created_at", None)
        return task_shared._elapsed_seconds_since(started_at)

    def _operation_requeue_payload_snapshot(
        self: TaskManager,
        task: BinarySecurityTask,
        *,
        target_stage: str | None,
        in_place_runtime_resume: bool,
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        now_value = task_manager_module._now()
        return {
            "requested": True,
            "applied": True,
            "applied_at": task_shared._isoformat_or_none(now_value),
            "task_status_after": str(getattr(task, "status", "") or "").strip() or None,
            "runtime_phase_after": self._task_runtime_phase(task),
            "current_stage_after": str(target_stage or getattr(task, "current_stage", "") or "").strip() or None,
            "in_place_runtime_resume": bool(in_place_runtime_resume),
        }

    def _mark_operation_requeue_applied(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
        *,
        target_stage: str | None,
        in_place_runtime_resume: bool,
        extra_payload: dict[str, Any] | None = None,
        record_event: bool = True,
    ) -> dict[str, Any]:
        requeue_payload = {
            **self._operation_requeue_payload_snapshot(
                task,
                target_stage=target_stage,
                in_place_runtime_resume=in_place_runtime_resume,
            ),
            **dict(extra_payload or {}),
        }
        merged = self._update_operation_result_payload(
            operation,
            {"requeue": requeue_payload},
            workspace_root=task.workspace_root,
        )
        if record_event:
            self._record_operation_event(
                db,
                task,
                operation,
                "operation_requeue_applied",
                "后台操作已完成重排队并生成恢复快照",
                stage_name=target_stage or operation.target_stage,
                payload={
                    "operation_id": operation.id,
                    "operation_type": operation.operation_type,
                    "current_step": operation.current_step,
                    "task_status": str(getattr(task, "status", "") or "").strip(),
                    "runtime_phase": self._task_runtime_phase(task),
                    "in_place_runtime_resume": bool(in_place_runtime_resume),
                    "auto_reconciled": False,
                    "requeue": requeue_payload,
                },
            )
        return merged

    def _operation_requeue_applied(
        self: TaskManager,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
    ) -> bool:
        from app.service import task_manager as task_manager_module

        result_payload = dict(self._operation_result_data(operation) or {})
        requeue_payload = dict(result_payload.get("requeue") or {})
        if not bool(requeue_payload.get("requested")) or not bool(requeue_payload.get("applied")):
            return False
        target_stage = str(
            requeue_payload.get("current_stage_after")
            or operation.target_stage
            or task.current_stage
            or ""
        ).strip() or None
        in_place_runtime_resume = bool(requeue_payload.get("in_place_runtime_resume"))
        task_status = str(task.status or "").strip()
        if in_place_runtime_resume:
            if task_status not in {"running", "dispatching"}:
                return False
            if self._task_runtime_phase(task) != task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION:
                return False
        elif task_status != "pending":
            return False
        if target_stage and str(task.current_stage or "").strip() != target_stage:
            return False
        if task.last_error not in {None, ""}:
            return False
        return True

    def _finalize_task_operation_after_requeue(
        self: TaskManager,
        db: Session,
        *,
        task_id: str,
        operation_id: str,
        finalize_event_type: str,
        finalize_message: str,
        source: str,
        auto_reconciled: bool = False,
    ) -> bool:
        from app.service import task_manager as task_manager_module

        refreshed_operation = (
            db.query(task_manager_module.BinarySecurityTaskOperation)
            .filter(task_manager_module.BinarySecurityTaskOperation.id == operation_id)
            .first()
        )
        if refreshed_operation is None:
            return False
        if str(getattr(refreshed_operation, "status", "") or "").strip().lower() in task_manager_module.TASK_OPERATION_TERMINAL_STATUSES:
            return False
        refreshed_task = (
            db.query(task_manager_module.BinarySecurityTask)
            .filter(task_manager_module.BinarySecurityTask.id == task_id)
            .first()
        )
        if refreshed_task is None:
            return False
        if str(getattr(refreshed_operation, "task_id", "") or "").strip() != str(task_id or "").strip():
            return False
        if str(getattr(refreshed_task, "current_operation_id", "") or "").strip() not in {"", operation_id}:
            return False
        if not self._operation_requeue_applied(refreshed_task, refreshed_operation) and str(getattr(refreshed_operation, "current_step", "") or "").strip() != task_manager_module.TASK_OPERATION_STEP_SUCCEEDED:
            return False
        refreshed_operation.status = "succeeded"
        refreshed_operation.current_step = task_manager_module.TASK_OPERATION_STEP_SUCCEEDED
        refreshed_operation.finished_at = task_manager_module._now()
        refreshed_operation.updated_at = refreshed_operation.finished_at
        if str(getattr(refreshed_task, "current_operation_id", "") or "").strip() == operation_id:
            refreshed_task.current_operation_id = None
        payload = {
            "operation_id": refreshed_operation.id,
            "operation_type": refreshed_operation.operation_type,
            "current_step": refreshed_operation.current_step,
            "task_status": str(getattr(refreshed_task, "status", "") or "").strip(),
            "runtime_phase": self._task_runtime_phase(refreshed_task),
            "in_place_runtime_resume": bool(dict(self._operation_result_data(refreshed_operation) or {}).get("requeue", {}).get("in_place_runtime_resume")),
            "previous_owner": str(getattr(refreshed_task, "dispatcher_instance_id", "") or "").strip() or None,
            "current_owner": str(getattr(refreshed_task, "dispatcher_instance_id", "") or "").strip() or None,
            "auto_reconciled": bool(auto_reconciled),
            "source": source,
        }
        self._record_operation_event(
            db,
            refreshed_task,
            refreshed_operation,
            finalize_event_type,
            finalize_message,
            stage_name=refreshed_operation.target_stage,
            payload=payload,
        )
        self._record_operation_event(
            db,
            refreshed_task,
            refreshed_operation,
            "operation_succeeded",
            f"任务 owner 已完成后台操作: {refreshed_operation.operation_type}",
            stage_name=refreshed_operation.target_stage,
            payload={"source": source, "auto_reconciled": bool(auto_reconciled)},
        )
        return True

    def _reconcile_stale_task_operation(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
    ) -> bool:
        from app.service import task_manager as task_manager_module

        operation_type = str(getattr(operation, "operation_type", "") or "").strip()
        if operation_type not in self._operation_requeue_family_types():
            return False
        age_seconds = self._task_operation_age_seconds(operation)
        if age_seconds is None or age_seconds < float(self._operation_stale_threshold_seconds()):
            return False
        task_manager_module.observe_control_operation_stale(operation_type, age_seconds=age_seconds)
        if self._operation_requeue_applied(task, operation):
            finalized = self._finalize_task_operation_after_requeue(
                db,
                task_id=task.id,
                operation_id=operation.id,
                finalize_event_type="operation_reconciled_to_succeeded",
                finalize_message="检测到重排队已生效，系统已自动收口后台操作",
                source="reconcile",
                auto_reconciled=True,
            )
            if finalized:
                task_manager_module.observe_control_operation_auto_reconciled(operation_type, "succeeded", age_seconds=age_seconds)
            return finalized
        current_operation_id = str(getattr(task, "current_operation_id", "") or "").strip()
        if current_operation_id in {"", operation.id} and str(getattr(task, "status", "") or "").strip() in {"pending", "dispatching", "running"}:
            self._enqueue_task(task.id)
            self._record_operation_event(
                db,
                task,
                operation,
                "operation_requeued_for_resume",
                "检测到后台操作停滞，系统已重新投递任务以恢复执行",
                stage_name=operation.target_stage,
                payload={
                    "operation_id": operation.id,
                    "operation_type": operation.operation_type,
                    "current_step": operation.current_step,
                    "task_status": str(getattr(task, "status", "") or "").strip(),
                    "runtime_phase": self._task_runtime_phase(task),
                    "auto_reconciled": True,
                },
            )
            return True
        if current_operation_id not in {"", operation.id}:
            return False
        operation.status = "failed"
        operation.error_code = "operation_stale_reconciled"
        operation.error_message = "operation stalled before requeue was applied"
        operation.finished_at = task_manager_module._now()
        operation.updated_at = operation.finished_at
        if current_operation_id == operation.id:
            task.current_operation_id = None
        self._record_operation_event(
            db,
            task,
            operation,
            "operation_reconciled_to_failed",
            "检测到后台操作已停滞且未完成重排队，系统已自动收口为失败",
            level="warning",
            stage_name=operation.target_stage,
            payload={
                "operation_id": operation.id,
                "operation_type": operation.operation_type,
                "current_step": operation.current_step,
                "task_status": str(getattr(task, "status", "") or "").strip(),
                "runtime_phase": self._task_runtime_phase(task),
                "auto_reconciled": True,
            },
        )
        task_manager_module.observe_control_operation_auto_reconciled(operation_type, "failed", age_seconds=age_seconds)
        return True

    async def _run_task_operation_steps(self: TaskManager, db: Session, task, operation) -> None:
        from app.service import task_manager as task_manager_module

        resume_step = self._operation_resume_step(operation)
        if operation.operation_type == task_manager_module.TASK_ACTION_CANCEL:
            await self._run_cancel_operation_steps(db, task, operation, resume_step)
            return
        if operation.operation_type in {
            task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS,
            task_manager_module.TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
        }:
            await self._run_retry_failed_items_operation_steps(db, task, operation, resume_step)
            return
        if operation.operation_type == task_manager_module.TASK_ACTION_RETRY_STAGE_FULL:
            resume_step = await self._run_retry_stage_full_operation_steps(db, task, operation, resume_step)
        else:
            prepare_step = task_manager_module.TASK_OPERATION_STEP_COLLECT_CLEANUP_PLAN
            if resume_step == prepare_step:
                self._record_operation_step_started(
                    db,
                    task,
                    operation,
                    step_name=prepare_step,
                    message=f"后台操作开始执行准备步骤: {operation.operation_type}",
                    stage_name=operation.target_stage,
                    payload={"operation_type": operation.operation_type},
                )
                db.commit()
                try:
                    if operation.operation_type == task_manager_module.TASK_ACTION_CONTINUE:
                        await self._prepare_continue_task(db, task, str(operation.target_stage or "").strip())
                    elif operation.operation_type == task_manager_module.TASK_ACTION_RETRY:
                        await self._prepare_retry_task(db, task)
                    elif operation.operation_type in {
                        task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS,
                        task_manager_module.TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
                    }:
                        await self._prepare_retry_failed_items(db, task, str(operation.target_stage or "").strip())
                    elif operation.operation_type == task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FAILED_ITEMS:
                        await self._prepare_archive_retry_failed_items(db, task, str(operation.target_stage or "").strip())
                    elif operation.operation_type == task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FULL:
                        await self._prepare_archive_retry_full(db, task, str(operation.target_stage or "").strip())
                    elif operation.operation_type == task_manager_module.TASK_ACTION_DELETE:
                        await self._prepare_delete_task(db, task)
                        self._record_operation_step_finished(
                            db,
                            task,
                            operation,
                            step_name=prepare_step,
                            message=f"后台操作准备步骤已完成: {operation.operation_type}",
                            stage_name=operation.target_stage,
                            next_step=task_manager_module.TASK_OPERATION_STEP_SUCCEEDED,
                        )
                        operation.current_step = task_manager_module.TASK_OPERATION_STEP_SUCCEEDED
                        db.commit()
                        return
                    else:
                        raise ValidationError(f"未知操作类型: {operation.operation_type}")
                except Exception as exc:
                    self._record_operation_step_failed(
                        db,
                        task,
                        operation,
                        step_name=prepare_step,
                        error=exc,
                        stage_name=operation.target_stage,
                    )
                    db.commit()
                    raise

                if operation.operation_type in {
                    task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS,
                    task_manager_module.TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
                }:
                    prepare_result = self._build_retry_prepare_result(
                        db,
                        task,
                        target_stage=str(operation.target_stage or "").strip(),
                    )
                    self._update_operation_result_payload(
                        operation,
                        prepare_result,
                        workspace_root=task.workspace_root,
                    )
                    validation = dict(prepare_result.get("validation") or {})
                    if not bool(validation.get("validated")):
                        self._record_operation_event(
                            db,
                            task,
                            operation,
                            "retry_prepare_validation_failed",
                            "失败项重试准备校验失败",
                            level="error",
                            stage_name=operation.target_stage,
                            payload=prepare_result,
                        )
                        raise ValidationError("失败项重试准备校验失败")
                    self._record_operation_event(
                        db,
                        task,
                        operation,
                        "retry_prepare_validation_succeeded",
                        "失败项重试准备校验通过",
                        stage_name=operation.target_stage,
                        payload=prepare_result,
                    )

                requeue_required = operation.operation_type not in {
                    task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FAILED_ITEMS,
                    task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FULL,
                }
                next_step = (
                    task_manager_module.TASK_OPERATION_STEP_VERIFY_CLEANUP_STATE
                    if requeue_required and operation.operation_type == task_manager_module.TASK_ACTION_RETRY
                    else (
                        task_manager_module.TASK_OPERATION_STEP_REQUEUE_TASK
                        if requeue_required
                        else task_manager_module.TASK_OPERATION_STEP_SUCCEEDED
                    )
                )
                self._record_operation_step_finished(
                    db,
                    task,
                    operation,
                    step_name=prepare_step,
                    message=f"后台操作准备步骤已完成: {operation.operation_type}",
                    stage_name=operation.target_stage,
                    payload=(
                        self._operation_result_data(operation)
                        if operation.operation_type in {
                            task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS,
                            task_manager_module.TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
                        }
                        else None
                    ),
                    next_step=next_step,
                )
                if not requeue_required:
                    db.commit()
                    return
                resume_step = next_step

        if resume_step == task_manager_module.TASK_OPERATION_STEP_VERIFY_CLEANUP_STATE:
            self._record_operation_step_started(
                db,
                task,
                operation,
                step_name=task_manager_module.TASK_OPERATION_STEP_VERIFY_CLEANUP_STATE,
                message=f"后台操作进入清空校验步骤: {operation.operation_type}",
                stage_name=operation.target_stage or task.current_stage,
            )
            db.commit()
            try:
                payload = await self._operation_verify_retry_cleanup_state(db, task, operation)
            except Exception as exc:
                self._record_operation_step_failed(
                    db,
                    task,
                    operation,
                    step_name=task_manager_module.TASK_OPERATION_STEP_VERIFY_CLEANUP_STATE,
                    error=exc,
                    stage_name=operation.target_stage or task.current_stage,
                )
                db.commit()
                raise
            self._record_operation_step_finished(
                db,
                task,
                operation,
                step_name=task_manager_module.TASK_OPERATION_STEP_VERIFY_CLEANUP_STATE,
                message=f"后台操作清空校验步骤已完成: {operation.operation_type}",
                stage_name=operation.target_stage or task.current_stage,
                payload=payload,
                next_step=task_manager_module.TASK_OPERATION_STEP_REQUEUE_TASK,
            )
            db.commit()
            resume_step = task_manager_module.TASK_OPERATION_STEP_REQUEUE_TASK

        if resume_step != task_manager_module.TASK_OPERATION_STEP_REQUEUE_TASK:
            return

        if self._is_operation_requeue_state_applied(task, operation):
            self._record_operation_step_finished(
                db,
                task,
                operation,
                step_name=task_manager_module.TASK_OPERATION_STEP_REQUEUE_TASK,
                message=f"后台操作重新排队步骤已确认完成，无需重复执行: {operation.operation_type}",
                stage_name=operation.target_stage,
                payload={"idempotent_recovery": True},
                next_step=task_manager_module.TASK_OPERATION_STEP_SUCCEEDED,
            )
            db.commit()
            return

        self._record_operation_step_started(
            db,
            task,
            operation,
            step_name=task_manager_module.TASK_OPERATION_STEP_REQUEUE_TASK,
            message=f"后台操作进入重新排队步骤: {operation.operation_type}",
            stage_name=operation.target_stage,
        )
        decision = self._decide_task_resume_after_stage_reset(
            db,
            task,
            next_stage=operation.target_stage or task.current_stage,
            resume_reason="task_operation_requeue",
            source=str(operation.operation_type or "").strip() or "task_operation",
            message=f"后台操作完成，任务已重新排队: {operation.operation_type}",
            payload={"operation_type": operation.operation_type},
        )
        if not decision.should_resume:
            self._record_operation_event(
                db,
                task,
                operation,
                decision.event_type or "task_resume_blocked",
                "后台操作完成，但当前仍不满足重新排队条件",
                level="warning",
                stage_name=operation.target_stage or task.current_stage,
                payload=dict(decision.payload or {}),
            )
            raise ValidationError("后台操作完成，但当前仍不满足重新排队条件")
        self._apply_task_resume_decision(db, task, decision, operation=operation)
        self._record_operation_step_finished(
            db,
            task,
            operation,
            step_name=task_manager_module.TASK_OPERATION_STEP_REQUEUE_TASK,
            message=f"后台操作重新排队步骤已完成: {operation.operation_type}",
            stage_name=operation.target_stage,
            next_step=task_manager_module.TASK_OPERATION_STEP_SUCCEEDED,
        )
        db.commit()

    def _is_operation_requeue_state_applied(
        self: TaskManager,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
    ) -> bool:
        return self._operation_requeue_applied(task, operation)

    def _can_resume_retry_operation_in_place(
        self: TaskManager,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
    ) -> bool:
        operation_type = str(getattr(operation, "operation_type", "") or "").strip()
        if operation_type not in {
            task_manager_module.TASK_ACTION_RETRY,
            task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS,
            task_manager_module.TASK_ACTION_RETRY_STAGE_FULL,
            task_manager_module.TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
        }:
            return False
        if str(getattr(task, "dispatcher_instance_id", "") or "").strip() != str(self.instance_id or "").strip():
            return False
        if not self._lease_is_active(task, db=None):
            return False
        return self._task_owner_runtime_supported_locally(task, active_operation=operation)

    def _requeue_task_after_retry_operation(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        target_stage: str | None,
        operation: BinarySecurityTaskOperation,
    ) -> None:
        resume_decision = self._decide_task_resume_after_stage_reset(
            db,
            task,
            next_stage=target_stage or task.current_stage,
            resume_reason="retry_operation_requeue",
            source=str(operation.operation_type or "").strip() or "retry_operation",
            message=f"失败项重试完成，任务已重新排队: {operation.operation_type}",
            payload={"operation_id": operation.id},
        )
        resume_decision.event_type = "task_requeued"
        if self._can_resume_retry_operation_in_place(task, operation):
            self._set_task_status(
                db,
                task,
                "running",
                reason="失败项重试完成，当前 runtime 原地继续推进任务",
                source="task_operation",
                stage_name=target_stage or task.current_stage,
            )
            task.current_stage = target_stage or task.current_stage
            task.last_error = None
            task.finished_at = None
            task.summary = self._clear_failure_fields_from_summary(dict(task.summary or {}))
            self._clear_task_abnormal_reason_snapshot(db, task)
            self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
            self._update_operation_result_payload(
                operation,
                {},
                workspace_root=task.workspace_root,
            )
            self._mark_operation_requeue_applied(
                db,
                task,
                operation,
                target_stage=target_stage or task.current_stage,
                in_place_runtime_resume=True,
                extra_payload={
                    "task_status_before": "retry_operation_succeeded",
                    "resume_reason": resume_decision.resume_reason,
                    "source": resume_decision.source,
                },
            )
            self._record_operation_event(
                db,
                task,
                operation,
                "task_requeued",
                f"失败项重试完成，当前 runtime 将继续推进任务: {operation.operation_type}",
                stage_name=operation.target_stage,
                payload={
                    "next_stage": task.current_stage,
                    "resume_reason": resume_decision.resume_reason,
                    "source": resume_decision.source,
                    "in_place_runtime_resume": True,
                },
            )
            return
        if not resume_decision.should_resume:
            self._set_task_status(
                db,
                task,
                "pending",
                reason="失败项重试完成，任务重新进入待调度",
                source="task_operation",
                stage_name=target_stage or task.current_stage,
            )
            task.current_stage = target_stage or task.current_stage
            task.last_error = None
            task.finished_at = None
            self._invalidate_task_execution(task)
            self._enqueue_task(task.id)
            self._mark_operation_requeue_applied(
                db,
                task,
                operation,
                target_stage=target_stage or task.current_stage,
                in_place_runtime_resume=False,
                extra_payload={
                    "task_status_before": "retry_operation_succeeded",
                },
                record_event=True,
            )
            self._record_operation_event(
                db,
                task,
                operation,
                "task_requeued",
                f"失败项重试完成，任务已重新排队: {operation.operation_type}",
                stage_name=operation.target_stage,
            )
            return
        self._apply_task_resume_decision(db, task, resume_decision, operation=operation)

    async def _run_cancel_operation_steps(self: TaskManager, db: Session, task, operation, resume_step: str) -> None:
        from app.service import task_manager as task_manager_module

        cancel_steps = task_manager_module.TASK_CANCEL_SAGA_STEPS
        current_step = (
            resume_step
            if resume_step in cancel_steps
            else task_manager_module.TASK_OPERATION_STEP_MARK_TASK_CANCELLING
        )
        step_order = {name: index for index, name in enumerate(cancel_steps)}

        async def _run_step(step_name: str, *, message: str, next_step: str | None, fn) -> Any:
            nonlocal current_step
            if step_order[current_step] > step_order[step_name]:
                return None
            self._record_operation_step_started(
                db,
                task,
                operation,
                step_name=step_name,
                message=message,
                stage_name=operation.target_stage,
                payload={"operation_type": operation.operation_type},
            )
            self._commit_or_rollback(db)
            try:
                result = await fn()
            except Exception as exc:
                self._record_operation_step_failed(
                    db,
                    task,
                    operation,
                    step_name=step_name,
                    error=exc,
                    stage_name=operation.target_stage,
                )
                self._commit_or_rollback(db)
                raise
            payload = result if isinstance(result, dict) else None
            self._record_operation_step_finished(
                db,
                task,
                operation,
                step_name=step_name,
                message=message,
                stage_name=operation.target_stage,
                payload=payload,
                next_step=next_step,
            )
            current_step = next_step or step_name
            self._commit_or_rollback(db)
            return result

        async def _mark_task_cancelling() -> dict[str, Any]:
            self._set_task_status(
                db,
                task,
                task_manager_module.TASK_STATUS_CANCELLING,
                reason="取消操作已开始，任务进入取消中",
                source="task_operation",
                stage_name=operation.target_stage,
            )
            task.finished_at = None
            task.last_error = None
            task.current_operation_id = operation.id
            self._record_operation_event(
                db,
                task,
                operation,
                "task_cancelling",
                "取消操作已开始，任务进入取消中",
                stage_name=operation.target_stage,
            )
            return {"task_status": task.status}

        async def _collect_targets() -> dict[str, Any]:
            targets = self._collect_cancel_targets(db, task)
            self._store_cancel_targets(operation, targets, workspace_root=task.workspace_root)
            for target in targets:
                self._record_operation_event(
                    db,
                    task,
                    operation,
                    "cancel_target_collected",
                    f"取消目标已纳入收敛检查: {self._cancel_target_display(target)}",
                    stage_name=str(target.get("stage_name") or operation.target_stage or "").strip() or None,
                    payload=dict(target),
                )
            return {"targets_total": len(targets)}

        async def _cancel_local() -> dict[str, Any]:
            cancelled_stages = await self._prepare_cancel_task(db, task)
            targets = [
                dict(target)
                for target in list(self._operation_result_data(operation).get("cancel_targets") or [])
                if isinstance(target, dict)
            ]
            for target in targets:
                if str(target.get("target_type") or "") == "local_worker":
                    target["cancel_request_status"] = "requested"
                    target["terminal_observation_status"] = "cancelled"
                    target["last_observed_at"] = task_manager_module._isoformat_or_none(task_manager_module._now())
            self._store_cancel_targets(operation, targets, workspace_root=task.workspace_root)
            return {"cancelled_stage_names": cancelled_stages}

        async def _cancel_downstream_targets() -> dict[str, Any]:
            targets = [
                dict(target)
                for target in list(self._operation_result_data(operation).get("cancel_targets") or [])
                if isinstance(target, dict)
            ]
            for target in targets:
                if str(target.get("target_type") or "") == "downstream_task":
                    target["cancel_request_status"] = "requested"
                    target["last_observed_at"] = task_manager_module._isoformat_or_none(task_manager_module._now())
            self._store_cancel_targets(operation, targets, workspace_root=task.workspace_root)
            return {
                "downstream_target_count": sum(
                    1 for target in targets if str(target.get("target_type") or "") == "downstream_task"
                )
            }

        async def _verify_quiesced() -> dict[str, Any]:
            timeout_seconds = self._cancel_verify_timeout_seconds()
            deadline = task_manager_module._now() + timedelta(seconds=timeout_seconds)
            token = self._service_token()
            last_blocking_snapshot: list[str] = []
            while True:
                refreshed_targets: list[dict[str, Any]] = []
                blocking_targets: list[dict[str, Any]] = []
                stored_targets = [
                    dict(target)
                    for target in list(self._operation_result_data(operation).get("cancel_targets") or [])
                    if isinstance(target, dict)
                ]
                task_items = {
                    item.id: item
                    for item in db.query(task_manager_module.BinarySecurityStageItem)
                    .filter(task_manager_module.BinarySecurityStageItem.task_id == task.id)
                    .all()
                }
                for target in stored_targets:
                    target_type = str(target.get("target_type") or "").strip()
                    previous_observed_status = str(target.get("terminal_observation_status") or "unknown")
                    observed_status = previous_observed_status
                    if target_type == "local_worker":
                        local_worker = self._workers.get(task.id)
                        observed_status = "running" if local_worker is not None and not local_worker.done() else "cancelled"
                    elif target_type == "stage_item":
                        item = task_items.get(str(target.get("item_id") or ""))
                        observed_status = self._normalize_item_status(item.status) if item is not None else "missing"
                    elif target_type == "downstream_task":
                        ref = {
                            "service": target.get("downstream_service"),
                            "task_id": target.get("downstream_task_id"),
                            "project_id": target.get("project_id"),
                            "stage_name": target.get("stage_name"),
                            "item_id": target.get("item_id"),
                            "item_key": target.get("item_key"),
                        }
                        try:
                            payload = await self._downstream_tasks().fetch_child_ref_payload(ref, token)
                        except task_manager_module.NotFoundError:
                            observed_status = "missing"
                        except Exception as exc:
                            observed_status = "unknown"
                            target["error"] = str(exc)
                        else:
                            observed_status = self._cancel_target_observation_status(payload)
                            target["error"] = None
                            target["status_raw"] = payload.get("status")
                    target["terminal_observation_status"] = observed_status
                    target["last_observed_at"] = task_manager_module._isoformat_or_none(task_manager_module._now())
                    refreshed_targets.append(target)
                    if bool(target.get("blocking")) and not self._cancel_target_is_terminal(observed_status):
                        blocking_targets.append(target)
                    if observed_status != previous_observed_status or previous_observed_status == "unknown":
                        self._record_operation_event(
                            db,
                            task,
                            operation,
                            "cancel_target_terminal_observed",
                            (
                                f"取消目标仍未收敛: {self._cancel_target_display(target)} -> {observed_status}"
                                if bool(target.get("blocking")) and not self._cancel_target_is_terminal(observed_status)
                                else f"取消目标已收敛: {self._cancel_target_display(target)} -> {observed_status}"
                            ),
                            stage_name=str(target.get("stage_name") or operation.target_stage or "").strip() or None,
                            payload=dict(target),
                        )
                self._store_cancel_targets(operation, refreshed_targets, workspace_root=task.workspace_root)
                self._commit_or_rollback(db)
                if not blocking_targets:
                    return {"targets_total": len(refreshed_targets), "targets_blocking": 0}
                blocking_snapshot = sorted(self._cancel_target_display(target) for target in blocking_targets)
                if blocking_snapshot != last_blocking_snapshot:
                    self._record_operation_event(
                        db,
                        task,
                        operation,
                        "task_cancel_waiting_for_convergence",
                        f"取消仍在等待 {len(blocking_targets)} 个目标收敛",
                        level="warning",
                        stage_name=operation.target_stage,
                        payload={"blocking_targets": blocking_targets},
                    )
                    self._commit_or_rollback(db)
                    last_blocking_snapshot = blocking_snapshot
                if task_manager_module._now() >= deadline:
                    raise ValidationError(
                        "取消收敛超时，仍有目标未进入终态: "
                        + ", ".join(self._cancel_target_display(target) for target in blocking_targets[:5])
                    )
                await asyncio.sleep(max(1, int(self.cfg.scheduler.stage_poll_interval_seconds or 5)))
                db.expire_all()
                task_refreshed = db.query(task_manager_module.BinarySecurityTask).filter(
                    task_manager_module.BinarySecurityTask.id == task.id
                ).first()
                operation_refreshed = db.query(task_manager_module.BinarySecurityTaskOperation).filter(
                    task_manager_module.BinarySecurityTaskOperation.id == operation.id
                ).first()
                if task_refreshed is not None:
                    task.status = task_refreshed.status
                    task.current_operation_id = task_refreshed.current_operation_id
                    task.updated_at = task_refreshed.updated_at
                if operation_refreshed is not None:
                    operation.result_payload_json = operation_refreshed.result_payload_json
                    operation.request_payload_json = operation_refreshed.request_payload_json
                    operation.step_payload_json = operation_refreshed.step_payload_json
                    operation.step_attempts_json = operation_refreshed.step_attempts_json
                    operation.resume_cursor_json = operation_refreshed.resume_cursor_json
                    operation.current_step = operation_refreshed.current_step

        async def _finalize_cancelled() -> dict[str, Any]:
            self._set_task_status(
                db,
                task,
                "cancelled",
                reason="取消操作已确认完成",
                source="task_operation",
                stage_name=operation.target_stage,
            )
            task.finished_at = task_manager_module._now()
            task.last_error = None
            self._invalidate_task_execution(task)
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            self._record_operation_event(
                db,
                task,
                operation,
                "task_cancel_succeeded",
                "任务取消已确认完成",
                stage_name=operation.target_stage,
                payload={"cancel_state": self._cancel_state_from_operation(task, operation)},
            )
            task_manager_module.observe_task_lifecycle("finished", status=task.status, task_type=self._task_type(task))
            await self._write_task_metadata_async(
                task,
                task_manager_module.Path(task.workspace_root) / "input" / "task-metadata.json",
                status="cancelled",
            )
            return {"task_status": task.status}

        async def _finalize_cancel_failed(error: Exception) -> dict[str, Any]:
            self._set_task_status(
                db,
                task,
                task_manager_module.TASK_STATUS_CANCEL_FAILED,
                reason="取消操作执行失败",
                source="task_operation",
                stage_name=operation.target_stage,
            )
            task.finished_at = task_manager_module._now()
            task.last_error = str(error)
            self._invalidate_task_execution(task)
            self._record_operation_event(
                db,
                task,
                operation,
                "task_cancel_failed",
                f"任务取消失败: {error}",
                level="error",
                stage_name=operation.target_stage,
                payload={"cancel_state": self._cancel_state_from_operation(task, operation)},
            )
            await self._write_task_metadata_async(
                task,
                task_manager_module.Path(task.workspace_root) / "input" / "task-metadata.json",
                status=task_manager_module.TASK_STATUS_CANCEL_FAILED,
            )
            return {"task_status": task.status, "error": str(error)}

        try:
            await _run_step(
                task_manager_module.TASK_OPERATION_STEP_MARK_TASK_CANCELLING,
                message="取消操作已进入任务状态切换",
                next_step=task_manager_module.TASK_OPERATION_STEP_COLLECT_CANCEL_TARGETS,
                fn=_mark_task_cancelling,
            )
            await _run_step(
                task_manager_module.TASK_OPERATION_STEP_COLLECT_CANCEL_TARGETS,
                message="取消操作已收集需要收敛的目标",
                next_step=task_manager_module.TASK_OPERATION_STEP_CANCEL_LOCAL_EXECUTION,
                fn=_collect_targets,
            )
            await _run_step(
                task_manager_module.TASK_OPERATION_STEP_CANCEL_LOCAL_EXECUTION,
                message="取消操作已停止本地执行链",
                next_step=task_manager_module.TASK_OPERATION_STEP_CANCEL_DOWNSTREAM_TARGETS,
                fn=_cancel_local,
            )
            await _run_step(
                task_manager_module.TASK_OPERATION_STEP_CANCEL_DOWNSTREAM_TARGETS,
                message="取消操作已向下游发出取消请求",
                next_step=task_manager_module.TASK_OPERATION_STEP_VERIFY_DOWNSTREAM_QUIESCED,
                fn=_cancel_downstream_targets,
            )
            await _run_step(
                task_manager_module.TASK_OPERATION_STEP_VERIFY_DOWNSTREAM_QUIESCED,
                message="取消操作已完成下游收敛核验",
                next_step=task_manager_module.TASK_OPERATION_STEP_FINALIZE_TASK_CANCELLED,
                fn=_verify_quiesced,
            )
        except Exception as exc:
            await _run_step(
                task_manager_module.TASK_OPERATION_STEP_FINALIZE_TASK_CANCEL_FAILED,
                message="取消操作已收口为失败",
                next_step=task_manager_module.TASK_OPERATION_STEP_FINALIZE_TASK_CANCEL_FAILED,
                fn=lambda: _finalize_cancel_failed(exc),
            )
            raise

        await _run_step(
            task_manager_module.TASK_OPERATION_STEP_FINALIZE_TASK_CANCELLED,
            message="取消操作已收口为已取消",
            next_step=task_manager_module.TASK_OPERATION_STEP_SUCCEEDED,
            fn=_finalize_cancelled,
        )

    async def _run_retry_failed_items_operation_steps(self: TaskManager, db: Session, task, operation, resume_step: str) -> None:
        from app.service import task_manager as task_manager_module

        step_flow = (
            (
                task_manager_module.TASK_OPERATION_STEP_COLLECT_CLEANUP_PLAN,
                "开始收集失败项重试计划",
                "失败项重试计划已收集",
                self._operation_collect_retry_failed_items_plan,
                task_manager_module.TASK_OPERATION_STEP_SYNC_TARGET_STAGE_STATE,
            ),
            (
                task_manager_module.TASK_OPERATION_STEP_SYNC_TARGET_STAGE_STATE,
                "开始同步目标阶段下游状态",
                "目标阶段下游状态同步完成",
                self._operation_sync_retry_target_stage_state,
                task_manager_module.TASK_OPERATION_STEP_PREPARE_RETRY_ITEMS,
            ),
            (
                task_manager_module.TASK_OPERATION_STEP_PREPARE_RETRY_ITEMS,
                "开始准备失败项重试上下文",
                "失败项重试上下文准备完成",
                self._operation_prepare_retry_items,
                task_manager_module.TASK_OPERATION_STEP_CLEANUP_ABNORMAL_CHILDREN,
            ),
            (
                task_manager_module.TASK_OPERATION_STEP_CLEANUP_ABNORMAL_CHILDREN,
                "开始清理异常子任务",
                "异常子任务清理完成",
                self._operation_cleanup_retry_abnormal_children,
                task_manager_module.TASK_OPERATION_STEP_CREATE_REPLACEMENT_CHILDREN,
            ),
            (
                task_manager_module.TASK_OPERATION_STEP_CREATE_REPLACEMENT_CHILDREN,
                "开始创建替换子任务",
                "替换子任务创建完成",
                self._operation_create_retry_children,
                task_manager_module.TASK_OPERATION_STEP_VERIFY_RETRY_BINDINGS,
            ),
            (
                task_manager_module.TASK_OPERATION_STEP_VERIFY_RETRY_BINDINGS,
                "开始校验失败项重试绑定",
                "失败项重试绑定校验完成",
                self._operation_verify_retry_bindings,
                task_manager_module.TASK_OPERATION_STEP_FINALIZE_RETRY_OPERATION,
            ),
            (
                task_manager_module.TASK_OPERATION_STEP_FINALIZE_RETRY_OPERATION,
                "开始完成失败项重试操作",
                "失败项重试操作已完成",
                self._operation_finalize_retry_failed_items,
                task_manager_module.TASK_OPERATION_STEP_REQUEUE_TASK,
            ),
        )
        current_step = (
            resume_step if resume_step in {row[0] for row in step_flow}
            else task_manager_module.TASK_OPERATION_STEP_COLLECT_CLEANUP_PLAN
        )
        for step_name, start_message, finish_message, handler, next_step in step_flow:
            if current_step != step_name:
                continue
            self._record_operation_step_started(
                db,
                task,
                operation,
                step_name=step_name,
                message=f"{start_message}: {operation.operation_type}",
                stage_name=operation.target_stage,
                payload={"operation_type": operation.operation_type},
            )
            db.commit()
            try:
                payload = await handler(db, task, operation)
            except Exception as exc:
                self._record_operation_step_failed(
                    db,
                    task,
                    operation,
                    step_name=step_name,
                    error=exc,
                    stage_name=operation.target_stage,
                )
                db.commit()
                raise
            self._record_operation_step_finished(
                db,
                task,
                operation,
                step_name=step_name,
                message=f"{finish_message}: {operation.operation_type}",
                stage_name=operation.target_stage,
                payload=dict(payload or {}),
                next_step=next_step,
            )
            db.commit()
            current_step = next_step

        if current_step != task_manager_module.TASK_OPERATION_STEP_REQUEUE_TASK:
            return
        if self._is_operation_requeue_state_applied(task, operation):
            self._record_operation_step_finished(
                db,
                task,
                operation,
                step_name=task_manager_module.TASK_OPERATION_STEP_REQUEUE_TASK,
                message=f"后台操作重新排队步骤已确认完成，无需重复执行: {operation.operation_type}",
                stage_name=operation.target_stage,
                payload={"idempotent_recovery": True},
                next_step=task_manager_module.TASK_OPERATION_STEP_SUCCEEDED,
            )
            db.commit()
            return
        self._record_operation_step_started(
            db,
            task,
            operation,
            step_name=task_manager_module.TASK_OPERATION_STEP_REQUEUE_TASK,
            message=f"后台操作进入重新排队步骤: {operation.operation_type}",
            stage_name=operation.target_stage,
        )
        self._requeue_task_after_retry_operation(
            db,
            task,
            target_stage=operation.target_stage,
            operation=operation,
        )
        self._record_operation_step_finished(
            db,
            task,
            operation,
            step_name=task_manager_module.TASK_OPERATION_STEP_REQUEUE_TASK,
            message=f"后台操作重新排队步骤已完成: {operation.operation_type}",
            stage_name=operation.target_stage,
            next_step=task_manager_module.TASK_OPERATION_STEP_SUCCEEDED,
        )
        db.commit()

    async def _run_retry_stage_full_operation_steps(self: TaskManager, db: Session, task, operation, resume_step: str) -> str:
        from app.service import task_manager as task_manager_module

        step_flow = (
            (
                task_manager_module.TASK_OPERATION_STEP_COLLECT_CLEANUP_PLAN,
                "后台操作开始收集清理计划",
                "后台操作清理计划收集完成",
                self._operation_collect_retry_stage_full_plan,
                task_manager_module.TASK_OPERATION_STEP_CANCEL_DOWNSTREAM,
            ),
            (
                task_manager_module.TASK_OPERATION_STEP_CANCEL_DOWNSTREAM,
                "后台操作开始清理下游子任务",
                "后台操作下游子任务清理完成",
                self._operation_execute_retry_stage_full_cleanup,
                task_manager_module.TASK_OPERATION_STEP_REQUEUE_TASK,
            ),
        )
        for step_name, start_message, finish_message, handler, next_step in step_flow:
            if resume_step != step_name:
                continue
            self._record_operation_step_started(
                db,
                task,
                operation,
                step_name=step_name,
                message=f"{start_message}: {operation.operation_type}",
                stage_name=operation.target_stage,
                payload={"operation_type": operation.operation_type},
            )
            db.commit()
            try:
                payload = await handler(db, task, operation)
            except Exception as exc:
                self._record_operation_step_failed(
                    db,
                    task,
                    operation,
                    step_name=step_name,
                    error=exc,
                    stage_name=operation.target_stage,
                )
                db.commit()
                raise
            self._record_operation_step_finished(
                db,
                task,
                operation,
                step_name=step_name,
                message=f"{finish_message}: {operation.operation_type}",
                stage_name=operation.target_stage,
                payload=payload,
                next_step=next_step,
            )
            db.commit()
            resume_step = next_step
        return resume_step
