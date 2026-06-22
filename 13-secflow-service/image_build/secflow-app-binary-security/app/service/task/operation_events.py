from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import shared as task_shared

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from app.model import BinarySecurityTask, BinarySecurityTaskOperation
    from app.service.task_manager import TaskManager


class TaskOperationEventServiceMixin:
    def _operation_payload_root(
        self: TaskManager,
        operation: BinarySecurityTaskOperation,
        *,
        workspace_root: str | None = None,
    ) -> Path | None:
        task_root_value = str(workspace_root or "").strip()
        task_root = Path(task_root_value) if task_root_value else None
        if task_root is None:
            return None
        return task_root / "run" / "task-operations" / str(operation.id or "").strip()

    def _operation_result_payload_path(
        self: TaskManager,
        operation: BinarySecurityTaskOperation,
        *,
        workspace_root: str | None = None,
    ) -> Path | None:
        root = self._operation_payload_root(operation, workspace_root=workspace_root)
        if root is None:
            return None
        return root / "result.json"

    def _operation_request_payload_path(
        self: TaskManager,
        operation: BinarySecurityTaskOperation,
        *,
        workspace_root: str | None = None,
    ) -> Path | None:
        root = self._operation_payload_root(operation, workspace_root=workspace_root)
        if root is None:
            return None
        return root / "request.json"

    def _operation_step_payload_path(
        self: TaskManager,
        operation: BinarySecurityTaskOperation,
        *,
        step_name: str,
        workspace_root: str | None = None,
    ) -> Path | None:
        root = self._operation_payload_root(operation, workspace_root=workspace_root)
        if root is None:
            return None
        safe_step_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(step_name or "").strip()) or "unknown"
        return root / "steps" / f"{safe_step_name}.json"

    def _load_externalized_payload(
        self: TaskManager,
        path_value: str | None,
        *,
        path_key: str,
        missing_key: str,
    ) -> dict[str, Any]:
        normalized_path = str(path_value or "").strip()
        if not normalized_path:
            return {}
        try:
            loaded = task_shared._read_json(Path(normalized_path))
        except Exception:
            return {path_key: normalized_path, missing_key: True}
        if isinstance(loaded, dict):
            return loaded
        return {path_key: normalized_path, "externalized_payload_invalid": True}

    def _load_operation_result_payload(self: TaskManager, operation: BinarySecurityTaskOperation) -> dict[str, Any]:
        payload = dict(operation.result_payload or {})
        path_value = str(payload.get("result_payload_path") or "").strip()
        if not path_value:
            return payload
        return self._load_externalized_payload(
            path_value,
            path_key="result_payload_path",
            missing_key="missing_externalized_payload",
        )

    def _load_operation_request_payload(self: TaskManager, operation: BinarySecurityTaskOperation) -> dict[str, Any]:
        payload = dict(operation.request_payload or {})
        path_value = str(payload.get("request_payload_path") or "").strip()
        if not path_value:
            return payload
        return self._load_externalized_payload(
            path_value,
            path_key="request_payload_path",
            missing_key="missing_externalized_request_payload",
        )

    def _load_operation_step_payload(self: TaskManager, operation: BinarySecurityTaskOperation) -> dict[str, Any]:
        step_payload = dict(operation.step_payload or {})
        resolved: dict[str, Any] = {}
        for step_name, raw_state in step_payload.items():
            state = dict(raw_state or {})
            payload_path = str(state.get("payload_path") or "").strip()
            if payload_path:
                loaded = self._load_externalized_payload(
                    payload_path,
                    path_key="payload_path",
                    missing_key="missing_externalized_step_payload",
                )
                if "payload_path" not in loaded:
                    loaded["payload_path"] = payload_path
                state["payload"] = loaded
            resolved[str(step_name)] = state
        return resolved

    def _persist_externalized_payload(
        self: TaskManager,
        *,
        operation: BinarySecurityTaskOperation,
        payload: dict[str, Any] | None,
        path: Path | None,
        fallback_name: str,
        path_key: str,
        assign,
    ) -> None:
        payload_data = dict(payload or {})
        if path is None:
            assign(payload_data)
            return
        task = None
        session_factory = getattr(self, "_session_factory", None)
        try:
            from app.service import task_manager as task_manager_module

            session_factory = session_factory or task_manager_module.get_session_factory
            db = session_factory() if callable(session_factory) else None
            if db is not None:
                try:
                    task = (
                        db.query(task_manager_module.BinarySecurityTask)
                        .filter(task_manager_module.BinarySecurityTask.id == str(operation.task_id or "").strip())
                        .first()
                    )
                finally:
                    db.close()
        except Exception:
            task = None
        if task is not None and not self._guard_task_workspace_write(task, purpose=f"operation_payload:{path_key}", path=path):
            assign(payload_data)
            return
        try:
            task_shared._write_json(path, payload_data)
            assign({path_key: str(path)})
            return
        except OSError:
            fallback_root = (
                Path(tempfile.gettempdir())
                / "secflow-binary-security"
                / "task-operations"
                / str(operation.task_id or "unknown")
                / str(operation.id or "unknown")
            )
            fallback_path = fallback_root / fallback_name
            task_shared._write_json(fallback_path, payload_data)
            assign({path_key: str(fallback_path)})

    def _persist_operation_result_payload(
        self: TaskManager,
        operation: BinarySecurityTaskOperation,
        payload: dict[str, Any] | None,
        *,
        workspace_root: str | None = None,
    ) -> None:
        self._persist_externalized_payload(
            operation=operation,
            payload=payload,
            path=self._operation_result_payload_path(operation, workspace_root=workspace_root),
            fallback_name="result.json",
            path_key="result_payload_path",
            assign=lambda value: setattr(operation, "result_payload", value),
        )

    def _persist_operation_request_payload(
        self: TaskManager,
        operation: BinarySecurityTaskOperation,
        payload: dict[str, Any] | None,
        *,
        workspace_root: str | None = None,
    ) -> None:
        self._persist_externalized_payload(
            operation=operation,
            payload=payload,
            path=self._operation_request_payload_path(operation, workspace_root=workspace_root),
            fallback_name="request.json",
            path_key="request_payload_path",
            assign=lambda value: setattr(operation, "request_payload", value),
        )

    def _persist_operation_step_payload(
        self: TaskManager,
        operation: BinarySecurityTaskOperation,
        *,
        step_name: str,
        payload: dict[str, Any] | None,
        workspace_root: str | None = None,
    ) -> str | None:
        if payload is None:
            return None
        captured_path: str | None = None

        def _assign(value: dict[str, Any]) -> None:
            nonlocal captured_path
            captured_path = str(value.get("payload_path") or "").strip() or None

        safe_step_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(step_name or "").strip()) or "unknown"
        self._persist_externalized_payload(
            operation=operation,
            payload=payload,
            path=self._operation_step_payload_path(operation, step_name=step_name, workspace_root=workspace_root),
            fallback_name=f"steps/{safe_step_name}.json",
            path_key="payload_path",
            assign=_assign,
        )
        return captured_path

    def _operation_result_data(self: TaskManager, operation: BinarySecurityTaskOperation) -> dict[str, Any]:
        return self._load_operation_result_payload(operation)

    def _operation_response(self: TaskManager, operation: BinarySecurityTaskOperation):
        from app.service import task_manager as task_manager_module

        return task_manager_module.BinarySecurityTaskOperationResponse(
            id=str(operation.id or ""),
            task_id=str(operation.task_id or ""),
            project_id=str(operation.project_id or ""),
            operation_type=str(operation.operation_type or ""),
            target_stage=str(operation.target_stage or "").strip() or None,
            requested_by=str(operation.requested_by or "").strip() or None,
            request_source=str(operation.request_source or "").strip() or None,
            status=str(operation.status or ""),
            operation_token=str(operation.operation_token or ""),
            execution_model="task_owner_inbox",
            owner_model="task_lease_owner",
            request_payload=self._load_operation_request_payload(operation),
            result_payload=self._load_operation_result_payload(operation),
            error_code=str(operation.error_code or "").strip() or None,
            error_message=str(operation.error_message or "").strip() or None,
            current_step=str(operation.current_step or "").strip() or None,
            step_attempts=dict(operation.step_attempts or {}),
            step_payload=self._load_operation_step_payload(operation),
            resume_cursor=dict(operation.resume_cursor or {}),
            superseded_by_operation_id=str(operation.superseded_by_operation_id or "").strip() or None,
            created_at=getattr(operation, "created_at", None),
            updated_at=getattr(operation, "updated_at", None),
            started_at=getattr(operation, "started_at", None),
            finished_at=getattr(operation, "finished_at", None),
        )

    def _update_operation_result_payload(
        self: TaskManager,
        operation: BinarySecurityTaskOperation,
        payload_updates: dict[str, Any] | None,
        *,
        workspace_root: str | None = None,
    ) -> dict[str, Any]:
        merged = {
            **self._operation_result_data(operation),
            **dict(payload_updates or {}),
        }
        self._persist_operation_result_payload(
            operation,
            merged,
            workspace_root=workspace_root,
        )
        return merged

    def _operation_resume_step(self: TaskManager, operation: BinarySecurityTaskOperation) -> str:
        from app.service import task_manager as task_manager_module

        cursor = dict(operation.resume_cursor or {})
        current_step = str(cursor.get("current_step") or operation.current_step or "").strip()
        valid_steps = (
            task_manager_module.TASK_CANCEL_SAGA_STEPS
            if str(operation.operation_type or "").strip() == task_manager_module.TASK_ACTION_CANCEL
            else task_manager_module.TASK_OPERATION_SAGA_STEPS
        )
        if current_step in valid_steps:
            return current_step
        if str(operation.operation_type or "").strip() == task_manager_module.TASK_ACTION_CANCEL:
            return task_manager_module.TASK_OPERATION_STEP_MARK_TASK_CANCELLING
        return task_manager_module.TASK_OPERATION_STEP_COLLECT_CLEANUP_PLAN

    def _record_operation_event(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
        event_type: str,
        message: str,
        *,
        level: str = "info",
        stage_name: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        merged_payload = {
            "operation_id": operation.id,
            "operation_type": operation.operation_type,
            "operation_status": operation.status,
            "owner_instance_id": None,
            **dict(payload or {}),
        }
        self._record_event(
            db,
            task,
            event_type,
            message,
            level=level,
            stage_name=stage_name or operation.target_stage,
            payload=merged_payload,
            operation_id=operation.id,
        )

    def _set_operation_step_state(
        self: TaskManager,
        operation: BinarySecurityTaskOperation,
        *,
        step_name: str,
        status: str,
        payload: dict[str, Any] | None = None,
        resume_cursor: dict[str, Any] | None = None,
        increment_attempt: bool = False,
        workspace_root: str | None = None,
    ) -> None:
        attempts = dict(operation.step_attempts or {})
        step_payload = dict(operation.step_payload or {})
        next_resume_cursor = dict(operation.resume_cursor or {})
        if increment_attempt:
            attempts[step_name] = int(attempts.get(step_name) or 0) + 1
        payload_path = self._persist_operation_step_payload(
            operation,
            step_name=step_name,
            payload=payload,
            workspace_root=workspace_root,
        )
        step_payload[step_name] = {
            **dict(step_payload.get(step_name) or {}),
            "status": status,
            "updated_at": task_shared._isoformat_or_none(task_shared._now()),
            **({"payload_path": payload_path} if payload_path else {}),
        }
        if resume_cursor is not None:
            next_resume_cursor = {
                key: value
                for key, value in dict(resume_cursor).items()
                if key == "current_step"
                or isinstance(value, (str, int, float, bool))
                or value is None
                or isinstance(value, dict)
            }
        operation.current_step = step_name
        operation.step_attempts = attempts
        operation.step_payload = step_payload
        operation.resume_cursor = next_resume_cursor
        operation.updated_at = task_shared._now()

    def _record_operation_step_started(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
        *,
        step_name: str,
        message: str,
        stage_name: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        self._set_operation_step_state(
            operation,
            step_name=step_name,
            status="running",
            payload=payload,
            resume_cursor={"current_step": step_name},
            increment_attempt=True,
            workspace_root=task.workspace_root,
        )
        self._record_operation_event(
            db,
            task,
            operation,
            "operation_step_started",
            message,
            stage_name=stage_name,
            payload={"step_name": step_name, **dict(payload or {})},
        )

    def _record_operation_step_finished(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
        *,
        step_name: str,
        message: str,
        stage_name: str | None = None,
        payload: dict[str, Any] | None = None,
        next_step: str | None = None,
    ) -> None:
        self._set_operation_step_state(
            operation,
            step_name=step_name,
            status="succeeded",
            payload=payload,
            resume_cursor={"current_step": next_step or step_name},
            workspace_root=task.workspace_root,
        )
        self._record_operation_event(
            db,
            task,
            operation,
            "operation_step_succeeded",
            message,
            stage_name=stage_name,
            payload={"step_name": step_name, "next_step": next_step, **dict(payload or {})},
        )

    def _record_operation_step_failed(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
        *,
        step_name: str,
        error: Exception | str,
        stage_name: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        error_message = str(error)
        self._set_operation_step_state(
            operation,
            step_name=step_name,
            status="failed",
            payload={"error": error_message, **dict(payload or {})},
            resume_cursor={"current_step": step_name},
            workspace_root=task.workspace_root,
        )
        self._record_operation_event(
            db,
            task,
            operation,
            "operation_step_failed",
            f"后台操作步骤失败: {step_name}: {error_message}",
            level="error",
            stage_name=stage_name,
            payload={"step_name": step_name, "error": error_message, **dict(payload or {})},
        )
