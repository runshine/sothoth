from __future__ import annotations

import asyncio
import json
import shutil
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.artifacts.io import ensure_dir, write_task_manifest
from app.config import get_config
from app.engine.workflow import ExitWorkflowError, WorkflowExecutor
from app.models.config_models import FrameworkConfig
from app.models.contracts import ExecutionState, TaskManifest
from app.models.database import (
    TriggerTask,
    WorkflowDefinition,
    WorkflowExecution,
    WorkflowExecutionEvent,
    get_db_session,
)
from app.schemas import (
    TriggerTaskCreate,
    TriggerTaskResponse,
    WorkflowExecutionEventResponse,
    WorkflowExecutionResponse,
)
from app.services.workflow_service import get_workflow_service


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _principal_id(principal: dict) -> str:
    return principal.get("user_id") or principal.get("subject") or principal.get("client_id") or "system"


def _project_ids(principal: dict) -> set[str]:
    return set(principal.get("project_ids") or [])


class CancellationRequestedError(ExitWorkflowError):
    pass


class ServiceWorkflowExecutor(WorkflowExecutor):
    def __init__(self, framework_config: FrameworkConfig, execution_id: str):
        super().__init__(framework_config)
        self.execution_id = execution_id

    def _emit(
        self,
        *,
        event_type: str,
        message: str,
        stage_id: str | None = None,
        round_no: int | None = None,
        level: str = "info",
        payload_json: dict[str, Any] | None = None,
    ) -> None:
        service = get_execution_service()
        db = get_db_session()
        try:
            service.record_event(
                db,
                execution_id=self.execution_id,
                event_type=event_type,
                message=message,
                stage_id=stage_id,
                round_no=round_no,
                level=level,
                payload_json=payload_json or {},
            )
        finally:
            db.close()

    def check_interruption(
        self,
        *,
        checkpoint: str,
        stage_id: str | None = None,
        task=None,
        round_no: int | None = None,
        task_dir: Path | None = None,
    ) -> None:
        db = get_db_session()
        try:
            execution = db.get(WorkflowExecution, self.execution_id)
            if execution is None:
                raise CancellationRequestedError("execution disappeared")
            trigger = db.get(TriggerTask, execution.trigger_task_id)
            cancelled = execution.status in {"cancel_requested", "cancelled"} or (
                trigger is not None and trigger.status in {"cancel_requested", "cancelled"}
            )
            if cancelled:
                self._emit(
                    event_type="execution_cancel_checkpoint",
                    message=f"execution cancel requested at {checkpoint}",
                    stage_id=stage_id,
                    round_no=round_no,
                    level="warning",
                    payload_json={
                        "checkpoint": checkpoint,
                        "task_id": getattr(task, "task_id", None),
                        "task_dir": str(task_dir) if task_dir else None,
                    },
                )
                raise CancellationRequestedError(f"execution cancelled at {checkpoint}")
        finally:
            db.close()

    def on_stage_started(self, *, workflow_config, stage, stage_dir: Path, tasks) -> None:
        db = get_db_session()
        try:
            execution = db.get(WorkflowExecution, self.execution_id)
            if execution is not None:
                execution.current_stage_id = stage.id
                db.add(execution)
                db.commit()
            self._emit(
                event_type="stage_started",
                message=f"stage {stage.id} started",
                stage_id=stage.id,
                payload_json={"workflow_ref": stage.workflow_ref, "task_count": len(tasks), "stage_dir": str(stage_dir)},
            )
        finally:
            db.close()

    def on_stage_completed(self, *, workflow_config, stage, stage_dir: Path, task_records) -> None:
        self._emit(
            event_type="stage_completed",
            message=f"stage {stage.id} completed",
            stage_id=stage.id,
            payload_json={
                "workflow_ref": stage.workflow_ref,
                "task_count": len(task_records),
                "produced_task_count": sum(record.produced_task_count for record in task_records),
                "stage_dir": str(stage_dir),
            },
        )

    def on_round_started(self, *, workflow_config, task, round_no: int, round_dir: Path) -> None:
        self._emit(
            event_type="round_started",
            message=f"round {round_no} started for task {task.task_id}",
            round_no=round_no,
            payload_json={"task_id": task.task_id, "workflow_id": workflow_config.id, "round_dir": str(round_dir)},
        )

    def on_round_feedback(self, *, workflow_config, task, round_no: int, feedback_path: Path, feedback_scope: str) -> None:
        self._emit(
            event_type="round_feedback",
            message=f"round {round_no} produced {feedback_scope} feedback for task {task.task_id}",
            round_no=round_no,
            level="warning",
            payload_json={"task_id": task.task_id, "feedback_scope": feedback_scope, "feedback_path": str(feedback_path)},
        )

    def on_round_completed(self, *, workflow_config, task, round_no: int, state, message: str, task_dir: Path) -> None:
        self._emit(
            event_type="round_completed",
            message=message,
            round_no=round_no,
            payload_json={"task_id": task.task_id, "workflow_id": workflow_config.id, "state": state.value, "task_dir": str(task_dir)},
        )

    def on_plugin_completed(self, *, plugin_id: str, phase: str, ctx, result, log_path: Path) -> None:
        self._emit(
            event_type="plugin_completed",
            message=f"plugin {plugin_id} finished with {result.status.value}",
            round_no=ctx.round_no or None,
            payload_json={
                "plugin_id": plugin_id,
                "phase": phase,
                "status": result.status.value,
                "task_id": ctx.task.task_id,
                "log_path": str(log_path),
            },
        )


class ExecutionService:
    def _ensure_project_access(self, principal: dict, project_id: str) -> None:
        project_ids = _project_ids(principal)
        if project_ids and project_id not in project_ids:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="project access denied")

    def _definition_or_404(self, db: Session, definition_id: str) -> WorkflowDefinition:
        definition = db.get(WorkflowDefinition, definition_id)
        if definition is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workflow definition not found")
        return definition

    def _trigger_or_404(self, db: Session, trigger_task_id: str) -> TriggerTask:
        trigger = db.get(TriggerTask, trigger_task_id)
        if trigger is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="trigger task not found")
        return trigger

    def _execution_or_404(self, db: Session, execution_id: str) -> WorkflowExecution:
        execution = db.get(WorkflowExecution, execution_id)
        if execution is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="execution not found")
        return execution

    def _trigger_response(self, model: TriggerTask) -> TriggerTaskResponse:
        return TriggerTaskResponse.model_validate(model, from_attributes=True)

    def _execution_response(self, model: WorkflowExecution) -> WorkflowExecutionResponse:
        return WorkflowExecutionResponse.model_validate(model, from_attributes=True)

    def _event_response(self, model: WorkflowExecutionEvent) -> WorkflowExecutionEventResponse:
        return WorkflowExecutionEventResponse.model_validate(model, from_attributes=True)

    def _build_workspace_root(self, execution_id: str, definition: WorkflowDefinition) -> Path:
        base_dir = definition.workspace_base_dir or get_config().service.workspace_base_dir
        return ensure_dir(Path(base_dir) / execution_id)

    def _set_terminal_state(
        self,
        db: Session,
        *,
        execution: WorkflowExecution,
        trigger: TriggerTask,
        execution_status: str,
        message: str,
        output_manifest_path: str | None = None,
        output_task_count: int = 0,
    ) -> None:
        now = datetime.utcnow()
        execution.status = execution_status
        execution.message = message
        execution.finished_at = now
        execution.output_manifest_path = output_manifest_path
        execution.output_task_count = output_task_count
        execution.lease_expires_at = now
        execution.current_stage_id = None
        trigger.status = execution_status
        trigger.message = message
        trigger.finished_at = now
        if trigger.started_at is None:
            trigger.started_at = execution.started_at or now
        db.add(execution)
        db.add(trigger)

    def create_trigger_task(
        self,
        db: Session,
        definition_id: str,
        payload: TriggerTaskCreate,
        principal: dict,
        *,
        trigger_type: str,
    ) -> TriggerTaskResponse:
        definition = self._definition_or_404(db, definition_id)
        self._ensure_project_access(principal, definition.project_id)
        if not definition.enabled:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="workflow definition is disabled")
        if trigger_type == "http":
            if definition.trigger_type != "http" or not definition.trigger_enabled or not definition.is_active:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="workflow definition http trigger is unavailable")
        manifest = TaskManifest(tasks=payload.input_tasks)
        actor = _principal_id(principal)
        now = datetime.utcnow()
        trigger = TriggerTask(
            id=_new_id("tt"),
            workflow_definition_id=definition.id,
            project_id=definition.project_id,
            trigger_type=trigger_type,
            input_tasks_json=manifest.model_dump(mode="json"),
            priority=payload.priority if payload.priority is not None else definition.priority_default,
            status="pending",
            submitted_by=actor,
            message="pending dispatch",
            created_at=now,
            updated_at=now,
        )
        execution = WorkflowExecution(
            id=_new_id("exec"),
            trigger_task_id=trigger.id,
            workflow_definition_id=definition.id,
            project_id=definition.project_id,
            status="pending",
            message="pending dispatch",
            created_at=now,
            updated_at=now,
        )
        db.add(trigger)
        db.add(execution)
        db.commit()
        db.refresh(trigger)
        return self._trigger_response(trigger)

    def list_trigger_tasks(self, db: Session, principal: dict) -> List[TriggerTaskResponse]:
        project_ids = _project_ids(principal)
        query = db.query(TriggerTask).order_by(TriggerTask.created_at.desc())
        if project_ids:
            query = query.filter(TriggerTask.project_id.in_(project_ids))
        return [self._trigger_response(item) for item in query.all()]

    def get_trigger_task(self, db: Session, trigger_task_id: str, principal: dict) -> TriggerTaskResponse:
        trigger = self._trigger_or_404(db, trigger_task_id)
        self._ensure_project_access(principal, trigger.project_id)
        return self._trigger_response(trigger)

    def cancel_trigger_task(self, db: Session, trigger_task_id: str, principal: dict) -> None:
        trigger = self._trigger_or_404(db, trigger_task_id)
        self._ensure_project_access(principal, trigger.project_id)
        execution = db.query(WorkflowExecution).filter(WorkflowExecution.trigger_task_id == trigger.id).first()
        now = datetime.utcnow()
        if trigger.status == "pending":
            trigger.status = "cancelled"
            trigger.finished_at = now
            trigger.message = "cancelled before dispatch"
            if execution is not None:
                execution.status = "cancelled"
                execution.finished_at = now
                execution.message = "cancelled before dispatch"
        elif trigger.status in {"running", "dispatching"}:
            trigger.status = "cancel_requested"
            trigger.message = "cancel requested"
            if execution is not None and execution.status == "running":
                execution.status = "cancel_requested"
                execution.message = "cancel requested"
        db.add(trigger)
        if execution is not None:
            db.add(execution)
        db.commit()

    def retry_trigger_task(self, db: Session, trigger_task_id: str, principal: dict) -> TriggerTaskResponse:
        trigger = self._trigger_or_404(db, trigger_task_id)
        self._ensure_project_access(principal, trigger.project_id)
        definition = self._definition_or_404(db, trigger.workflow_definition_id)
        payload = TriggerTaskCreate(input_tasks=TaskManifest.model_validate(trigger.input_tasks_json).tasks, priority=trigger.priority)
        return self.create_trigger_task(db, definition.id, payload, principal, trigger_type=trigger.trigger_type)

    def list_executions(self, db: Session, principal: dict) -> List[WorkflowExecutionResponse]:
        project_ids = _project_ids(principal)
        query = db.query(WorkflowExecution).order_by(WorkflowExecution.created_at.desc())
        if project_ids:
            query = query.filter(WorkflowExecution.project_id.in_(project_ids))
        return [self._execution_response(item) for item in query.all()]

    def get_execution(self, db: Session, execution_id: str, principal: dict) -> WorkflowExecutionResponse:
        execution = self._execution_or_404(db, execution_id)
        self._ensure_project_access(principal, execution.project_id)
        return self._execution_response(execution)

    def list_execution_events(self, db: Session, execution_id: str, principal: dict) -> List[WorkflowExecutionEventResponse]:
        execution = self._execution_or_404(db, execution_id)
        self._ensure_project_access(principal, execution.project_id)
        events = (
            db.query(WorkflowExecutionEvent)
            .filter(WorkflowExecutionEvent.execution_id == execution.id)
            .order_by(WorkflowExecutionEvent.created_at.asc())
            .all()
        )
        return [self._event_response(item) for item in events]

    def get_execution_artifacts(self, db: Session, execution_id: str, principal: dict) -> Dict[str, Any]:
        execution = self._execution_or_404(db, execution_id)
        self._ensure_project_access(principal, execution.project_id)
        files: List[Dict[str, Any]] = []
        workspace_root = Path(execution.workspace_root) if execution.workspace_root else None
        if workspace_root and workspace_root.exists():
            for path in sorted(p for p in workspace_root.rglob("*") if p.is_file()):
                files.append(
                    {
                        "path": str(path.relative_to(workspace_root)),
                        "size": path.stat().st_size,
                    }
                )
        return {
            "execution_id": execution.id,
            "workspace_root": execution.workspace_root,
            "output_manifest_path": execution.output_manifest_path,
            "files": files,
        }

    def cancel_execution(self, db: Session, execution_id: str, principal: dict) -> None:
        execution = self._execution_or_404(db, execution_id)
        self._ensure_project_access(principal, execution.project_id)
        trigger = self._trigger_or_404(db, execution.trigger_task_id)
        self.cancel_trigger_task(db, trigger.id, principal)

    def record_event(
        self,
        db: Session,
        *,
        execution_id: str,
        event_type: str,
        message: str,
        stage_id: str | None = None,
        round_no: int | None = None,
        level: str = "info",
        payload_json: dict[str, Any] | None = None,
    ) -> WorkflowExecutionEvent:
        event = WorkflowExecutionEvent(
            id=_new_id("evt"),
            execution_id=execution_id,
            event_type=event_type,
            stage_id=stage_id,
            round_no=round_no,
            level=level,
            message=message,
            payload_json=payload_json or {},
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    def run_claimed_execution(self, execution_id: str) -> None:
        db = get_db_session()
        execution: WorkflowExecution | None = None
        trigger: TriggerTask | None = None
        try:
            execution = self._execution_or_404(db, execution_id)
            trigger = self._trigger_or_404(db, execution.trigger_task_id)
            definition = self._definition_or_404(db, execution.workflow_definition_id)
            framework_config = get_workflow_service().validate_definition_payload(definition.definition_json)
            workspace_root = self._build_workspace_root(execution.id, definition)
            input_dir = ensure_dir(workspace_root / "input")
            input_manifest_path = write_task_manifest(input_dir / "tasks.json", TaskManifest.model_validate(trigger.input_tasks_json).tasks)

            execution.workspace_root = str(workspace_root)
            execution.message = "execution running"
            if execution.started_at is None:
                execution.started_at = datetime.utcnow()
            if trigger.started_at is None:
                trigger.started_at = execution.started_at
            db.add(execution)
            db.add(trigger)
            db.commit()
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="execution_started",
                message="execution claimed and started",
                payload_json={"workspace_root": str(workspace_root), "owner_pod_id": execution.owner_pod_id},
            )

            executor = ServiceWorkflowExecutor(framework_config, execution.id)
            result = executor.run(str(input_manifest_path), str(workspace_root))

            db.refresh(execution)
            db.refresh(trigger)
            self._set_terminal_state(
                db,
                execution=execution,
                trigger=trigger,
                execution_status="succeeded" if result.state == ExecutionState.SUCCEEDED else "failed",
                message="execution completed",
                output_manifest_path=result.output_manifest_path,
                output_task_count=result.output_task_count,
            )
            db.commit()
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="execution_finished",
                message="execution finished",
                payload_json={
                    "status": execution.status,
                    "output_manifest_path": execution.output_manifest_path,
                    "output_task_count": execution.output_task_count,
                },
            )
        except CancellationRequestedError as exc:
            if execution is None or trigger is None:
                return
            db.refresh(execution)
            db.refresh(trigger)
            self._set_terminal_state(db, execution=execution, trigger=trigger, execution_status="cancelled", message=str(exc))
            db.commit()
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="execution_cancelled",
                message=str(exc),
                level="warning",
            )
        except Exception as exc:
            if execution is not None and trigger is not None:
                db.refresh(execution)
                db.refresh(trigger)
                self._set_terminal_state(db, execution=execution, trigger=trigger, execution_status="failed", message=str(exc))
                db.commit()
                self.record_event(
                    db,
                    execution_id=execution.id,
                    event_type="execution_failed",
                    message=str(exc),
                    level="error",
                )
            raise
        finally:
            db.close()


_execution_service: ExecutionService | None = None


def get_execution_service() -> ExecutionService:
    global _execution_service
    if _execution_service is None:
        _execution_service = ExecutionService()
    return _execution_service
