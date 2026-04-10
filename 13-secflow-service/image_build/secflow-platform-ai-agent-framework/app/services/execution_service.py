from __future__ import annotations

import asyncio
import shutil
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.artifacts.io import abs_path, ensure_dir, sanitize_name, write_json, write_task_manifest, write_text
from app.config import get_config
from app.models.contracts import ExecutionState, TaskItem, TaskManifest
from app.models.database import (
    TriggerTask,
    WorkflowDefinition,
    WorkflowExecution,
    WorkflowExecutionEvent,
    get_db_session,
)
from app.schemas import (
    TriggerTaskInputTask,
    TriggerTaskCreate,
    TriggerTaskResponse,
    WorkflowExecutionEventResponse,
    WorkflowExecutionResponse,
)
from app.pi_vuln_core.runner import build_runtime_framework_config, run_framework_config
from app.services.pi_vuln_adapter import (
    DbExecutionObserver,
    DbExecutionRecorder,
    build_core_tasks,
    write_final_task_manifest,
)
from app.services.fileserver_client import get_fileserver_client
from app.services.workflow_service import get_workflow_service


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _principal_id(principal: dict) -> str:
    return principal.get("user_id") or principal.get("subject") or principal.get("client_id") or "system"


def _project_ids(principal: dict) -> set[str]:
    return set(principal.get("project_ids") or [])


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

    def _normalize_trigger_tasks(
        self,
        *,
        input_tasks: List[TriggerTaskInputTask],
        workspace_root: Path,
        entry_input_task_type: str,
    ) -> List[TaskItem]:
        task_inputs_root = ensure_dir(workspace_root / "trigger_inputs")
        normalized: List[TaskItem] = []
        if not input_tasks:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="input_tasks must not be empty")
        for index, raw_task in enumerate(input_tasks, start=1):
            provided_task_type = (raw_task.task_type or "").strip()
            if provided_task_type and provided_task_type != entry_input_task_type:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"task {raw_task.task_id or index} task_type '{provided_task_type}' does not match entry_input_task_type '{entry_input_task_type}'",
                )
            task_id = raw_task.task_id or _new_id(f"task{index}")
            task_slug = sanitize_name(task_id)
            task_dir = ensure_dir(task_inputs_root / task_slug)
            input_dir = ensure_dir(task_dir / "input")
            markdown = raw_task.task_markdown
            if markdown is None and raw_task.task_md_path:
                markdown = Path(raw_task.task_md_path).read_text(encoding="utf-8")
            if markdown is None:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"task {task_id} missing task_markdown",
                )
            task_md_path = write_text(input_dir / "task.md", markdown.strip() + "\n")
            copied_inputs = self._copy_uploaded_inputs_to_task_dir(
                task_input_dir=input_dir,
                metadata=raw_task.metadata,
            )
            write_json(
                input_dir / "task.json",
                {
                    "task_id": task_id,
                    "task_type": entry_input_task_type,
                    "title": raw_task.title,
                    "metadata": raw_task.metadata,
                    "upstream_refs": raw_task.upstream_refs,
                    "copied_input_files": copied_inputs,
                },
            )
            normalized.append(
                TaskItem(
                    task_id=task_id,
                    task_type=entry_input_task_type,
                    title=raw_task.title,
                    task_md_path=abs_path(task_md_path),
                    metadata=dict(raw_task.metadata),
                    upstream_refs=list(raw_task.upstream_refs),
                )
            )
        return normalized

    def _copy_uploaded_inputs_to_task_dir(self, *, task_input_dir: Path, metadata: Dict[str, Any]) -> List[Dict[str, str]]:
        uploads = metadata.get("task_input_uploads")
        if not isinstance(uploads, list) or not uploads:
            return []
        copied: List[Dict[str, str]] = []
        data_mount_path = Path(get_config().fileserver_service.data_mount_path)
        assets_dir = ensure_dir(task_input_dir / "assets")

        for item in uploads:
            if not isinstance(item, dict):
                continue
            storage_key = str(item.get("storage_key") or "").strip()
            if not storage_key:
                continue
            relative_path_raw = str(item.get("relative_path") or item.get("filename") or "").strip()
            if not relative_path_raw:
                continue
            relative_path = Path(relative_path_raw)
            if relative_path.is_absolute() or ".." in relative_path.parts:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"invalid uploaded relative path: {relative_path_raw}",
                )
            storage_path = Path(storage_key)
            if storage_path.is_absolute() or ".." in storage_path.parts:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"invalid uploaded storage key: {storage_key}",
                )
            source_path = data_mount_path / storage_path
            if not source_path.exists() or not source_path.is_file():
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"uploaded file not found in pvc: {storage_key}",
                )
            target_path = assets_dir / relative_path
            ensure_dir(target_path.parent)
            shutil.copy2(source_path, target_path)
            copied.append(
                {
                    "relative_path": relative_path.as_posix(),
                    "target_path": abs_path(target_path),
                    "source_storage_key": storage_key,
                }
            )
        if copied:
            write_json(task_input_dir / "uploaded_assets_manifest.json", {"items": copied})
        return copied

    def _build_project_workspace_root(
        self,
        *,
        definition: WorkflowDefinition,
        trigger_id: str,
        execution_id: str,
        authorization_token: str | None,
        created_by: str,
    ) -> Path:
        subproject = get_fileserver_client().ensure_subproject(
            project_id=definition.project_id,
            authorization_token=authorization_token,
            created_by=created_by,
        )
        base_root = Path(subproject["root_dir"])
        return ensure_dir(
            base_root
            / "workflow-definitions"
            / sanitize_name(definition.id)
            / "trigger-tasks"
            / sanitize_name(trigger_id)
            / "executions"
            / sanitize_name(execution_id)
        )

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
        authorization_token: str | None = None,
    ) -> TriggerTaskResponse:
        definition = self._definition_or_404(db, definition_id)
        self._ensure_project_access(principal, definition.project_id)
        if not definition.enabled:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="workflow definition is disabled")
        if trigger_type == "http":
            if definition.trigger_type != "http" or not definition.trigger_enabled or not definition.is_active:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="workflow definition http trigger is unavailable")
        actor = _principal_id(principal)
        now = datetime.utcnow()
        trigger_id = _new_id("tt")
        execution_id = _new_id("exec")
        workspace_root = self._build_project_workspace_root(
            definition=definition,
            trigger_id=trigger_id,
            execution_id=execution_id,
            authorization_token=authorization_token,
            created_by=actor,
        )
        validated_definition = get_workflow_service().validate_definition_payload(definition.definition_json)
        entry_input_task_type = validated_definition.resolve_entry_input_task_type()
        normalized_tasks = self._normalize_trigger_tasks(
            input_tasks=payload.input_tasks,
            workspace_root=workspace_root,
            entry_input_task_type=entry_input_task_type,
        )
        input_manifest_path = write_task_manifest(workspace_root / "input" / "tasks.json", normalized_tasks)
        write_json(
            workspace_root / "execution_meta.json",
            {
                "workflow_definition_id": definition.id,
                "project_id": definition.project_id,
                "trigger_id": trigger_id,
                "execution_id": execution_id,
                "trigger_type": trigger_type,
                "entry_input_task_type": entry_input_task_type,
                "workspace_root": abs_path(workspace_root),
                "input_manifest_path": abs_path(input_manifest_path),
            },
        )
        manifest = TaskManifest(tasks=normalized_tasks)
        trigger = TriggerTask(
            id=trigger_id,
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
            id=execution_id,
            trigger_task_id=trigger.id,
            workflow_definition_id=definition.id,
            project_id=definition.project_id,
            status="pending",
            workspace_root=abs_path(workspace_root),
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

    def retry_trigger_task(
        self,
        db: Session,
        trigger_task_id: str,
        principal: dict,
        *,
        authorization_token: str | None = None,
    ) -> TriggerTaskResponse:
        trigger = self._trigger_or_404(db, trigger_task_id)
        self._ensure_project_access(principal, trigger.project_id)
        definition = self._definition_or_404(db, trigger.workflow_definition_id)
        payload = TriggerTaskCreate(
            input_tasks=[
                TriggerTaskInputTask(
                    task_id=item.task_id,
                    task_type=item.task_type,
                    title=item.title,
                    task_md_path=item.task_md_path,
                    metadata=item.metadata,
                    upstream_refs=item.upstream_refs,
                )
                for item in TaskManifest.model_validate(trigger.input_tasks_json).tasks
            ],
            priority=trigger.priority,
        )
        return self.create_trigger_task(
            db,
            definition.id,
            payload,
            principal,
            trigger_type=trigger.trigger_type,
            authorization_token=authorization_token,
        )

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
            workspace_root = Path(execution.workspace_root) if execution.workspace_root else self._build_workspace_root(execution.id, definition)
            input_manifest_path = workspace_root / "input" / "tasks.json"
            if not input_manifest_path.exists():
                input_manifest_path = write_task_manifest(input_manifest_path, TaskManifest.model_validate(trigger.input_tasks_json).tasks)

            execution.workspace_root = abs_path(workspace_root)
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
            service_manifest = TaskManifest.model_validate(trigger.input_tasks_json)
            runtime_config = build_runtime_framework_config(
                definition.definition_json,
                workspace_root=abs_path(workspace_root),
                execution_id=execution.id,
                input_task_file=service_manifest.tasks[0].task_md_path,
                input_task_id=service_manifest.tasks[0].task_id,
                output_dir=abs_path(workspace_root / "output"),
                summary_file=abs_path(workspace_root / "output" / "execution_summary.json"),
                runtime_mode="rest_service",
            )
            observer = DbExecutionObserver(execution.id)
            recorder = DbExecutionRecorder(abs_path(workspace_root), execution.id)
            artifacts = asyncio.run(
                run_framework_config(
                    runtime_config,
                    initial_tasks=build_core_tasks(service_manifest),
                    observer=observer,
                    recorder=recorder,
                )
            )
            output_manifest_path = write_final_task_manifest(
                workspace_root=workspace_root,
                final_tasks=artifacts.result.final_tasks,
                final_output_task_type=runtime_config.resolve_final_output_task_type(),
            )

            db.refresh(execution)
            db.refresh(trigger)
            self._set_terminal_state(
                db,
                execution=execution,
                trigger=trigger,
                execution_status="succeeded" if artifacts.result.success else "failed",
                message="execution completed" if artifacts.result.success else (artifacts.result.error or "execution failed"),
                output_manifest_path=abs_path(output_manifest_path),
                output_task_count=len(artifacts.result.final_tasks),
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
        except Exception as exc:
            from app.pi_vuln_core.observer import ExecutionCancelledError

            if isinstance(exc, ExecutionCancelledError):
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
                return
            if execution is None or trigger is None:
                raise
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
