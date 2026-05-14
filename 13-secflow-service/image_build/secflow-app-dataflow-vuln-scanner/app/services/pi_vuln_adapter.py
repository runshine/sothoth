from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from app.artifacts.io import abs_path, ensure_dir, write_task_manifest
from app.models.contracts import TaskItem, TaskManifest
from app.models.database import TriggerTask, WorkflowExecution, WorkflowExecutionEvent, get_db_session
from app.pi_vuln_core.engine.models import TaskItem as CoreTaskItem
from app.pi_vuln_core.observer import ExecutionCancelledError, ExecutionObserver
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _write_event(
    *,
    execution_id: str,
    event_type: str,
    message: str,
    level: str = "info",
    stage_id: str | None = None,
    round_no: int | None = None,
    payload_json: dict[str, Any] | None = None,
) -> None:
    db = get_db_session()
    try:
        db.add(
            WorkflowExecutionEvent(
                id=_new_id("evt"),
                execution_id=execution_id,
                event_type=event_type,
                stage_id=stage_id,
                round_no=round_no,
                level=level,
                message=message,
                payload_json=payload_json or {},
            )
        )
        db.commit()
    finally:
        db.close()


class DbExecutionObserver(ExecutionObserver):
    def __init__(self, execution_id: str):
        self.execution_id = execution_id

    def _load_execution(self, db):
        execution = db.get(WorkflowExecution, self.execution_id)
        if execution is None:
            raise ExecutionCancelledError("execution disappeared")
        trigger = db.get(TriggerTask, execution.trigger_task_id)
        return execution, trigger

    async def check_cancel(self, checkpoint: str, **payload: Any) -> None:
        db = get_db_session()
        try:
            execution, trigger = self._load_execution(db)
            cancelled = execution.status in {"cancel_requested", "cancelled"} or (
                trigger is not None and trigger.status in {"cancel_requested", "cancelled"}
            )
        finally:
            db.close()
        if cancelled:
            _write_event(
                execution_id=self.execution_id,
                event_type="execution_cancel_checkpoint",
                message=f"cancel requested at {checkpoint}",
                level="warning",
                stage_id=payload.get("stage_id"),
                round_no=payload.get("cycle"),
                payload_json={"checkpoint": checkpoint, **payload},
            )
            raise ExecutionCancelledError(f"execution cancelled at {checkpoint}")

    async def on_stage_started(self, **payload: Any) -> None:
        db = get_db_session()
        try:
            execution, _ = self._load_execution(db)
            execution.current_stage_id = payload.get("stage_id")
            db.add(execution)
            db.commit()
        finally:
            db.close()
        _write_event(
            execution_id=self.execution_id,
            event_type="stage_started",
            message=f"stage {payload.get('stage_id')} started",
            stage_id=payload.get("stage_id"),
            payload_json=payload,
        )

    async def on_stage_completed(self, **payload: Any) -> None:
        _write_event(
            execution_id=self.execution_id,
            event_type="stage_completed",
            message=f"stage {payload.get('stage_id')} completed",
            stage_id=payload.get("stage_id"),
            payload_json=payload,
        )

    async def on_stage_failed(self, **payload: Any) -> None:
        _write_event(
            execution_id=self.execution_id,
            event_type="stage_failed",
            message=f"stage {payload.get('stage_id')} failed",
            stage_id=payload.get("stage_id"),
            level="error",
            payload_json=payload,
        )

    async def on_cycle_started(self, **payload: Any) -> None:
        _write_event(
            execution_id=self.execution_id,
            event_type="atomic_cycle_started",
            message=f"cycle {payload.get('cycle')} started",
            round_no=payload.get("cycle"),
            payload_json=payload,
        )

    async def on_cycle_completed(self, **payload: Any) -> None:
        level = "warning" if payload.get("outcome") != "passed" else "info"
        _write_event(
            execution_id=self.execution_id,
            event_type="atomic_cycle_completed",
            message=f"cycle {payload.get('cycle')} completed with {payload.get('outcome')}",
            round_no=payload.get("cycle"),
            level=level,
            payload_json=payload,
        )

    async def on_summary_completed(self, **payload: Any) -> None:
        _write_event(
            execution_id=self.execution_id,
            event_type="summary_completed",
            message=f"summary completed for cycle {payload.get('cycle')}",
            round_no=payload.get("cycle"),
            payload_json=payload,
        )

    async def on_workflow_abnormal_exit(self, **payload: Any) -> None:
        _write_event(
            execution_id=self.execution_id,
            event_type="workflow_abnormal_exit",
            message=str(payload.get("error") or "workflow abnormal exit"),
            level="error",
            payload_json=payload,
        )


class DbExecutionRecorder(ExecutionRecorder):
    def __init__(self, workspace_root: str, execution_id: str):
        super().__init__(workspace_root)
        self.execution_id = execution_id

    async def record_plugin(self, *args, **kwargs) -> None:
        await super().record_plugin(*args, **kwargs)
        _write_event(
            execution_id=self.execution_id,
            event_type="plugin_completed",
            message=f"plugin {kwargs['plugin_id']} finished with {kwargs['result'].code.value}",
            level="warning" if kwargs["result"].code.value.startswith("error") else "info",
            payload_json={
                "plugin_id": kwargs["plugin_id"],
                "phase": kwargs["phase"],
                "sequence": kwargs["sequence"],
                "duration_ms": kwargs["result"].duration_ms,
                "result_code": kwargs["result"].code.value,
                "message": kwargs["result"].message,
                "data": kwargs["result"].data,
            },
        )

    async def record_global_review(self, *args, **kwargs) -> None:
        await super().record_global_review(*args, **kwargs)
        _write_event(
            execution_id=self.execution_id,
            event_type="global_review_result",
            message=f"global review {kwargs['advisor_id']} {'passed' if kwargs['passed'] else 'failed'}",
            round_no=kwargs["cycle"],
            level="info" if kwargs["passed"] else "warning",
            payload_json={
                "advisor_id": kwargs["advisor_id"],
                "passed": kwargs["passed"],
                "verdict": kwargs.get("verdict"),
                "agent_id": kwargs.get("agent_id"),
                "role_name": kwargs.get("role_name"),
                "feedback": kwargs["content"],
                "feedback_detail": kwargs.get("detail_feedback"),
            },
        )

    async def record_result_review(self, *args, **kwargs) -> None:
        await super().record_result_review(*args, **kwargs)
        _write_event(
            execution_id=self.execution_id,
            event_type="result_review_result",
            message=f"result review {kwargs['advisor_id']} {'passed' if kwargs['passed'] else 'failed'} for {kwargs['result_file']}",
            round_no=kwargs["cycle"],
            level="info" if kwargs["passed"] else "warning",
            payload_json={
                "advisor_id": kwargs["advisor_id"],
                "result_file": kwargs["result_file"],
                "passed": kwargs["passed"],
                "verdict": kwargs.get("verdict"),
                "agent_id": kwargs.get("agent_id"),
                "role_name": kwargs.get("role_name"),
                "feedback": kwargs["content"],
                "feedback_detail": kwargs.get("detail_feedback"),
            },
        )

    async def record_abnormal_exit(self, work_dir: str, error: str, context: dict[str, Any] | None = None) -> None:
        await super().record_abnormal_exit(work_dir, error, context)
        _write_event(
            execution_id=self.execution_id,
            event_type="abnormal_exit",
            message=error,
            level="error",
            payload_json={"work_dir": work_dir, "context": context or {}},
        )


def build_core_tasks(manifest: TaskManifest) -> list[CoreTaskItem]:
    return [
        CoreTaskItem(
            id=item.task_id,
            file=item.task_md_path,
            source_stage="input",
        )
        for item in manifest.tasks
    ]


def write_final_task_manifest(
    *,
    workspace_root: str | Path,
    final_tasks: list[CoreTaskItem],
    final_output_task_type: str,
) -> Path:
    output_dir = ensure_dir(Path(workspace_root) / "output")
    normalized = [
        TaskItem(
            task_id=item.id,
            task_type=final_output_task_type,
            title=Path(item.file).stem,
            task_md_path=abs_path(item.file),
            metadata={"source_stage": item.source_stage},
            upstream_refs=[],
        )
        for item in final_tasks
    ]
    return write_task_manifest(output_dir / "tasks.json", normalized)
