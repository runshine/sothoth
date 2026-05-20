from __future__ import annotations

from datetime import datetime
from unittest import mock

from app.models.database import TriggerTask, WorkflowExecution, WorkflowExecutionEvent
from app.services.execution_service import ExecutionService


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def limit(self, *_args, **_kwargs):
        return self

    def all(self):
        return list(self._rows)


class _FakeDb:
    def __init__(self, rows=None):
        self.rows = list(rows or [])
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    def query(self, _model):
        return _FakeQuery(self.rows)


def test_set_terminal_state_records_abnormal_reason_event() -> None:
    service = ExecutionService()
    db = _FakeDb()
    trigger = TriggerTask(
        id="tt-1",
        workflow_definition_id="wf-1",
        workflow_definition_version_id="wfver-1",
        project_id="proj-1",
        trigger_type="manual",
        input_tasks_json={"tasks": []},
        status="running",
        message="running",
    )
    execution = WorkflowExecution(
        id="exec-1",
        trigger_task_id="tt-1",
        workflow_definition_id="wf-1",
        workflow_definition_version_id="wfver-1",
        project_id="proj-1",
        attempt_no=1,
        status="running",
        dispatch_status="running",
    )

    service._set_terminal_state(
        db,
        execution=execution,
        trigger=trigger,
        execution_status="failed",
        message="dispatcher crashed",
    )

    assert trigger.latest_abnormal_reason_json is not None
    assert trigger.latest_abnormal_reason_json["code"] == "dispatch_failed"
    abnormal_events = [item for item in db.added if isinstance(item, WorkflowExecutionEvent) and item.event_type == "abnormal_reason_recorded"]
    assert len(abnormal_events) == 1
    assert abnormal_events[0].payload_json["reason"]["code"] == "dispatch_failed"


def test_abnormal_reason_history_reads_recorded_events() -> None:
    service = ExecutionService()
    event = WorkflowExecutionEvent(
        id="evt-1",
        execution_id="exec-1",
        event_type="abnormal_reason_recorded",
        created_at=datetime(2026, 5, 20, 12, 0, 0),
        payload_json={
            "reason": {
                "is_abnormal": True,
                "category": "runtime",
                "code": "dispatch_failed",
                "title": "调度失败",
                "message": "dispatcher crashed",
                "terminal": True,
                "source_layer": "task",
                "status": "failed",
                "service": "dataflow-vuln-scanner",
                "stage_name": None,
                "item_key": None,
                "downstream_task_id": "exec-1",
                "downstream_service": "workflow_execution",
                "first_seen_at": None,
                "last_seen_at": None,
                "evidence": [],
                "recommended_action": None,
                "related_event_ids": [],
            }
        },
    )
    trigger = TriggerTask(
        id="tt-1",
        workflow_definition_id="wf-1",
        workflow_definition_version_id="wfver-1",
        project_id="proj-1",
        trigger_type="manual",
        input_tasks_json={"tasks": []},
        status="failed",
    )
    execution = WorkflowExecution(
        id="exec-1",
        trigger_task_id="tt-1",
        workflow_definition_id="wf-1",
        workflow_definition_version_id="wfver-1",
        project_id="proj-1",
        attempt_no=1,
        status="failed",
    )
    db = _FakeDb(rows=[event])

    with mock.patch.object(service, "_list_executions_for_trigger", return_value=[execution]):
        history = service._abnormal_reason_history(db, trigger)

    assert len(history) == 1
    assert history[0]["event_id"] == "evt-1"
    assert history[0]["reason"]["code"] == "dispatch_failed"
