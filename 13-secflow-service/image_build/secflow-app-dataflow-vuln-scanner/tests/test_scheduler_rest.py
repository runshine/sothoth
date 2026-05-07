from __future__ import annotations

from pathlib import Path

from app.config import get_config
from app.models.database import TriggerTask, WorkflowDefinition, WorkflowExecution, get_db_session
from app.services.scheduler import SchedulerService


def test_scheduler_claim_respects_single_owner_and_definition_concurrency(
    service_config_path: Path,
    framework_config_payload: dict,
):
    config = get_config()
    config.scheduler.enabled = True

    db = get_db_session()
    try:
        definition = WorkflowDefinition(
            id="wfd-sched-demo",
            name="sched-demo",
            description="demo",
            project_id="default",
            template_kind="vuln_scan_default",
            config_payload_json={},
            definition_json=framework_config_payload,
            root_workflow_id="vuln_scan_pipeline",
            trigger_type="manual",
            trigger_enabled=False,
            is_active=True,
            enabled=True,
            max_concurrency=1,
            priority_default=100,
            max_retry_count=3,
            execution_timeout_seconds=7200,
            created_by="tester",
            updated_by="tester",
        )
        first_trigger = TriggerTask(
            id="tt-sched-1",
            workflow_definition_id=definition.id,
            project_id="default",
            trigger_type="manual",
            input_tasks_json={"tasks": []},
            priority=100,
            status="pending",
            submitted_by="tester",
            retry_count=0,
            max_retry_count=3,
        )
        second_trigger = TriggerTask(
            id="tt-sched-2",
            workflow_definition_id=definition.id,
            project_id="default",
            trigger_type="manual",
            input_tasks_json={"tasks": []},
            priority=100,
            status="pending",
            submitted_by="tester",
            retry_count=0,
            max_retry_count=3,
        )
        first_execution = WorkflowExecution(
            id="exec-sched-1",
            trigger_task_id=first_trigger.id,
            workflow_definition_id=definition.id,
            project_id="default",
            attempt_no=1,
            status="pending",
        )
        second_execution = WorkflowExecution(
            id="exec-sched-2",
            trigger_task_id=second_trigger.id,
            workflow_definition_id=definition.id,
            project_id="default",
            attempt_no=1,
            status="pending",
        )
        first_trigger.latest_execution_id = first_execution.id
        second_trigger.latest_execution_id = second_execution.id
        db.add_all([definition, first_trigger, second_trigger, first_execution, second_execution])
        db.commit()
    finally:
        db.close()

    config.scheduler.pod_id = "pod-a"
    scheduler_a = SchedulerService()
    first_execution_id = scheduler_a._claim_next_execution()
    assert first_execution_id is not None

    config.scheduler.pod_id = "pod-b"
    scheduler_b = SchedulerService()
    second_execution_id = scheduler_b._claim_next_execution()
    assert second_execution_id is None

    db = get_db_session()
    try:
        running = db.query(WorkflowExecution).filter(WorkflowExecution.status == "running").all()
        pending = db.query(WorkflowExecution).filter(WorkflowExecution.status == "pending").all()
        assert len(running) == 1
        assert running[0].owner_pod_id == "pod-a"
        assert len(pending) == 1
    finally:
        db.close()
