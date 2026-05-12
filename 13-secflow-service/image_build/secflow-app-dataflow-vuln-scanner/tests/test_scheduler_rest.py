from __future__ import annotations

from pathlib import Path

from app.config import get_config
from app.models.database import SchedulerWorker, TriggerTask, WorkflowDefinition, WorkflowExecution, get_db_session
from app.services.scheduler import SchedulerService


def test_scheduler_claim_allows_multiple_running_executions_per_definition(
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
    assert second_execution_id is not None

    db = get_db_session()
    try:
        running = db.query(WorkflowExecution).filter(WorkflowExecution.status == "running").all()
        pending = db.query(WorkflowExecution).filter(WorkflowExecution.status == "pending").all()
        assert len(running) == 2
        assert {item.owner_pod_id for item in running} == {"pod-a", "pod-b"}
        assert pending == []
    finally:
        db.close()


def test_manager_role_does_not_register_or_execute_worker(service_config_path: Path):
    config = get_config()
    config.scheduler.enabled = True
    config.scheduler.role = "manager"
    config.scheduler.pod_id = "manager-pod"

    scheduler = SchedulerService()
    scheduler._heartbeat_once()

    db = get_db_session()
    try:
        assert db.get(SchedulerWorker, "manager-pod") is None
    finally:
        db.close()
    assert scheduler.start_execution_now("exec-should-not-run") is False
    assert scheduler.health_payload()["worker_enabled"] == "false"


def test_worker_role_registers_single_capacity_worker(service_config_path: Path):
    config = get_config()
    config.scheduler.enabled = True
    config.scheduler.role = "worker"
    config.scheduler.pod_id = "worker-pod"
    config.scheduler.worker_capacity = 1

    scheduler = SchedulerService()
    scheduler._heartbeat_once()

    db = get_db_session()
    try:
        worker = db.get(SchedulerWorker, "worker-pod")
        assert worker is not None
        assert worker.capacity == 1
        assert worker.metadata_json["role"] == "worker"
    finally:
        db.close()
