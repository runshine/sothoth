from __future__ import annotations

from datetime import datetime, timedelta

from app.models.database import TriggerTask, WorkflowExecution, get_db_session
from app.schemas import ScanProfileCreateRequest, ScanTaskCreateRequest
from app.services.execution_service import get_execution_service
from app.services.scheduler import SchedulerService
from app.services.workflow_service import get_workflow_service


def _create_profile(db):
    return get_workflow_service().create_profile(
        db,
        ScanProfileCreateRequest(
            project_id="default",
            name="recoverable profile",
            description="requeue",
            template_kind="vuln_scan_default",
            config_payload={
                "model": "mock/model",
                "thinking": "high",
                "max_review_cycles": 2,
                "worker_timeout": 60,
                "advisor_timeout": 60,
                "result_review_concurrency": 2,
                "runtime_overrides": {},
            },
            is_default=True,
            enabled=True,
            default_priority=100,
            max_retry_count=1,
            execution_timeout_seconds=600,
        ),
        {"user_id": "tester", "project_ids": ["default"]},
    )


def test_cleanup_requeues_orphaned_execution(service_config_path):
    db = get_db_session()
    try:
        profile = _create_profile(db)
        get_execution_service().create_scan_task(
            db,
            ScanTaskCreateRequest(
                project_id="default",
                profile_id=profile.profile_id,
                title="demo",
                task_markdown="# Demo\n",
                artifact_refs=[],
                runtime_overrides={},
            ),
            {"user_id": "tester", "project_ids": ["default"]},
        )
    finally:
        db.close()

    scheduler = SchedulerService()
    execution_id = scheduler._claim_next_execution()
    assert execution_id is not None

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        assert execution is not None
        execution.status = "running"
        execution.owner_pod_id = "dead-pod"
        execution.lease_expires_at = datetime.utcnow() - timedelta(seconds=30)
        db.add(execution)
        trigger = db.get(TriggerTask, execution.trigger_task_id)
        assert trigger is not None
        trigger.status = "running"
        db.add(trigger)
        db.commit()
    finally:
        db.close()

    scheduler._cleanup_once()

    db = get_db_session()
    try:
        executions = db.query(WorkflowExecution).order_by(WorkflowExecution.attempt_no.asc()).all()
        assert len(executions) == 2
        assert executions[0].status == "orphaned"
        assert executions[1].status == "pending"
        trigger = db.get(TriggerTask, executions[0].trigger_task_id)
        assert trigger is not None
        assert trigger.retry_count == 1
        assert trigger.latest_execution_id == executions[1].id
        assert trigger.status == "pending"
    finally:
        db.close()
