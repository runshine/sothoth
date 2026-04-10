from __future__ import annotations

from pathlib import Path

from app.config import get_config
from app.models.database import WorkflowExecution, get_db_session
from app.schemas import TriggerTaskCreate, WorkflowDefinitionCreate
from app.services.execution_service import get_execution_service
from app.services.scheduler import SchedulerService
from app.services.workflow_service import get_workflow_service


def test_scheduler_claim_respects_single_owner_and_definition_concurrency(
    service_config_path: Path,
    framework_config_payload: dict,
):
    config = get_config()
    config.scheduler.enabled = True

    db = get_db_session()
    try:
        definition = get_workflow_service().create_definition(
            db,
            WorkflowDefinitionCreate(
                name="sched-demo",
                description="demo",
                project_id="default",
                definition_json=framework_config_payload,
                is_active=True,
                enabled=True,
                max_concurrency=1,
            ),
            {"user_id": "tester", "project_ids": ["default"]},
        )

        payload = TriggerTaskCreate(
            input_tasks=[
                {
                    "task_id": "task-1",
                    "task_type": "package_list",
                    "title": "Task 1",
                    "task_markdown": "# Task 1\n",
                    "metadata": {},
                    "upstream_refs": [],
                }
            ]
        )
        get_execution_service().create_trigger_task(
            db,
            definition.id,
            payload,
            {"user_id": "tester", "project_ids": ["default"]},
            trigger_type="manual",
        )
        get_execution_service().create_trigger_task(
            db,
            definition.id,
            TriggerTaskCreate(
                input_tasks=[
                    {
                        "task_id": "task-2",
                        "task_type": "package_list",
                        "title": "Task 2",
                        "task_markdown": "# Task 2\n",
                        "metadata": {},
                        "upstream_refs": [],
                    }
                ]
            ),
            {"user_id": "tester", "project_ids": ["default"]},
            trigger_type="manual",
        )
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
