from __future__ import annotations

from datetime import timedelta
from unittest.mock import AsyncMock, patch

from app.model import ScheduleJob
from app.service.schedule_manager import get_schedule_manager, get_scheduler_runtime, get_worker_runtime, utcnow


def test_scheduler_dispatches_due_job(db_session):
    job = ScheduleJob(
        project_id="proj1",
        name="due-job",
        description="",
        enabled=True,
        trigger_type="interval",
        interval_seconds=60,
        timezone="UTC",
        target_method="POST",
        target_url="http://example/api/tasks",
        target_headers={},
        target_query={},
        target_body_template={},
        auth_mode="none",
        success_status_codes=[200],
        dedupe_window_seconds=0,
        next_run_at=utcnow() - timedelta(seconds=1),
        created_by="tester",
        updated_by="tester",
    )
    db_session.add(job)
    db_session.commit()

    runtime = get_scheduler_runtime()
    runtime.config.poll_interval_seconds = 1

    async def run_once():
        await runtime.manager.process_due_jobs()
        execution = get_schedule_manager().list_executions(db_session, "proj1", job.id)[1][0]
        with patch("app.service.schedule_manager.get_shared_async_client") as client_factory:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=type("Resp", (), {"status_code": 200, "json": lambda self: {"task_id": "task-1"}, "text": ""})())
            client_factory.return_value = mock_client
            await get_worker_runtime().manager.dispatch_execution(execution.id)

    __import__("asyncio").run(run_once())

    total, executions = get_schedule_manager().list_executions(db_session, "proj1", job.id)
    assert total == 1
    assert executions[0].status == "succeeded"


def test_scheduler_keeps_queue_unbounded_but_reserves_only_with_capacity(db_session):
    manager = get_schedule_manager()
    manager.cfg.limits.project_default_concurrency = 1
    manager.cfg.limits.target_default_concurrency = 1

    job = ScheduleJob(
        project_id="proj-cap",
        name="cap-job",
        description="",
        enabled=True,
        trigger_type="manual",
        timezone="UTC",
        target_method="POST",
        target_url="http://example/api/tasks",
        target_headers={},
        target_query={},
        target_body_template={},
        auth_mode="none",
        success_status_codes=[200],
        dedupe_window_seconds=0,
        max_concurrency=1,
        created_by="tester",
        updated_by="tester",
    )
    db_session.add(job)
    db_session.commit()

    first = manager._create_execution_record(db_session, job, "manual", scheduled_for=utcnow(), dedupe_key="manual:first")
    first.status = "running"
    second = manager._create_execution_record(db_session, job, "manual", scheduled_for=utcnow(), dedupe_key="manual:second")
    db_session.commit()

    execution, claimed = manager.claim_execution_if_capacity(db_session, second.id)
    assert execution is not None
    assert claimed is False
    assert execution.status == "queued"
    assert execution.capacity_reject_count == 1
    assert execution.capacity_reject_reason == "capacity_full"


def test_requeue_pending_executions_only_enqueues_reserved(db_session):
    manager = get_schedule_manager()
    manager.cfg.limits.project_default_concurrency = 1
    manager.cfg.limits.target_default_concurrency = 1

    job = ScheduleJob(
        project_id="proj-requeue",
        name="requeue-job",
        description="",
        enabled=True,
        trigger_type="manual",
        timezone="UTC",
        target_method="POST",
        target_url="http://example/api/tasks",
        target_headers={},
        target_query={},
        target_body_template={},
        auth_mode="none",
        success_status_codes=[200],
        dedupe_window_seconds=0,
        max_concurrency=1,
        created_by="tester",
        updated_by="tester",
    )
    db_session.add(job)
    db_session.commit()

    blocked = manager._create_execution_record(db_session, job, "manual", scheduled_for=utcnow(), dedupe_key="manual:blocked")
    blocked.status = "running"
    waiting = manager._create_execution_record(db_session, job, "manual", scheduled_for=utcnow(), dedupe_key="manual:waiting")
    db_session.commit()

    __import__("asyncio").run(manager.requeue_pending_executions())

    db_session.refresh(waiting)
    assert waiting.status == "queued"
    assert waiting.capacity_reject_count == 1
