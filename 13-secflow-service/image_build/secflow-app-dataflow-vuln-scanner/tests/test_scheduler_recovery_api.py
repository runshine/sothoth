from __future__ import annotations

from datetime import timedelta

from app.models.database import DfvsTaskListProjection, RunIndex, SchedulerWorker, SchedulerWorkerSlotReservation, TriggerTask, WorkflowExecution, WorkflowExecutionEvent, get_db_session
from app.schemas import ScanProfileCreateRequest, ScanTaskCreateRequest
from app.services.execution_service import get_execution_service
from app.services.scheduler import SchedulerService
from app.services.workflow_service import get_workflow_service
from app.time_utils import now_local


def _create_profile(db):
    return get_workflow_service().create_profile(
        db,
        ScanProfileCreateRequest(
            project_id="default",
            name="recoverable profile",
            description="scheduler cleanup",
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


def test_cleanup_does_not_mutate_running_execution(service_config_path):
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
        assert len(executions) == 1
        assert executions[0].status == "running"
        assert executions[0].message == f"starting by {scheduler.pod_id}"
        trigger = db.get(TriggerTask, executions[0].trigger_task_id)
        assert trigger is not None
        assert trigger.retry_count == 0
        assert trigger.latest_execution_id == executions[0].id
        assert trigger.status == "running"
    finally:
        db.close()


def test_cleanup_backfills_missing_owner_from_reservation(service_config_path):
    db = get_db_session()
    try:
        execution_id = "exec-recover-owner-from-reservation"
        db.add(
            SchedulerWorker(
                pod_id="worker-recover-a",
                host_name="worker-recover-a",
                capacity=2,
                running_count=0,
                status="active",
                metadata_json={"advertise_url": "http://worker-recover-a:8080"},
            )
        )
        trigger = TriggerTask(
            id="tt-recover-owner-from-reservation",
            workflow_definition_id="wfd-recover-owner-from-reservation",
            project_id="default",
            trigger_type="manual",
            input_tasks_json={"tasks": []},
            priority=100,
            status="pending",
            submitted_by="tester",
            retry_count=0,
            max_retry_count=3,
            latest_execution_id=execution_id,
        )
        execution = WorkflowExecution(
            id=execution_id,
            trigger_task_id=trigger.id,
            workflow_definition_id=trigger.workflow_definition_id,
            project_id="default",
            attempt_no=1,
            status="pending",
            owner_pod_id=None,
            worker_url="http://worker-recover-a:8080",
            worker_job_id="job-recover-owner-a",
            dispatch_status="queued",
        )
        reservation = SchedulerWorkerSlotReservation(
            reservation_id="resv-recover-owner-a",
            worker_pod_id="worker-recover-a",
            execution_id=execution_id,
            status="reserved",
            lease_expires_at=now_local() + timedelta(minutes=5),
        )
        db.add_all([trigger, execution, reservation])
        db.commit()
    finally:
        db.close()

    scheduler = SchedulerService()
    scheduler._cleanup_once()

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        assert execution is not None
        assert execution.owner_pod_id == "worker-recover-a"
    finally:
        db.close()


def test_cleanup_backfills_missing_owner_from_worker_url(service_config_path):
    db = get_db_session()
    try:
        execution_id = "exec-recover-owner-from-url"
        db.add(
            SchedulerWorker(
                pod_id="worker-recover-b",
                host_name="worker-recover-b",
                capacity=2,
                running_count=0,
                status="active",
                metadata_json={"advertise_url": "http://worker-recover-b:8080"},
            )
        )
        trigger = TriggerTask(
            id="tt-recover-owner-from-url",
            workflow_definition_id="wfd-recover-owner-from-url",
            project_id="default",
            trigger_type="manual",
            input_tasks_json={"tasks": []},
            priority=100,
            status="pending",
            submitted_by="tester",
            retry_count=0,
            max_retry_count=3,
            latest_execution_id=execution_id,
        )
        execution = WorkflowExecution(
            id=execution_id,
            trigger_task_id=trigger.id,
            workflow_definition_id=trigger.workflow_definition_id,
            project_id="default",
            attempt_no=1,
            status="pending",
            owner_pod_id=None,
            worker_url="http://worker-recover-b:8080",
            worker_job_id="job-recover-owner-b",
            dispatch_status="queued",
        )
        db.add_all([trigger, execution])
        db.commit()
    finally:
        db.close()

    scheduler = SchedulerService()
    scheduler._cleanup_once()

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        assert execution is not None
        assert execution.owner_pod_id == "worker-recover-b"
    finally:
        db.close()


def test_cleanup_requeues_stuck_dispatch_execution(service_config_path):
    db = get_db_session()
    try:
        execution_id = "exec-stuck-dispatch-timeout"
        trigger = TriggerTask(
            id="tt-stuck-dispatch-timeout",
            workflow_definition_id="wfd-stuck-dispatch-timeout",
            project_id="default",
            trigger_type="manual",
            input_tasks_json={"tasks": []},
            priority=100,
            status="dispatching",
            submitted_by="tester",
            retry_count=0,
            max_retry_count=3,
            latest_execution_id=execution_id,
        )
        execution = WorkflowExecution(
            id=execution_id,
            trigger_task_id=trigger.id,
            workflow_definition_id=trigger.workflow_definition_id,
            project_id="default",
            attempt_no=1,
            status="dispatching",
            owner_pod_id="worker-stuck-timeout",
            worker_url="http://worker-stuck-timeout:8080",
            worker_job_id="job-stuck-timeout",
            dispatch_status="queued",
            updated_at=now_local() - timedelta(minutes=5),
        )
        reservation = SchedulerWorkerSlotReservation(
            reservation_id="rsv-stuck-dispatch-timeout",
            worker_pod_id="worker-stuck-timeout",
            execution_id=execution_id,
            status="reserved",
            lease_expires_at=now_local() + timedelta(minutes=5),
        )
        db.add_all([trigger, execution, reservation])
        db.commit()
    finally:
        db.close()

    scheduler = SchedulerService()
    scheduler._cleanup_once()

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        trigger = db.get(TriggerTask, "tt-stuck-dispatch-timeout")
        reservation = db.query(SchedulerWorkerSlotReservation).filter(SchedulerWorkerSlotReservation.execution_id == execution_id).first()
        assert execution is not None
        assert trigger is not None
        assert execution.status == "pending"
        assert execution.owner_pod_id is None
        assert execution.worker_job_id is None
        assert execution.dispatch_status is None
        assert trigger.status == "pending"
        assert reservation is None
    finally:
        db.close()


def test_cleanup_requeues_stuck_starting_execution_before_process_launch(service_config_path):
    db = get_db_session()
    try:
        execution_id = "exec-stuck-starting-timeout"
        trigger = TriggerTask(
            id="tt-stuck-starting-timeout",
            workflow_definition_id="wfd-stuck-starting-timeout",
            project_id="default",
            trigger_type="manual",
            input_tasks_json={"tasks": []},
            priority=100,
            status="dispatching",
            submitted_by="tester",
            retry_count=0,
            max_retry_count=3,
            latest_execution_id=execution_id,
        )
        execution = WorkflowExecution(
            id=execution_id,
            trigger_task_id=trigger.id,
            workflow_definition_id=trigger.workflow_definition_id,
            project_id="default",
            attempt_no=1,
            status="starting",
            owner_pod_id="worker-starting-timeout",
            worker_url="http://worker-starting-timeout:8080",
            worker_job_id="job-starting-timeout",
            dispatch_status="starting",
            process_pid=None,
            process_started_at=None,
            updated_at=now_local() - timedelta(minutes=5),
        )
        db.add_all([trigger, execution])
        db.commit()
    finally:
        db.close()

    SchedulerService()._cleanup_once()

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        trigger = db.get(TriggerTask, "tt-stuck-starting-timeout")
        assert execution is not None
        assert trigger is not None
        assert execution.status == "pending"
        assert execution.owner_pod_id is None
        assert execution.worker_job_id is None
        assert execution.dispatch_status is None
        assert execution.process_status == "not_started"
        assert trigger.status == "pending"
    finally:
        db.close()


def test_requeue_before_process_start_records_normalized_reason_metadata(service_config_path):
    db = get_db_session()
    try:
        execution_id = "exec-projection-conflict-requeue"
        trigger = TriggerTask(
            id="tt-projection-conflict-requeue",
            workflow_definition_id="wfd-projection-conflict-requeue",
            project_id="default",
            trigger_type="manual",
            input_tasks_json={"tasks": []},
            priority=100,
            status="dispatching",
            submitted_by="tester",
            retry_count=0,
            max_retry_count=3,
            latest_execution_id=execution_id,
        )
        execution = WorkflowExecution(
            id=execution_id,
            trigger_task_id=trigger.id,
            workflow_definition_id=trigger.workflow_definition_id,
            project_id="default",
            attempt_no=1,
            status="starting",
            owner_pod_id="worker-0",
            worker_url="http://worker-0:8080",
            worker_job_id="job-0",
            dispatch_status="starting",
            process_pid=None,
            process_started_at=None,
        )
        db.add_all([trigger, execution])
        db.commit()
    finally:
        db.close()

    scheduler = SchedulerService()
    assert scheduler._requeue_if_not_process_started(
        execution_id,
        "IntegrityError: Duplicate entry 'tt-projection-conflict-requeue' for key 'task_list_projection.PRIMARY'",
    )

    db = get_db_session()
    try:
        events = (
            db.query(WorkflowExecutionEvent)
            .filter(WorkflowExecutionEvent.execution_id == execution_id)
            .order_by(WorkflowExecutionEvent.created_at.asc())
            .all()
        )
        assert {event.event_type for event in events} >= {
            "worker_job_start_failed",
            "worker_job_requeued_before_process_start",
        }
        for event in events:
            if event.event_type not in {"worker_job_start_failed", "worker_job_requeued_before_process_start"}:
                continue
            payload = event.payload_json or {}
            assert event.message in {
                "startup metadata write failed; task requeued before process start",
                "task list projection write conflict; requeued before process start",
            }
            assert payload["reason_category"] == "startup_metadata_write_conflict"
            assert payload["projection_write_involved"] is True
            assert payload["session_rollback_applied"] is True
            assert "raw_error" in payload
    finally:
        db.close()


def test_cleanup_reconciles_orphan_cancel_requested_execution(service_config_path):
    db = get_db_session()
    try:
        execution_id = "exec-orphan-cancel-reconcile"
        trigger = TriggerTask(
            id="tt-orphan-cancel-reconcile",
            workflow_definition_id="wfd-orphan-cancel-reconcile",
            project_id="default",
            trigger_type="manual",
            input_tasks_json={"tasks": []},
            priority=100,
            status="running",
            public_status="running",
            control_state="cancel_requested",
            message="cancel requested",
            submitted_by="tester",
            retry_count=0,
            max_retry_count=3,
            latest_execution_id=execution_id,
        )
        execution = WorkflowExecution(
            id=execution_id,
            trigger_task_id=trigger.id,
            workflow_definition_id=trigger.workflow_definition_id,
            project_id="default",
            attempt_no=1,
            status="pending",
            public_status="pending",
            control_state="cancel_requested",
            dispatch_status=None,
            owner_pod_id=None,
            worker_job_id=None,
            worker_url=None,
            process_status="not_started",
            message="worker dispatch failed, requeued: timeout",
        )
        db.add_all([trigger, execution])
        db.commit()
    finally:
        db.close()

    SchedulerService()._cleanup_once()

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        trigger = db.get(TriggerTask, "tt-orphan-cancel-reconcile")
        assert execution is not None
        assert trigger is not None
        assert execution.status == "cancelled"
        assert trigger.status == "cancelled"
        event = (
            db.query(WorkflowExecutionEvent)
            .filter(
                WorkflowExecutionEvent.execution_id == execution.id,
                WorkflowExecutionEvent.event_type == "task_cancel_reconciled",
            )
            .order_by(WorkflowExecutionEvent.created_at.desc())
            .first()
        )
        assert event is not None
    finally:
        db.close()


def test_active_reconcile_refreshes_stale_running_projection(service_config_path):
    db = get_db_session()
    try:
        execution_id = "exec-active-reconcile-stale-projection"
        trigger = TriggerTask(
            id="tt-active-reconcile-stale-projection",
            workflow_definition_id="wfd-active-reconcile-stale-projection",
            project_id="default",
            trigger_type="manual",
            input_tasks_json={"tasks": []},
            priority=100,
            status="failed",
            public_status="failed",
            message="stale active runtime assumed failed",
            submitted_by="tester",
            retry_count=0,
            max_retry_count=3,
            latest_execution_id=execution_id,
        )
        execution = WorkflowExecution(
            id=execution_id,
            trigger_task_id=trigger.id,
            workflow_definition_id=trigger.workflow_definition_id,
            project_id="default",
            attempt_no=1,
            status="failed",
            public_status="failed",
            dispatch_status="failed",
            owner_pod_id="worker-a",
            worker_job_id="job-a",
            worker_url="http://worker-a:8080",
            process_status="exited",
            message="stale active runtime assumed failed",
        )
        db.add_all([trigger, execution])
        db.flush()
        get_execution_service()._rebuild_task_list_projections(db, [trigger])
        projection = db.get(DfvsTaskListProjection, trigger.id)
        assert projection is not None
        projection.public_status = "running"
        projection.dispatch_status = "running"
        db.add(projection)
        db.commit()
    finally:
        db.close()

    db = get_db_session()
    try:
        response = get_execution_service().reconcile_active_tasks(db, limit=10)
        assert response.reconciled_count >= 1
        projection = db.get(DfvsTaskListProjection, "tt-active-reconcile-stale-projection")
        assert projection is not None
        assert projection.public_status == "failed"
        assert projection.dispatch_status == "failed"
    finally:
        db.close()


def test_active_reconcile_terminal_task_fixes_stale_running_run_index(service_config_path):
    db = get_db_session()
    try:
        execution_id = "exec-active-reconcile-stale-run-index"
        finished_at = now_local()
        trigger = TriggerTask(
            id="tt-active-reconcile-stale-run-index",
            workflow_definition_id="wfd-active-reconcile-stale-run-index",
            project_id="default",
            trigger_type="manual",
            input_tasks_json={"tasks": []},
            priority=100,
            status="cancelled",
            public_status="cancelled",
            message="cancelled before worker start",
            submitted_by="tester",
            retry_count=0,
            max_retry_count=3,
            latest_execution_id=execution_id,
            finished_at=finished_at,
        )
        execution = WorkflowExecution(
            id=execution_id,
            trigger_task_id=trigger.id,
            workflow_definition_id=trigger.workflow_definition_id,
            project_id="default",
            attempt_no=1,
            status="pending",
            public_status="pending",
            dispatch_status=None,
            owner_pod_id=None,
            worker_job_id=None,
            worker_url=None,
            process_status="not_started",
            message="cancelled before worker start",
        )
        run_index = RunIndex(
            id="ri-active-reconcile-stale-run-index",
            project_id="default",
            source_type="execution_workspace",
            source_key="/tmp/stale-run-index",
            run_name="stale-run-index",
            run_root_path="/tmp/stale-run-index",
            linked_task_id=trigger.id,
            linked_execution_id=execution.id,
            status="running",
            started_at=finished_at - timedelta(seconds=30),
        )
        db.add_all([trigger, execution, run_index])
        db.flush()
        get_execution_service()._rebuild_task_list_projections(db, [trigger])
        projection = db.get(DfvsTaskListProjection, trigger.id)
        assert projection is not None
        projection.public_status = "running"
        projection.latest_run_status = "running"
        db.add(projection)
        db.commit()
    finally:
        db.close()

    db = get_db_session()
    try:
        response = get_execution_service().reconcile_active_tasks(db, limit=10)
        assert response.reconciled_count >= 1
        run_index = db.get(RunIndex, "ri-active-reconcile-stale-run-index")
        assert run_index is not None
        assert run_index.status == "cancelled"
        projection = db.get(DfvsTaskListProjection, "tt-active-reconcile-stale-run-index")
        assert projection is not None
        assert projection.public_status == "cancelled"
        assert projection.latest_run_status == "cancelled"
        event = (
            db.query(WorkflowExecutionEvent)
            .filter(
                WorkflowExecutionEvent.execution_id == execution_id,
                WorkflowExecutionEvent.event_type == "run_index_status_reconciled",
            )
            .first()
        )
        assert event is not None
    finally:
        db.close()
