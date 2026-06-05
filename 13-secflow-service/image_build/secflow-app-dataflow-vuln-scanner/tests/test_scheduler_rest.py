from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from app.config import get_config
from app.main import create_app
from app.models.database import (
    RunIndex,
    SchedulerWorker,
    SchedulerWorkerSlotReservation,
    TaskTimelineEvent,
    TriggerTask,
    WorkflowDefinition,
    WorkflowExecution,
    WorkflowExecutionEvent,
    get_db_session,
)
from app.services.dataflow_worker_client import DataflowWorkerError
from app.services.execution_service import get_execution_service
from app.services.runtime_config_service import get_runtime_config_service
from app.services.scheduler import SchedulerService
from app.time_utils import now_local


def _create_pending_execution(
    db,
    framework_config_payload: dict,
    *,
    suffix: str,
    status: str = "pending",
    trigger_status: str = "pending",
    worker_url: str | None = None,
    worker_job_id: str | None = None,
    owner_pod_id: str | None = None,
    dispatch_status: str | None = None,
) -> str:
    definition = WorkflowDefinition(
        id=f"wfd-sched-{suffix}",
        name=f"sched-{suffix}",
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
    trigger = TriggerTask(
        id=f"tt-sched-{suffix}",
        workflow_definition_id=definition.id,
        project_id="default",
        trigger_type="manual",
        input_tasks_json={"tasks": []},
        priority=100,
        status=trigger_status,
        submitted_by="tester",
        retry_count=0,
        max_retry_count=3,
    )
    execution = WorkflowExecution(
        id=f"exec-sched-{suffix}",
        trigger_task_id=trigger.id,
        workflow_definition_id=definition.id,
        project_id="default",
        attempt_no=1,
        status=status,
        worker_url=worker_url,
        worker_job_id=worker_job_id,
        owner_pod_id=owner_pod_id,
        dispatch_status=dispatch_status,
    )
    trigger.latest_execution_id = execution.id
    db.add_all([definition, trigger, execution])
    db.commit()
    return execution.id


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
        running = db.query(WorkflowExecution).filter(WorkflowExecution.status == "starting").all()
        pending = db.query(WorkflowExecution).filter(WorkflowExecution.status == "pending").all()
        assert len(running) == 2
        assert {item.owner_pod_id for item in running} == {"pod-a", "pod-b"}
        assert pending == []
    finally:
        db.close()


def test_worker_advertise_url_defaults_to_headless_fqdn(service_config_path: Path):
    config = get_config()
    config.scheduler.pod_id = "worker-3"
    config.scheduler.host_name = "worker-3"
    config.scheduler.pod_namespace = "secflow-ns"
    config.scheduler.worker_headless_service_name = "secflow-app-dataflow-vuln-scanner-worker-headless"
    config.dataflow_worker.advertise_url_template = ""

    assert SchedulerService().advertise_url() == (
        "http://worker-3.secflow-app-dataflow-vuln-scanner-worker-headless.secflow-ns.svc.cluster.local:8080"
    )


def test_manager_role_does_not_register_worker(service_config_path: Path):
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
        expected_advertise_url = (
            f"http://{config.scheduler.pod_id}."
            f"{config.scheduler.worker_headless_service_name}."
            f"{config.scheduler.pod_namespace}.svc.cluster.local:8080"
        )
        assert worker.metadata_json["advertise_url"] == expected_advertise_url
    finally:
        db.close()


def test_worker_capacity_default_is_one(service_config_path: Path):
    config = get_config()
    assert config.scheduler.worker_capacity == 1

    db = get_db_session()
    try:
        runtime_config = get_runtime_config_service().get_config(db)
    finally:
        db.close()

    assert runtime_config["scheduler"]["worker_capacity"] == 1


def test_database_pool_size_default_is_forty(service_config_path: Path):
    config = get_config()
    assert config.database.pool_size == 40
    assert config.database.max_overflow == 20
    assert config.database.pool_timeout == 30


def test_agent_cleanup_records_error_timeline_when_residuals_found(
    service_config_path: Path,
    framework_config_payload: dict,
    monkeypatch,
):
    execution_id: str
    db = get_db_session()
    try:
        execution_id = _create_pending_execution(db, framework_config_payload, suffix="cleanup-event")
    finally:
        db.close()

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        assert execution is not None
        trigger = db.get(TriggerTask, execution.trigger_task_id)
        assert trigger is not None
        execution.owner_pod_id = "worker-pod-cleanup"
        execution.workspace_root = "/tmp/cleanup-event"
        db.add(execution)
        db.commit()

        service = SchedulerService()
        exec_service = get_execution_service()

        monkeypatch.setattr(
            exec_service,
            "_scan_residual_agent_processes",
            lambda _db, **_kwargs: [
                {
                    "pid": 4321,
                    "ppid": 1,
                    "pgid": 4321,
                    "cmdline": "python /tmp/.pi/agent/codex residual",
                    "classified_type": "pi_agent",
                    "workspace_match": False,
                    "pattern_matches": ["codex"],
                }
            ],
        )
        monkeypatch.setattr(
            exec_service,
            "_kill_residual_agent_processes",
            lambda _db, **_kwargs: (_kwargs["processes"], [], True),
        )

        report = exec_service._cleanup_residual_agents_for_task(
            db,
            trigger=trigger,
            execution=execution,
            phase="pre_task_start",
            cleanup_reason="task_start_guard",
            strict=True,
        )
        assert report is not None
        assert report["matched_process_count"] == 1
        assert report["killed_process_count"] == 1

        timeline_events = (
            db.query(TaskTimelineEvent)
            .filter(TaskTimelineEvent.task_id == trigger.id)
            .order_by(TaskTimelineEvent.created_at.asc(), TaskTimelineEvent.id.asc())
            .all()
        )
        assert any(event.event_type == "task_agent_residual_force_killed" and event.level == "error" for event in timeline_events)
        assert any(event.event_type == "task_agent_cleanup_before_start" for event in timeline_events)
    finally:
        db.close()


def test_start_execution_now_allows_unlimited_worker_capacity(
    service_config_path: Path,
    framework_config_payload: dict,
    monkeypatch,
):
    config = get_config()
    config.scheduler.enabled = True
    config.scheduler.role = "standalone"
    config.scheduler.pod_id = "standalone-pod"
    config.scheduler.worker_capacity = 0

    db = get_db_session()
    try:
        execution_id = _create_pending_execution(db, framework_config_payload, suffix="unlimited-now")
    finally:
        db.close()

    started: list[str] = []
    monkeypatch.setattr(SchedulerService, "_schedule_execution_thread", lambda self, execution_id: started.append(execution_id))

    scheduler = SchedulerService()
    assert scheduler.start_execution_now(execution_id) is True
    assert started == [execution_id]

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        trigger = db.get(TriggerTask, "tt-sched-unlimited-now")
        assert execution is not None
        assert trigger is not None
        assert execution.status == "starting"
        assert trigger.status == "dispatching"
        assert execution.owner_pod_id == "standalone-pod"
    finally:
        db.close()


def test_worker_capacity_zero_starts_all_assigned_jobs(
    service_config_path: Path,
    framework_config_payload: dict,
    monkeypatch,
):
    config = get_config()
    config.scheduler.enabled = True
    config.scheduler.role = "worker"
    config.scheduler.pod_id = "worker-pod"
    config.scheduler.worker_capacity = 0

    db = get_db_session()
    try:
        execution_ids = [
            _create_pending_execution(
                db,
                framework_config_payload,
                suffix=f"unlimited-assigned-{idx}",
                worker_url="http://worker-pod",
                worker_job_id=f"job-unlimited-assigned-{idx}",
                owner_pod_id="worker-pod",
                dispatch_status="queued",
            )
            for idx in range(3)
        ]
    finally:
        db.close()

    started: list[str] = []
    monkeypatch.setattr(SchedulerService, "_schedule_execution_thread", lambda self, execution_id: started.append(execution_id))

    SchedulerService()._start_assigned_jobs()
    assert started == execution_ids

    db = get_db_session()
    try:
        executions = db.query(WorkflowExecution).filter(WorkflowExecution.id.in_(execution_ids)).all()
        triggers = db.query(TriggerTask).filter(TriggerTask.id.in_([f"tt-sched-unlimited-assigned-{idx}" for idx in range(3)])).all()
        assert {item.status for item in executions} == {"starting"}
        assert {item.status for item in triggers} == {"dispatching"}
        assert {item.dispatch_status for item in executions} == {"starting"}
    finally:
        db.close()


def test_worker_claims_already_dispatching_assigned_job(
    service_config_path: Path,
    framework_config_payload: dict,
    monkeypatch,
):
    config = get_config()
    config.scheduler.enabled = True
    config.scheduler.role = "worker"
    config.scheduler.pod_id = "worker-pod"
    config.scheduler.worker_capacity = 1

    db = get_db_session()
    try:
        execution_id = _create_pending_execution(
            db,
            framework_config_payload,
            suffix="assigned-dispatching",
            status="dispatching",
            trigger_status="dispatching",
            worker_url="http://worker-pod",
            worker_job_id="job-assigned-dispatching",
            owner_pod_id="worker-pod",
            dispatch_status="dispatching",
        )
    finally:
        db.close()

    started: list[str] = []
    monkeypatch.setattr(SchedulerService, "_schedule_execution_thread", lambda self, execution_id: started.append(execution_id))

    SchedulerService()._start_assigned_jobs()
    assert started == [execution_id]

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        trigger = db.get(TriggerTask, "tt-sched-assigned-dispatching")
        assert execution is not None
        assert trigger is not None
        assert execution.status == "starting"
        assert trigger.status == "dispatching"
        assert execution.dispatch_status == "starting"
    finally:
        db.close()


def test_manager_dispatches_execution_to_dataflow_worker(
    service_config_path: Path,
    framework_config_payload: dict,
    monkeypatch,
):
    config = get_config()
    config.scheduler.role = "manager"

    db = get_db_session()
    try:
        db.add(SchedulerWorker(
            pod_id="worker-a",
            host_name="worker-a",
            capacity=2,
            running_count=0,
            status="active",
            metadata_json={"advertise_url": "http://worker-a"},
        ))
        execution_id = _create_pending_execution(db, framework_config_payload, suffix="manager-dispatch")
        db.commit()
    finally:
        db.close()

    calls: list[tuple[str, dict]] = []

    class FakeClient:
        def __init__(self, base_url: str):
            self.base_url = base_url

        def create_job(self, payload: dict) -> dict:
            calls.append((self.base_url, payload))
            return {"id": f"job-{payload['execution_id']}", "status": "queued"}

    monkeypatch.setattr(
        "app.services.scheduler.get_dataflow_worker_client",
        lambda base_url=None: FakeClient(base_url or ""),
    )

    scheduler = SchedulerService()
    assert scheduler.start_execution_now(execution_id) is True
    assert calls == [("http://worker-a", {"execution_id": execution_id, "worker_url": "http://worker-a", "worker_pod_id": "worker-a"})]

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        trigger = db.get(TriggerTask, "tt-sched-manager-dispatch")
        assert execution is not None
        assert trigger is not None
        assert execution.status == "pending"
        assert trigger.status == "pending"
        assert execution.owner_pod_id == "worker-a"
        assert execution.worker_url == "http://worker-a"
        assert execution.worker_job_id == f"job-{execution_id}"
        assert execution.dispatch_status == "queued"
    finally:
        db.close()


def test_manager_dispatch_uses_registry_worker_and_creates_reservation(
    service_config_path: Path,
    framework_config_payload: dict,
    monkeypatch,
):
    config = get_config()
    config.scheduler.role = "manager"

    db = get_db_session()
    try:
        db.add(SchedulerWorker(
            pod_id="worker-registry-1",
            host_name="worker-registry-1",
            capacity=2,
            running_count=0,
            status="active",
            metadata_json={"advertise_url": "http://worker-registry-1:8080"},
        ))
        execution_id = _create_pending_execution(db, framework_config_payload, suffix="manager-registry-dispatch")
        db.commit()
    finally:
        db.close()

    calls: list[tuple[str, dict]] = []

    class FakeClient:
        def __init__(self, base_url: str):
            self.base_url = base_url

        def create_job(self, payload: dict) -> dict:
            calls.append((self.base_url, payload))
            return {"id": f"job-{payload['execution_id']}", "status": "queued"}

    monkeypatch.setattr("app.services.scheduler.get_dataflow_worker_client", lambda base_url=None: FakeClient(base_url or ""))

    scheduler = SchedulerService()
    assert scheduler.start_execution_now(execution_id) is True
    assert calls[0][0] == "http://worker-registry-1:8080"
    assert calls[0][1]["worker_pod_id"] == "worker-registry-1"

    db = get_db_session()
    try:
        reservation = db.query(SchedulerWorkerSlotReservation).filter(SchedulerWorkerSlotReservation.execution_id == execution_id).first()
        execution = db.get(WorkflowExecution, execution_id)
        assert reservation is None
        assert execution is not None
        assert execution.owner_pod_id == "worker-registry-1"
        assert execution.worker_url == "http://worker-registry-1:8080"
        assert execution.dispatch_status == "queued"
    finally:
        db.close()



def test_manager_chooses_lowest_load_worker_with_db_supplement(
    service_config_path: Path,
    framework_config_payload: dict,
    monkeypatch,
):
    config = get_config()
    config.scheduler.role = "manager"

    db = get_db_session()
    try:
        db.add_all([
            SchedulerWorker(
                pod_id="worker-a-pod",
                host_name="worker-a",
                capacity=4,
                running_count=0,
                status="active",
                metadata_json={"advertise_url": "http://worker-a"},
            ),
            SchedulerWorker(
                pod_id="worker-b-pod",
                host_name="worker-b",
                capacity=4,
                running_count=0,
                status="active",
                metadata_json={"advertise_url": "http://worker-b"},
            ),
            SchedulerWorker(
                pod_id="worker-c-pod",
                host_name="worker-c",
                capacity=4,
                running_count=0,
                status="active",
                metadata_json={"advertise_url": "http://worker-c"},
            ),
        ])
        execution_id = _create_pending_execution(db, framework_config_payload, suffix="choose-pending")
        _create_pending_execution(
            db,
            framework_config_payload,
            suffix="choose-active",
            status="running",
            trigger_status="running",
            worker_url="http://worker-b",
            worker_job_id="job-active",
            owner_pod_id="worker-b-pod",
        )
        _create_pending_execution(
            db,
            framework_config_payload,
            suffix="choose-active-a",
            status="running",
            trigger_status="running",
            worker_url="http://worker-a",
            worker_job_id="job-active-a",
            owner_pod_id="worker-a-pod",
        )
        db.commit()
        assert SchedulerService()._choose_dataflow_worker(db, execution_id) == ("worker-c-pod", "http://worker-c")
    finally:
        db.close()


def test_manager_dispatch_fails_over_when_worker_capacity_exceeded(
    service_config_path: Path,
    framework_config_payload: dict,
    monkeypatch,
):
    config = get_config()
    config.scheduler.role = "manager"
    config.dataflow_worker.dispatch_max_retries = 1

    db = get_db_session()
    try:
        db.add_all([
            SchedulerWorker(
                pod_id="worker-full",
                host_name="worker-full",
                capacity=3,
                running_count=0,
                status="active",
                metadata_json={"advertise_url": "http://worker-full"},
            ),
            SchedulerWorker(
                pod_id="worker-free",
                host_name="worker-free",
                capacity=3,
                running_count=0,
                status="active",
                metadata_json={"advertise_url": "http://worker-free"},
            ),
        ])
        execution_id = _create_pending_execution(db, framework_config_payload, suffix="manager-capacity-failover")
        for idx in range(3):
            _create_pending_execution(
                db,
                framework_config_payload,
                suffix=f"manager-capacity-running-{idx}",
                status="running",
                trigger_status="running",
                worker_url="http://worker-full",
                worker_job_id=f"job-running-{idx}",
                owner_pod_id="worker-full",
                dispatch_status="running",
            )
        db.commit()
    finally:
        db.close()

    calls: list[str] = []

    class FakeClient:
        def __init__(self, base_url: str):
            self.base_url = base_url

        def create_job(self, payload: dict) -> dict:
            calls.append(self.base_url)
            if self.base_url == "http://worker-full":
                raise DataflowWorkerError('{"detail":"capacity_exceeded"}')
            return {"id": payload["execution_id"], "status": "queued"}

        def list_jobs(self) -> list[dict]:
            return []

    monkeypatch.setattr("app.services.scheduler.get_dataflow_worker_client", lambda base_url=None: FakeClient(base_url or ""))
    monkeypatch.setattr(
        SchedulerService,
        "_rank_dataflow_workers",
        lambda self, db, execution_id: [("worker-full", "http://worker-full"), ("worker-free", "http://worker-free")],
    )

    assert SchedulerService().start_execution_now(execution_id) is True
    assert calls == ["http://worker-full", "http://worker-free"]

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        assert execution is not None
        assert execution.owner_pod_id == "worker-free"
        assert execution.worker_url == "http://worker-free"
        assert execution.dispatch_status == "queued"
        assert db.query(SchedulerWorkerSlotReservation).filter(SchedulerWorkerSlotReservation.execution_id == execution_id).first() is None
        assert (
            db.query(WorkflowExecutionEvent)
            .filter(
                WorkflowExecutionEvent.execution_id == execution_id,
                WorkflowExecutionEvent.event_type == "worker_dispatch_requeued",
            )
            .count()
            == 0
        )
    finally:
        db.close()


def test_manager_dispatch_requires_registry_worker(
    service_config_path: Path,
    framework_config_payload: dict,
):
    config = get_config()
    config.scheduler.role = "manager"

    db = get_db_session()
    try:
        execution_id = _create_pending_execution(db, framework_config_payload, suffix="manager-no-worker")
    finally:
        db.close()

    db = get_db_session()
    try:
        try:
            SchedulerService()._choose_dataflow_worker(db, execution_id)
            raise AssertionError("expected DataflowWorkerError when no registry workers are available")
        except DataflowWorkerError as exc:
            assert "no healthy registry worker" in str(exc)
    finally:
        db.close()


def test_worker_jobs_api_claims_and_starts_assigned_execution(
    service_config_path: Path,
    framework_config_payload: dict,
    monkeypatch,
):
    config = get_config()
    config.scheduler.role = "worker"
    config.scheduler.pod_id = "worker-pod"
    config.scheduler.worker_capacity = 1

    db = get_db_session()
    try:
        execution_id = _create_pending_execution(db, framework_config_payload, suffix="worker-api")
    finally:
        db.close()

    started: list[str] = []
    monkeypatch.setattr(SchedulerService, "_schedule_execution_thread", lambda self, execution_id: started.append(execution_id))

    client = TestClient(create_app())
    response = client.post("/api/v1/jobs", json={"execution_id": execution_id, "worker_url": "http://worker-pod"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["id"] == execution_id
    assert payload["status"] == "starting"
    assert payload["phase"] == "starting"
    assert started == [execution_id]

    list_response = client.get("/api/v1/jobs")
    assert list_response.status_code == 200
    assert [job["execution_id"] for job in list_response.json()["jobs"]] == [execution_id]
    public_response = client.get("/api/dataflow-vuln-scanner/capabilities")
    assert public_response.status_code == 404

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        trigger = db.get(TriggerTask, "tt-sched-worker-api")
        assert execution is not None
        assert trigger is not None
        assert execution.status == "starting"
        assert trigger.status == "dispatching"
        assert execution.owner_pod_id == "worker-pod"
        assert execution.worker_url == "http://worker-pod"
        assert execution.worker_job_id == execution_id
        assert execution.dispatch_status == "starting"
    finally:
        db.close()


def test_worker_cancel_job_marks_running_execution_stop_requested(
    service_config_path: Path,
    framework_config_payload: dict,
    monkeypatch,
):
    config = get_config()
    config.scheduler.role = "worker"
    config.scheduler.pod_id = "worker-pod"

    db = get_db_session()
    try:
        execution_id = _create_pending_execution(
            db,
            framework_config_payload,
            suffix="worker-cancel",
            status="running",
            trigger_status="running",
            worker_url="http://worker-pod",
            worker_job_id="job-worker-cancel",
            owner_pod_id="worker-pod",
        )
    finally:
        db.close()

    signals: list[tuple[str, bool]] = []

    class FakeExecutionService:
        def _write_run_control_state(self, *_args, **_kwargs):
            return None

        def _signal_local_cli_process(self, execution_id: str, *, wait: bool = False):
            signals.append((execution_id, wait))
            return {"found": True, "signal": "sigint"}

    monkeypatch.setattr("app.services.scheduler.get_execution_service", lambda: FakeExecutionService())

    payload = SchedulerService().cancel_local_job("job-worker-cancel")
    assert payload["status"] == "running"


def test_worker_jobs_api_rejects_when_capacity_exhausted(
    service_config_path: Path,
    framework_config_payload: dict,
):
    config = get_config()
    config.scheduler.role = "worker"
    config.scheduler.pod_id = "worker-capacity-limit-pod"
    config.scheduler.worker_capacity = 1

    db = get_db_session()
    try:
        _create_pending_execution(
            db,
            framework_config_payload,
            suffix="worker-capacity-running",
            status="running",
            trigger_status="running",
            worker_url="http://worker-capacity-limit-pod",
            worker_job_id="job-worker-capacity-running",
            owner_pod_id="worker-capacity-limit-pod",
            dispatch_status="running",
        )
        execution_id = _create_pending_execution(db, framework_config_payload, suffix="worker-capacity-pending")
    finally:
        db.close()

    client = TestClient(create_app())
    response = client.post("/api/v1/jobs", json={"execution_id": execution_id, "worker_url": "http://worker-capacity-limit-pod"})
    assert response.status_code == 409
    assert response.json()["detail"] == "capacity_exceeded"


def test_worker_jobs_api_excludes_prebound_execution_from_capacity(
    service_config_path: Path,
    framework_config_payload: dict,
    monkeypatch,
):
    config = get_config()
    config.scheduler.role = "worker"
    config.scheduler.pod_id = "worker-prebound-capacity-pod"
    config.scheduler.worker_capacity = 1

    db = get_db_session()
    try:
        execution_id = _create_pending_execution(
            db,
            framework_config_payload,
            suffix="worker-prebound-capacity",
            worker_url="http://worker-prebound-capacity-pod",
            worker_job_id="exec-sched-worker-prebound-capacity",
            owner_pod_id="worker-prebound-capacity-pod",
            dispatch_status="dispatching",
        )
    finally:
        db.close()

    started: list[str] = []
    monkeypatch.setattr(SchedulerService, "_schedule_execution_thread", lambda self, execution_id: started.append(execution_id))

    client = TestClient(create_app())
    response = client.post("/api/v1/jobs", json={"execution_id": execution_id, "worker_url": "http://worker-prebound-capacity-pod"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["id"] == execution_id
    assert payload["status"] == "starting"
    assert started == [execution_id]


def test_cluster_capacity_api_returns_worker_jobs(
    service_config_path: Path,
    framework_config_payload: dict,
    monkeypatch,
):
    config = get_config()
    config.scheduler.enabled = True
    config.scheduler.role = "worker"
    config.scheduler.pod_id = "worker-capacity-pod"
    config.scheduler.host_name = "worker-capacity-host"
    config.scheduler.worker_capacity = 4

    scheduler = SchedulerService()
    scheduler._heartbeat_once()

    db = get_db_session()
    try:
        execution_id = _create_pending_execution(
            db,
            framework_config_payload,
            suffix="capacity-view",
            status="running",
            trigger_status="running",
            worker_url="http://worker-capacity",
            worker_job_id="job-capacity-view",
            owner_pod_id="worker-capacity-pod",
            dispatch_status="running",
        )
        db.add(
            RunIndex(
                id="ri-capacity-view",
                project_id="default",
                source_type="execution_workspace",
                source_key="/tmp/capacity-view",
                source_hash="capacity-view",
                run_name="capacity-view-run",
                run_root_path="/tmp/capacity-view-run",
                linked_task_id="tt-sched-capacity-view",
                linked_execution_id=execution_id,
                status="running",
            )
        )
        db.commit()
    finally:
        db.close()

    class FakeClient:
        def list_jobs(self) -> list[dict]:
            return [{
                "id": "job-capacity-view",
                "execution_id": execution_id,
                "status": "running",
                "phase": "running",
                "worker_url": "http://worker-capacity",
            }]

    monkeypatch.setattr(
        "app.services.scheduler.get_dataflow_worker_client",
        lambda base_url=None: FakeClient(),
    )

    client = TestClient(create_app())
    response = client.get("/api/dataflow-vuln-scanner/workers/cluster-capacity")
    assert response.status_code == 200
    payload = response.json()
    assert payload["worker_count"] == 1
    assert payload["total_capacity"] == 4
    assert payload["running_jobs"] == 1
    assert payload["used_slots"] == 1
    assert payload["available_slots"] == 3
    assert payload["schedulable_slots"] == 3
    assert payload["workers"][0]["worker_id"] == "worker-capacity-pod"
    assert payload["workers"][0]["healthy"] is True
    assert payload["workers"][0]["used_slots"] == 1
    assert payload["workers"][0]["active_jobs"][0]["execution_id"] == execution_id
    assert payload["workers"][0]["active_jobs"][0]["task_id"] == "tt-sched-capacity-view"
    assert payload["workers"][0]["active_jobs"][0]["mapped"] is True
    assert payload["workers"][0]["active_jobs"][0]["run_path"] == "/tmp/capacity-view-run"


def test_cluster_capacity_api_degrades_when_worker_probe_fails(
    service_config_path: Path,
    monkeypatch,
):
    config = get_config()
    config.scheduler.enabled = True
    config.scheduler.role = "worker"
    config.scheduler.pod_id = "worker-capacity-fail-pod"
    config.scheduler.host_name = "worker-capacity-fail-host"
    config.scheduler.worker_capacity = 2

    scheduler = SchedulerService()
    scheduler._heartbeat_once()

    class FakeClient:
        def list_jobs(self) -> list[dict]:
            raise RuntimeError("probe failed")

    monkeypatch.setattr(
        "app.services.scheduler.get_dataflow_worker_client",
        lambda base_url=None: FakeClient(),
    )

    client = TestClient(create_app())
    response = client.get("/api/dataflow-vuln-scanner/workers/cluster-capacity")
    assert response.status_code == 200
    payload = response.json()
    assert payload["worker_count"] >= 1
    target = next(item for item in payload["workers"] if item["worker_id"] == "worker-capacity-fail-pod")
    assert target["healthy"] is False
    assert target["active_jobs"] == []
    assert "probe failed" in (target["error"] or "")


def test_cluster_capacity_api_hides_historical_offline_workers(service_config_path: Path):
    config = get_config()
    config.scheduler.enabled = True
    config.scheduler.role = "worker"
    config.scheduler.pod_id = "worker-visible-pod"
    config.scheduler.host_name = "worker-visible-host"
    config.scheduler.worker_capacity = 2

    scheduler = SchedulerService()
    scheduler._heartbeat_once()

    db = get_db_session()
    try:
        db.add(
            SchedulerWorker(
                pod_id="worker-offline-stale",
                host_name="worker-offline-stale",
                capacity=3,
                running_count=0,
                status="offline",
                last_heartbeat_at=now_local() - timedelta(hours=12),
                metadata_json={"advertise_url": "http://worker-offline-stale:8080"},
            )
        )
        db.commit()
    finally:
        db.close()

    client = TestClient(create_app())
    response = client.get("/api/dataflow-vuln-scanner/workers/cluster-capacity")
    assert response.status_code == 200
    payload = response.json()
    worker_ids = {item["worker_id"] for item in payload["workers"]}
    assert "worker-visible-pod" in worker_ids
    assert "worker-offline-stale" not in worker_ids


def test_pending_dispatch_skips_execution_in_backoff(service_config_path: Path, framework_config_payload: dict):
    config = get_config()
    config.scheduler.enabled = True
    config.scheduler.role = "manager"

    db = get_db_session()
    try:
        execution_id = _create_pending_execution(db, framework_config_payload, suffix="backoff-skip")
    finally:
        db.close()

    scheduler = SchedulerService()
    scheduler._schedule_dispatch_backoff(execution_id, reason="capacity_exceeded", worker_pod_id="worker-a")
    assert scheduler._pending_worker_dispatch_execution_ids() == []
    metrics = scheduler.dispatch_backoff_metrics()
    assert metrics["backoff_scheduled_total"] >= 1
    assert metrics["skipped_due_to_backoff_total"] >= 1

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        assert execution is not None
        assert execution.dispatch_backoff_reason == "capacity_exceeded"
        assert execution.dispatch_backoff_until is not None
        assert (execution.dispatch_backoff_until - now_local()).total_seconds() >= 50
    finally:
        db.close()


def test_pending_dispatch_query_respects_persisted_backoff_across_scheduler_instances(service_config_path: Path, framework_config_payload: dict):
    config = get_config()
    config.scheduler.enabled = True
    config.scheduler.role = "manager"

    db = get_db_session()
    try:
        execution_id = _create_pending_execution(db, framework_config_payload, suffix="persisted-backoff")
        execution = db.get(WorkflowExecution, execution_id)
        assert execution is not None
        execution.dispatch_backoff_until = now_local() + timedelta(seconds=60)
        execution.dispatch_backoff_reason = "capacity_exceeded"
        db.add(execution)
        db.commit()
    finally:
        db.close()

    scheduler = SchedulerService()
    assert execution_id not in scheduler._pending_worker_dispatch_execution_ids()


def test_rank_workers_uses_db_snapshot_without_remote_job_probe(service_config_path: Path, framework_config_payload: dict, monkeypatch):
    config = get_config()
    config.scheduler.enabled = True
    config.scheduler.role = "manager"

    db = get_db_session()
    try:
        execution_id = _create_pending_execution(db, framework_config_payload, suffix="rank-no-probe")
        db.add_all(
            [
                SchedulerWorker(
                    pod_id="worker-rank-a",
                    host_name="worker-rank-a",
                    capacity=2,
                    running_count=0,
                    status="active",
                    last_heartbeat_at=None,
                    metadata_json={"advertise_url": "http://worker-rank-a"},
                ),
                SchedulerWorker(
                    pod_id="worker-rank-b",
                    host_name="worker-rank-b",
                    capacity=2,
                    running_count=0,
                    status="active",
                    last_heartbeat_at=None,
                    metadata_json={"advertise_url": "http://worker-rank-b"},
                ),
            ]
        )
        db.commit()
    finally:
        db.close()

    def _fail_client(*args, **kwargs):
        raise AssertionError("manager dispatch ranking should not probe worker jobs")

    monkeypatch.setattr("app.services.scheduler.get_dataflow_worker_client", _fail_client)
    scheduler = SchedulerService()
    db = get_db_session()
    try:
        workers = scheduler._rank_dataflow_workers(db, execution_id)
    finally:
        db.close()
    assert len(workers) == 2


def test_worker_capacity_runtime_config_applies_to_heartbeat_and_capacity_view(
    service_config_path: Path,
):
    config = get_config()
    config.scheduler.enabled = True
    config.scheduler.role = "worker"
    config.scheduler.pod_id = "worker-runtime-capacity-pod"
    config.scheduler.host_name = "worker-runtime-capacity-host"
    config.scheduler.worker_capacity = 1

    scheduler = SchedulerService()
    scheduler._heartbeat_once()

    db = get_db_session()
    try:
        worker = db.get(SchedulerWorker, "worker-runtime-capacity-pod")
        assert worker is not None
        assert worker.capacity == 1

        saved = get_runtime_config_service().save_config(db, {
            "scheduler": {
                "worker_capacity": 3,
            },
        })
        assert saved["scheduler"]["worker_capacity"] == 3
    finally:
        db.close()

    scheduler._heartbeat_once()

    db = get_db_session()
    try:
        worker = db.get(SchedulerWorker, "worker-runtime-capacity-pod")
        assert worker is not None
        assert worker.capacity == 3

        payload = scheduler.get_cluster_capacity_summary(db)
        target = next(item for item in payload.workers if item.worker_id == "worker-runtime-capacity-pod")
        assert target.max_concurrent_jobs == 3
        assert target.available_slots == 3
    finally:
        db.close()


def test_cleanup_once_releases_terminal_executions_from_active_capacity(
    service_config_path: Path,
    framework_config_payload: dict,
):
    config = get_config()
    config.scheduler.enabled = True

    db = get_db_session()
    try:
        _create_pending_execution(
            db,
            framework_config_payload,
            suffix="terminal-capacity-leak",
            status="failed",
            trigger_status="failed",
            owner_pod_id="worker-terminal-leak",
            dispatch_status="running",
        )
    finally:
        db.close()

    scheduler = SchedulerService()
    scheduler._cleanup_once()

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, "exec-sched-terminal-capacity-leak")
        assert execution is not None
        assert execution.status == "failed"
        assert execution.dispatch_status == "failed"
        assert execution.dispatch_error
    finally:
        db.close()


def test_cluster_capacity_summary_ignores_stale_worker_running_count(
    service_config_path: Path,
    framework_config_payload: dict,
):
    config = get_config()
    config.scheduler.enabled = True
    config.scheduler.role = "worker"
    config.scheduler.pod_id = "worker-summary-pod"
    config.scheduler.host_name = "worker-summary-host"
    config.scheduler.worker_capacity = 3

    scheduler = SchedulerService()
    scheduler._heartbeat_once()

    db = get_db_session()
    try:
        _create_pending_execution(
            db,
            framework_config_payload,
            suffix="summary-active",
            status="running",
            trigger_status="running",
            owner_pod_id="worker-summary-pod",
            dispatch_status="running",
        )
        _create_pending_execution(
            db,
            framework_config_payload,
            suffix="summary-terminal",
            status="failed",
            trigger_status="failed",
            owner_pod_id="worker-summary-pod",
            dispatch_status="running",
        )
        worker = db.get(SchedulerWorker, "worker-summary-pod")
        assert worker is not None
        worker.running_count = 7
        db.add(worker)
        db.commit()

        payload = scheduler.get_cluster_capacity_summary(db)
        target = next(item for item in payload.workers if item.worker_id == "worker-summary-pod")
        assert target.running_jobs == 1
        assert target.available_slots == 2
    finally:
        db.close()


def test_worker_heartbeat_loop_retries_after_failure(service_config_path: Path, monkeypatch):
    config = get_config()
    config.scheduler.enabled = True
    config.scheduler.role = "worker"
    config.scheduler.pod_id = "worker-heartbeat-loop"
    config.scheduler.host_name = "worker-heartbeat-loop"
    config.scheduler.heartbeat_interval_seconds = 0

    scheduler = SchedulerService()
    calls: list[str] = []

    def fake_heartbeat_once():
        calls.append("heartbeat")
        if len(calls) == 1:
            raise RuntimeError("db down")
        raise asyncio.CancelledError()

    async def fake_sleep(_interval):
        return None

    monkeypatch.setattr(scheduler, "_heartbeat_once", fake_heartbeat_once)
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(scheduler._heartbeat_loop())

    metrics = scheduler.heartbeat_metrics()
    assert len(calls) == 2
    assert metrics["failure_total"] == 1
    assert metrics["failure_reasons"]["runtimeerror"] == 1
    assert metrics["loop_alive"] == 0


def test_scheduler_start_survives_initial_heartbeat_failure(service_config_path: Path, monkeypatch):
    config = get_config()
    config.scheduler.enabled = True
    config.scheduler.role = "worker"
    config.scheduler.pod_id = "worker-heartbeat-start"
    config.scheduler.host_name = "worker-heartbeat-start"

    scheduler = SchedulerService()
    created_tasks: list[str] = []

    def fake_heartbeat_once():
        raise RuntimeError("mysql unavailable")

    async def fake_start_assigned_jobs():
        return None

    def fake_create_task(coro, name=None):
        coro.close()

        class DummyTask:
            def cancel(self):
                return None

        created_tasks.append(str(name or "unnamed"))
        return DummyTask()

    monkeypatch.setattr(scheduler, "_heartbeat_once", fake_heartbeat_once)
    monkeypatch.setattr(scheduler, "_start_assigned_jobs", lambda: None)
    monkeypatch.setattr(asyncio, "create_task", fake_create_task)

    asyncio.run(scheduler.start())

    metrics = scheduler.heartbeat_metrics()
    assert scheduler._started is True
    assert "scheduler-heartbeat" in created_tasks
    assert "scheduler-assigned-dispatch" in created_tasks
    assert metrics["failure_total"] == 1
    assert metrics["failure_reasons"]["startup_initial_heartbeat"] == 1
