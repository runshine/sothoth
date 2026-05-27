from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.config import get_config
from app.main import create_app
from app.models.database import SchedulerWorker, SchedulerWorkerSlotReservation, TriggerTask, WorkflowDefinition, WorkflowExecution, get_db_session
from app.services.dataflow_worker_client import DataflowWorkerError
from app.services.runtime_config_service import get_runtime_config_service
from app.services.scheduler import SchedulerService


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
        running = db.query(WorkflowExecution).filter(WorkflowExecution.status == "running").all()
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
        assert worker.metadata_json["advertise_url"] == f"http://{worker.host_name}:8080"
    finally:
        db.close()


def test_worker_capacity_default_is_five(service_config_path: Path):
    config = get_config()
    assert config.scheduler.worker_capacity == 5

    db = get_db_session()
    try:
        runtime_config = get_runtime_config_service().get_config(db)
    finally:
        db.close()

    assert runtime_config["scheduler"]["worker_capacity"] == 5


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
        assert execution.status == "running"
        assert trigger.status == "running"
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
        assert {item.status for item in executions} == {"running"}
        assert {item.status for item in triggers} == {"running"}
        assert {item.dispatch_status for item in executions} == {"running"}
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
        assert reservation is not None
        assert execution is not None
        assert execution.owner_pod_id == "worker-registry-1"
        assert reservation.worker_pod_id == "worker-registry-1"
        assert reservation.status == "accepted"
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


def test_worker_jobs_api_claims_execution_without_polling_pending_queue(
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
    assert payload["status"] == "running"
    assert payload["phase"] == "running"
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
        assert execution.status == "running"
        assert trigger.status == "running"
        assert execution.owner_pod_id == "worker-pod"
        assert execution.worker_url == "http://worker-pod"
        assert execution.worker_job_id == execution_id
        assert execution.dispatch_status == "running"
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
    assert payload["available_slots"] == 3
    assert payload["workers"][0]["worker_id"] == "worker-capacity-pod"
    assert payload["workers"][0]["healthy"] is True
    assert payload["workers"][0]["active_jobs"][0]["execution_id"] == execution_id
    assert payload["workers"][0]["active_jobs"][0]["task_id"] == "tt-sched-capacity-view"
    assert payload["workers"][0]["active_jobs"][0]["mapped"] is True


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
