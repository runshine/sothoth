from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.config import get_config
from app.main import create_app
from app.models.database import SchedulerWorker, TriggerTask, WorkflowDefinition, WorkflowExecution, get_db_session
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
    finally:
        db.close()


def test_manager_dispatches_execution_to_dataflow_worker(
    service_config_path: Path,
    framework_config_payload: dict,
    monkeypatch,
):
    config = get_config()
    config.scheduler.role = "manager"
    config.dataflow_worker.worker_urls = ["http://worker-a"]

    db = get_db_session()
    try:
        execution_id = _create_pending_execution(db, framework_config_payload, suffix="manager-dispatch")
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
    assert calls == [("http://worker-a", {"execution_id": execution_id, "worker_url": "http://worker-a"})]

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        trigger = db.get(TriggerTask, "tt-sched-manager-dispatch")
        assert execution is not None
        assert trigger is not None
        assert execution.status == "pending"
        assert trigger.status == "pending"
        assert execution.worker_url == "http://worker-a"
        assert execution.worker_job_id == f"job-{execution_id}"
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
    config.dataflow_worker.worker_urls = ["http://worker-a", "http://worker-b", "http://worker-c"]

    remote_jobs = {
        "http://worker-a": [{"status": "queued"}, {"status": "running"}],
        "http://worker-b": [],
        "http://worker-c": [],
    }

    class FakeClient:
        def __init__(self, base_url: str):
            self.base_url = base_url

        def list_jobs(self) -> list[dict]:
            return remote_jobs[self.base_url]

    monkeypatch.setattr(
        "app.services.scheduler.get_dataflow_worker_client",
        lambda base_url=None: FakeClient(base_url or ""),
    )

    db = get_db_session()
    try:
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
        assert SchedulerService()._choose_dataflow_worker(db, execution_id) == "http://worker-c"
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
    assert payload["status"] == "cancel_requested"
    assert signals == [(execution_id, False)]

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        trigger = db.get(TriggerTask, "tt-sched-worker-cancel")
        assert execution is not None
        assert trigger is not None
        assert execution.status == "cancel_requested"
        assert trigger.status == "cancel_requested"
        assert execution.dispatch_status == "cancel_requested"
        assert execution.process_status == "stop_requested"
    finally:
        db.close()
