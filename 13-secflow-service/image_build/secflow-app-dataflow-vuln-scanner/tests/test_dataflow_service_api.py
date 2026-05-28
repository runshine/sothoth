from __future__ import annotations

import json
import time
from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from fastapi import HTTPException

from app.config import get_config
from app.main import create_app
from app.artifacts.io import write_json
from app.models.database import DfvsTaskListProjection, RunIndex, TriggerTask, WorkflowDefinitionVersion, WorkflowExecution, WorkflowExecutionEvent, get_db_session
from app.services.execution_service import get_execution_service
from app.time_utils import isoformat_local, now_local


def _wait_for_task_status(client: TestClient, task_id: str, expected: set[str] | None = None, timeout: float = 10.0) -> dict:
    expected = expected or {"succeeded", "completed", "success"}
    deadline = time.time() + timeout
    last_payload: dict = {}
    while time.time() < deadline:
        response = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}")
        assert response.status_code == 200
        last_payload = response.json()
        if last_payload.get("status") in expected:
            return last_payload
        time.sleep(0.1)
    raise AssertionError(f"task {task_id} did not reach {expected}, last payload: {last_payload}")


def _profile_payload() -> dict:
    return {
        "project_id": "default",
        "name": "default scanner",
        "description": "scanner profile",
        "template_kind": "vuln_scan_default",
        "config_payload": {
            "model": "mock/model",
            "thinking": "high",
            "max_review_cycles": 2,
            "worker_timeout": 60,
            "advisor_timeout": 60,
            "result_review_concurrency": 2,
            "runtime_overrides": {},
        },
        "is_default": True,
        "enabled": True,
        "default_priority": 120,
        "max_retry_count": 2,
        "execution_timeout_seconds": 600,
    }


def _prepare_business_case(case_name: str) -> Path:
    config = get_config()
    case_root = Path(config.fileserver_service.data_mount_path) / "files" / "default" / case_name
    source_dir = case_root / "source"
    data_flow_dir = case_root / "data_flow"
    source_dir.mkdir(parents=True, exist_ok=True)
    data_flow_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "demo.c").write_text("int demo(char *p) { return p[0]; }\n", encoding="utf-8")
    (data_flow_dir / "data_flow.md").write_text("# 数据流追踪：demo\n\n| 📌 USED | 1 |\nINPUT-1\n", encoding="utf-8")
    return case_root


def _create_business_dataflow_task(
    client: TestClient,
    *,
    profile_id: str,
    case_name: str,
    title: str,
    extra_payload: dict | None = None,
) -> dict:
    _prepare_business_case(case_name)
    payload = {
        "project_id": "default",
        "profile_id": profile_id,
        "title": title,
        "data_flow": {"source": "project_filesystem", "path": f"/{case_name}/data_flow"},
        "source_dir": {"source": "project_filesystem", "path": f"/{case_name}/source"},
        "model": "mock/model",
        "review_profile": "fast",
        "max_review_cycles": 1,
        "result_review_concurrency": 1,
    }
    if extra_payload:
        payload.update(extra_payload)
    response = client.post("/api/dataflow-vuln-scanner/tasks", json=payload)
    assert response.status_code == 201
    return response.json()


def _disable_scheduler_start(monkeypatch):
    from app.api import tasks as task_api

    class NoopScheduler:
        def start_execution_now(self, execution_id):
            return False

    monkeypatch.setattr(task_api, "get_scheduler_service", lambda: NoopScheduler())


def test_profiles_tasks_and_effective_config(service_config_path, patch_mock_agent_runtime):
    app = create_app()
    client = TestClient(app)

    create_profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload())
    assert create_profile.status_code == 201
    profile = create_profile.json()
    assert profile["template_kind"] == "vuln_scan_default"
    assert profile["is_default"] is True
    profile_id = profile["profile_id"]

    versions = client.get(f"/api/dataflow-vuln-scanner/profiles/{profile_id}/versions")
    assert versions.status_code == 200
    assert versions.json()[0]["version"] == 1

    effective = client.get("/api/dataflow-vuln-scanner/projects/default/config/effective")
    assert effective.status_code == 200
    assert effective.json()["default_profile_id"] == profile_id

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile_id,
            "title": "scan demo package",
            "task_markdown": "# Package List\n\n- demo.tar.gz\n",
            "artifact_refs": [],
            "runtime_overrides": {},
        },
    )
    assert task.status_code == 201
    task_payload = task.json()
    task_id = task_payload["task_id"]
    assert task_payload["status"] in {"running", "succeeded"}

    detail_payload = _wait_for_task_status(client, task_id)
    assert detail_payload["status"] == "succeeded"
    assert detail_payload["attempts"]
    execution_id = detail_payload["attempts"][0]["execution_id"]

    run_resolve = client.get(
        "/api/dataflow-vuln-scanner/runs/by-task",
        params={"project_id": "default", "task_id": task_id, "execution_id": execution_id},
    )
    assert run_resolve.status_code == 200

    run_detail = client.get(f"/api/dataflow-vuln-scanner/runs/{run_resolve.json()['run_id']}")
    assert run_detail.status_code == 200
    run_files = client.get(f"/api/dataflow-vuln-scanner/runs/{run_resolve.json()['run_id']}/files")
    assert run_files.status_code == 200
    artifact_paths = [item["path"] for item in run_files.json()]
    assert "run/input/task.md" in artifact_paths
    assert "run/run.log" in artifact_paths

    task_artifacts = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/artifacts")
    assert task_artifacts.status_code == 200
    artifacts_payload = task_artifacts.json()
    assert artifacts_payload["workspace_root"]
    assert artifacts_payload["output_root"] == str((Path(artifacts_payload["workspace_root"]) / "output").resolve())
    assert artifacts_payload["run_id"] == run_resolve.json()["run_id"]
    assert "run/input/task.md" in [item["path"] for item in artifacts_payload["files"]]

    retry = client.post(f"/api/dataflow-vuln-scanner/tasks/{task_id}/retry", json={"extra_cycles": 1})
    assert retry.status_code == 202
    assert retry.json()["latest_execution_id"] != execution_id
    _wait_for_task_status(client, task_id)

def test_task_retry_refreshes_projection_latest_execution(service_config_path, patch_mock_agent_runtime, monkeypatch):
    _disable_scheduler_start(monkeypatch)
    app = create_app()
    client = TestClient(app)

    create_profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload())
    assert create_profile.status_code == 201
    profile_id = create_profile.json()["profile_id"]

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile_id,
            "title": "projection retry demo",
            "task_markdown": "# Package List\n\n- demo.tar.gz\n",
            "artifact_refs": [],
            "runtime_overrides": {},
        },
    )
    assert task.status_code == 201
    task_payload = task.json()
    task_id = task_payload["task_id"]
    initial_execution_id = task_payload["latest_execution_id"]

    with get_db_session() as db:
        trigger = db.get(TriggerTask, task_id)
        execution = db.get(WorkflowExecution, initial_execution_id)
        projection = db.get(DfvsTaskListProjection, task_id)
        assert trigger is not None and execution is not None and projection is not None

        finished_at = now_local()
        trigger.status = "succeeded"
        trigger.public_status = "succeeded"
        trigger.message = "done"
        trigger.finished_at = finished_at
        execution.status = "succeeded"
        execution.public_status = "succeeded"
        execution.dispatch_status = "succeeded"
        execution.message = "done"
        execution.finished_at = finished_at
        db.add_all([trigger, execution])
        get_execution_service()._refresh_task_list_projection_for_task_id(db, task_id)
        db.commit()

        projection = db.get(DfvsTaskListProjection, task_id)
        assert projection is not None
        assert projection.latest_execution_id == initial_execution_id
        assert projection.public_status == "success"

    retry = client.post(f"/api/dataflow-vuln-scanner/tasks/{task_id}/retry", json={"extra_cycles": 1})
    assert retry.status_code == 202
    retry_payload = retry.json()
    next_execution_id = retry_payload["latest_execution_id"]
    assert next_execution_id != initial_execution_id

    with get_db_session() as db:
        trigger = db.get(TriggerTask, task_id)
        projection = db.get(DfvsTaskListProjection, task_id)
        assert trigger is not None and projection is not None
        assert trigger.latest_execution_id == next_execution_id
        assert projection.latest_execution_id == next_execution_id
        assert projection.public_status in {"pending", "dispatching", "running"}
        assert str(projection.message or "").strip()
        retry_event = (
            db.query(WorkflowExecutionEvent)
            .filter(
                WorkflowExecutionEvent.execution_id == next_execution_id,
                WorkflowExecutionEvent.event_type == "task_retry_queued",
            )
            .order_by(WorkflowExecutionEvent.created_at.desc())
            .first()
        )
        assert retry_event is not None
        assert retry_event.payload_json["task_id"] == task_id
        assert retry_event.payload_json["attempt_no"] == 2
        assert retry_event.payload_json["request"]["extra_cycles"] == 1


def test_task_apis_accept_machine_subject(service_config_path, patch_mock_agent_runtime, monkeypatch):
    app = create_app()
    client = TestClient(app)

    create_profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload())
    assert create_profile.status_code == 201
    profile_id = create_profile.json()["profile_id"]
    created = _create_business_dataflow_task(
        client,
        profile_id=profile_id,
        case_name="machine-subject-demo",
        title="machine subject scan",
    )

    from app.api import tasks as task_api

    async def _machine_subject(_authorization=None):
        return ({"token_type": "machine", "project_ids": ["default"]}, "machine-token")

    async def _reject_human(_authorization=None):
        raise HTTPException(status_code=401, detail="human token invalid")

    monkeypatch.setattr(task_api, "get_current_or_machine_subject", _machine_subject)
    monkeypatch.setattr(task_api, "get_current_subject", _reject_human)

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{created['task_id']}")
    assert detail.status_code == 200
    assert detail.json()["task_id"] == created["task_id"]

    listed = client.get("/api/dataflow-vuln-scanner/tasks", params={"project_id": "default"})
    assert listed.status_code == 200
    listed_payload = listed.json()
    assert listed_payload["page"] == 1
    assert listed_payload["page_size"] >= 1
    assert any(item["task_id"] == created["task_id"] for item in listed_payload["items"])


def test_task_apis_accept_machine_subject(service_config_path, patch_mock_agent_runtime, monkeypatch):
    app = create_app()
    client = TestClient(app)

    create_profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload())
    assert create_profile.status_code == 201
    profile_id = create_profile.json()["profile_id"]
    created = _create_business_dataflow_task(
        client,
        profile_id=profile_id,
        case_name="machine-subject-demo",
        title="machine subject scan",
    )

    from app.api import tasks as task_api

    async def _machine_subject(_authorization=None):
        return ({"token_type": "machine", "project_ids": ["default"]}, "machine-token")

    async def _reject_human(_authorization=None):
        raise HTTPException(status_code=401, detail="human token invalid")

    monkeypatch.setattr(task_api, "get_current_or_machine_subject", _machine_subject)
    monkeypatch.setattr(task_api, "get_current_subject", _reject_human)

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{created['task_id']}")
    assert detail.status_code == 200
    assert detail.json()["task_id"] == created["task_id"]

    listed = client.get("/api/dataflow-vuln-scanner/tasks", params={"project_id": "default"})
    assert listed.status_code == 200
    listed_payload = listed.json()
    assert listed_payload["page"] == 1
    assert listed_payload["page_size"] >= 1
    assert any(item["task_id"] == created["task_id"] for item in listed_payload["items"])


def test_task_list_uses_lightweight_run_locator_without_full_run_summary(service_config_path, patch_mock_agent_runtime, monkeypatch):
    app = create_app()
    client = TestClient(app)

    create_profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload())
    assert create_profile.status_code == 201
    profile_id = create_profile.json()["profile_id"]
    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile_id,
            "title": "lightweight list scan",
            "task_markdown": "# Package List\n\n- demo.tar.gz\n",
            "artifact_refs": [],
            "runtime_overrides": {},
        },
    )
    assert task.status_code == 201
    _wait_for_task_status(client, task.json()["task_id"])

    def fail_full_summary(*_args, **_kwargs):
        raise AssertionError("task list must not parse full run summary")

    monkeypatch.setattr(type(get_execution_service()), "_latest_run_summary_for_execution", fail_full_summary)

    response = client.get("/api/dataflow-vuln-scanner/tasks", params={"project_id": "default"})
    assert response.status_code == 200
    page_payload = response.json()
    items = page_payload["items"]
    assert items
    listed = next(item for item in items if item["task_id"] == task.json()["task_id"])
    assert listed["run_name"]
    assert listed["runs_root"]
    assert listed["latest_run"]["name"] == listed["run_name"]
    assert "process_state" not in listed["latest_run"]


def test_task_list_marks_stale_running_process_as_runtime_lost(service_config_path, patch_mock_agent_runtime):
    app = create_app()
    client = TestClient(app)

    create_profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload())
    assert create_profile.status_code == 201
    profile_id = create_profile.json()["profile_id"]
    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile_id,
            "title": "stale runtime list scan",
            "task_markdown": "# Package List\n\n- demo.tar.gz\n",
            "artifact_refs": [],
            "runtime_overrides": {},
        },
    )
    assert task.status_code == 201
    task_id = task.json()["task_id"]
    _wait_for_task_status(client, task_id)

    with get_db_session() as db:
        trigger = db.get(TriggerTask, task_id)
        execution = (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.trigger_task_id == task_id)
            .order_by(WorkflowExecution.created_at.desc())
            .first()
        )
        run_index = (
            db.query(RunIndex)
            .filter(RunIndex.linked_task_id == task_id)
            .order_by(RunIndex.started_at.desc(), RunIndex.created_at.desc())
            .first()
        )
        assert trigger is not None and execution is not None and run_index is not None
        run_index.status = "running"
        execution.status = "running"
        execution.process_status = "running"
        trigger.status = "running"
        db.add_all([run_index, execution, trigger])
        db.commit()
        write_json(
            run_index.run_root_path + "/_meta/process.json",
            {
                "execution_id": execution.id,
                "trigger_task_id": trigger.id,
                "pid": 4242,
                "pod_id": "old-pod",
                "status": "running",
                "heartbeat_at": "2026-04-28T01:02:03+08:00",
            },
        )

    response = client.get("/api/dataflow-vuln-scanner/tasks", params={"project_id": "default"})
    assert response.status_code == 200
    listed = next(item for item in response.json()["items"] if item["task_id"] == task_id)
    assert listed["status"] in {"running", "failed", "success", "pending", "queued", "dispatching"}
    assert "process_state" not in listed["latest_run"]

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}")
    assert detail.status_code == 200
    process_state = detail.json()["latest_run"]["process_state"]
    assert process_state["display_status"] == "runtime_lost"
    assert process_state["display_label"] == "运行失联"
    assert process_state["source"] == "stale_process_heartbeat"
    assert process_state["can_retry"] is True


def test_task_list_keeps_recent_heartbeat_grace_as_running(service_config_path, patch_mock_agent_runtime):
    app = create_app()
    client = TestClient(app)

    create_profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload())
    assert create_profile.status_code == 201
    profile_id = create_profile.json()["profile_id"]
    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile_id,
            "title": "heartbeat grace scan",
            "task_markdown": "# Package List\n\n- demo.tar.gz\n",
            "artifact_refs": [],
            "runtime_overrides": {},
        },
    )
    assert task.status_code == 201
    task_id = task.json()["task_id"]
    _wait_for_task_status(client, task_id)

    with get_db_session() as db:
        trigger = db.get(TriggerTask, task_id)
        execution = (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.trigger_task_id == task_id)
            .order_by(WorkflowExecution.created_at.desc())
            .first()
        )
        run_index = (
            db.query(RunIndex)
            .filter(RunIndex.linked_task_id == task_id)
            .order_by(RunIndex.started_at.desc(), RunIndex.created_at.desc())
            .first()
        )
        assert trigger is not None and execution is not None and run_index is not None
        run_index.status = "running"
        execution.status = "running"
        execution.process_status = "running"
        trigger.status = "running"
        db.add_all([run_index, execution, trigger])
        db.commit()
        write_json(
            run_index.run_root_path + "/_meta/process.json",
            {
                "execution_id": execution.id,
                "trigger_task_id": trigger.id,
                "pid": 4242,
                "pod_id": "slow-but-live-pod",
                "status": "running",
                "heartbeat_at": isoformat_local(now_local() - timedelta(seconds=151)),
            },
        )

    response = client.get("/api/dataflow-vuln-scanner/tasks", params={"project_id": "default"})
    assert response.status_code == 200
    listed = next(item for item in response.json()["items"] if item["task_id"] == task_id)
    assert "process_state" not in listed["latest_run"]

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}")
    assert detail.status_code == 200
    process_state = detail.json()["latest_run"]["process_state"]
    assert process_state["source"] == "process_file_heartbeat"
    assert process_state["is_running"] is True
    assert process_state["can_retry"] is False
    assert process_state.get("display_status") != "runtime_lost"
    assert process_state["stale_after_seconds"] >= 300


def test_get_task_keeps_pending_status_while_dispatch_is_queued(
    service_config_path,
    patch_mock_agent_runtime,
):
    app = create_app()
    client = TestClient(app)

    create_profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload())
    assert create_profile.status_code == 201
    profile_id = create_profile.json()["profile_id"]

    created = _create_business_dataflow_task(
        client,
        profile_id=profile_id,
        case_name="queued-task-status",
        title="queued task status",
    )
    task_id = created["task_id"]

    with get_db_session() as db:
        trigger = db.get(TriggerTask, task_id)
        execution = db.get(WorkflowExecution, created["latest_execution_id"])
        assert trigger is not None and execution is not None
        trigger.status = "pending"
        trigger.started_at = None
        trigger.finished_at = None
        trigger.message = "dispatch pending"
        execution.status = "pending"
        execution.dispatch_status = "queued"
        execution.message = "queued on worker http://worker-0"
        execution.started_at = None
        execution.finished_at = None
        db.add_all([trigger, execution])
        db.commit()

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}")
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["status"] == "dispatching"
    assert payload["message"] == "queued on worker http://worker-0"
    assert payload["started_at"] is None
    assert payload["finished_at"] is None


def test_get_task_promotes_pending_trigger_to_running_from_execution_status(
    service_config_path,
    patch_mock_agent_runtime,
):
    app = create_app()
    client = TestClient(app)

    create_profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload())
    assert create_profile.status_code == 201
    profile_id = create_profile.json()["profile_id"]

    created = _create_business_dataflow_task(
        client,
        profile_id=profile_id,
        case_name="running-task-status",
        title="running task status",
    )
    task_id = created["task_id"]
    started_at = now_local()

    with get_db_session() as db:
        trigger = db.get(TriggerTask, task_id)
        execution = db.get(WorkflowExecution, created["latest_execution_id"])
        assert trigger is not None and execution is not None
        trigger.status = "pending"
        trigger.started_at = None
        trigger.finished_at = None
        trigger.message = "pending start"
        execution.status = "running"
        execution.dispatch_status = "running"
        execution.message = "run_vuln_scan.py running"
        execution.started_at = started_at
        execution.finished_at = None
        db.add_all([trigger, execution])
        db.commit()

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}")
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["status"] == "running"
    assert payload["message"] == "run_vuln_scan.py running"
    assert payload["started_at"].startswith(started_at.strftime("%Y-%m-%dT%H:%M:%S"))
    assert payload["finished_at"] is None



def test_create_task_bootstraps_default_profile_when_missing(service_config_path, patch_mock_agent_runtime):
    app = create_app()
    client = TestClient(app)

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "title": "scan without precreated profile",
            "task_markdown": "# Package List\n\n- demo.tar.gz\n",
            "artifact_refs": [],
            "runtime_overrides": {},
        },
    )
    assert task.status_code == 201
    task_payload = task.json()
    assert task_payload["status"] in {"running", "succeeded"}
    assert task_payload["profile_id"]
    _wait_for_task_status(client, task_payload["task_id"])

    profiles = client.get("/api/dataflow-vuln-scanner/profiles", params={"project_id": "default"})
    assert profiles.status_code == 200
    profile_items = profiles.json()
    assert len(profile_items) == 1
    assert profile_items[0]["profile_id"] == task_payload["profile_id"]
    assert profile_items[0]["is_default"] is True
    assert profile_items[0]["enabled"] is True


def test_create_task_rejects_profile_from_different_project(service_config_path, patch_mock_agent_runtime):
    app = create_app()
    client = TestClient(app)

    profile_payload = _profile_payload()
    profile_payload["project_id"] = "project-1"
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=profile_payload)
    assert profile.status_code == 201

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile.json()["profile_id"],
            "title": "scan with wrong project profile",
            "task_markdown": "# Package List\n\n- demo.tar.gz\n",
            "artifact_refs": [],
            "runtime_overrides": {},
        },
    )
    assert task.status_code == 422
    assert "different project" in task.json()["detail"]


def test_task_bound_profile_versions_do_not_become_default(service_config_path, patch_mock_agent_runtime):
    app = create_app()
    client = TestClient(app)

    create_profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload())
    assert create_profile.status_code == 201
    profile = create_profile.json()
    profile_id = profile["profile_id"]
    assert profile["version"] == 1

    override_task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile_id,
            "title": "fast one-off task",
            "task_markdown": "# Package List\n\n- demo.tar.gz\n",
            "review_profile": "fast",
            "max_review_cycles": 1,
        },
    )
    assert override_task.status_code == 201
    assert override_task.json()["profile_version"] == 2
    _wait_for_task_status(client, override_task.json()["task_id"])

    default_task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile_id,
            "title": "default task after one-off override",
            "task_markdown": "# Package List\n\n- demo.tar.gz\n",
        },
    )
    assert default_task.status_code == 201
    assert default_task.json()["profile_version"] == 1
    _wait_for_task_status(client, default_task.json()["task_id"])

    profile_after = client.get(f"/api/dataflow-vuln-scanner/profiles/{profile_id}")
    assert profile_after.status_code == 200
    assert profile_after.json()["version"] == 1

    effective = client.get("/api/dataflow-vuln-scanner/projects/default/config/effective")
    assert effective.status_code == 200
    assert effective.json()["effective_config"]["profile_version"]["version"] == 1


def test_dataflow_task_rejects_absolute_input_refs_by_default(service_config_path, patch_mock_agent_runtime):
    config = get_config()
    project_root = config.fileserver_service.data_mount_path
    from pathlib import Path

    case_root = Path(project_root) / "files" / "default" / "case-absolute"
    source_dir = case_root / "source"
    source_dir.mkdir(parents=True, exist_ok=True)
    data_flow_dir = case_root / "data_flow"
    data_flow_dir.mkdir(parents=True, exist_ok=True)
    (data_flow_dir / "data_flow.md").write_text("# 数据流追踪：demo\n", encoding="utf-8")

    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile["profile_id"],
            "title": "absolute path rejected",
            "data_flow": {"source": "absolute_path", "path": str(data_flow_dir.resolve())},
            "source_dir": {"source": "absolute_path", "path": str(source_dir.resolve())},
        },
    )
    assert task.status_code == 422
    assert "absolute_path input is disabled" in task.json()["detail"]


def test_dataflow_task_rejects_fileserver_storage_outside_project(service_config_path, patch_mock_agent_runtime):
    config = get_config()
    project_root = config.fileserver_service.data_mount_path
    from pathlib import Path

    other_root = Path(project_root) / "files" / "other" / "case-cross-project"
    other_source = other_root / "source"
    other_source.mkdir(parents=True, exist_ok=True)
    other_data_flow_dir = other_root / "data_flow"
    other_data_flow_dir.mkdir(parents=True, exist_ok=True)
    (other_data_flow_dir / "data_flow.md").write_text("# 数据流追踪：demo\n", encoding="utf-8")

    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile["profile_id"],
            "title": "cross project storage rejected",
            "data_flow": {"source": "fileserver_storage", "storage_key": "files/other/case-cross-project/data_flow"},
            "source_dir": {"source": "fileserver_storage", "storage_key": "files/other/case-cross-project/source"},
        },
    )
    assert task.status_code == 422
    assert "escapes project root" in task.json()["detail"]


def test_business_dataflow_task_materializes_inputs_and_runs(service_config_path, patch_mock_agent_runtime):
    config = get_config()
    project_root = config.fileserver_service.data_mount_path
    from pathlib import Path

    case_root = Path(project_root) / "files" / "default" / "case-a"
    source_dir = case_root / "source"
    data_flow_dir = case_root / "data_flow"
    source_dir.mkdir(parents=True, exist_ok=True)
    data_flow_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "demo.c").write_text("int demo(char *p) { return p[0]; }\n", encoding="utf-8")
    (data_flow_dir / "data_flow.md").write_text("# 数据流追踪：demo\n\n| 📌 USED | 1 |\nINPUT-1\n", encoding="utf-8")

    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile["profile_id"],
            "title": "business scan",
            "data_flow": {"source": "project_filesystem", "path": "/case-a/data_flow"},
            "source_dir": {"source": "project_filesystem", "path": "/case-a/source"},
            "model": "mock/model",
            "thinking": "medium",
            "review_profile": "fast",
            "max_review_cycles": 1,
            "result_review_concurrency": 1,
        },
    )
    assert task.status_code == 201
    task_id = task.json()["task_id"]

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}")
    assert detail.status_code == 200
    payload = detail.json()
    assert "漏洞挖掘任务" in payload["task_markdown"]
    cli_plan = payload["task_metadata"]["dataflow_cli"]
    expected_run_name = "business-scan"
    assert cli_plan["launcher"] == "run_vuln_scan.py"
    assert cli_plan["data_flow_dir"] == str(data_flow_dir.resolve())
    assert cli_plan["data_flow_files"] == [str((data_flow_dir / "data_flow.md").resolve())]
    assert cli_plan["source_dir"] == str(source_dir.resolve())
    assert Path(cli_plan["run_dir"]).parent.name == "secflow-app-dataflow-vuln-scanner"
    assert cli_plan["run_name"] == expected_run_name
    assert Path(cli_plan["run_dir"]).name == expected_run_name

    execution_id = payload["attempts"][0]["execution_id"]
    _wait_for_task_status(client, task_id)

    run_resolve = client.get(
        "/api/dataflow-vuln-scanner/runs/by-task",
        params={"project_id": "default", "task_id": task_id, "execution_id": execution_id},
    )
    assert run_resolve.status_code == 200
    run_detail = client.get(f"/api/dataflow-vuln-scanner/runs/{run_resolve.json()['run_id']}")
    assert run_detail.status_code == 200
    run_payload = run_detail.json()
    assert run_payload["config"]["thinking"] == ""
    assert "run_vuln_scan.py" in run_payload["command_display"]
    assert "--model mock/model" in run_payload["command_display"] or "--config " in run_payload["command_display"]
    assert f"--run-name {expected_run_name}" in run_payload["command_display"]
    assert "--timeout-max-retries 3" in run_payload["command_display"]
    assert "--timeout-retry-interval-seconds 30" in run_payload["command_display"]
    assert run_payload["raw"]["dataflow_cli"]["command_display"] == run_payload["command_display"]
    input_manifest = json.loads((Path(cli_plan["run_dir"]) / "input" / "input_manifest.json").read_text(encoding="utf-8"))
    assert input_manifest["input"]["data_flow_dir"] == str(data_flow_dir.resolve())
    assert input_manifest["input"]["data_flow_files"] == [str((data_flow_dir / "data_flow.md").resolve())]
    assert "data_flow_file" not in input_manifest["input"]

    run_files = client.get(f"/api/dataflow-vuln-scanner/runs/{run_resolve.json()['run_id']}/files")
    assert run_files.status_code == 200
    file_paths = [item["path"] for item in run_files.json()]
    assert "run/input/task.md" in file_paths
    assert "run/config.json" in file_paths
    assert "run/run.log" in file_paths


def test_business_dataflow_task_ignores_selected_runs_root_for_standard_task_layout(service_config_path, patch_mock_agent_runtime):
    config = get_config()
    project_root = config.fileserver_service.data_mount_path
    from pathlib import Path
    import json

    case_root = Path(project_root) / "files" / "default" / "case-custom"
    source_dir = case_root / "source"
    runs_root = case_root / "runs"
    source_dir.mkdir(parents=True, exist_ok=True)
    runs_root.mkdir(parents=True, exist_ok=True)
    (source_dir / "demo.c").write_text("int demo(char *p) { return p[0]; }\n", encoding="utf-8")
    (runs_root / ".keep").write_text("", encoding="utf-8")
    data_flow_dir = case_root / "data_flow"
    data_flow_dir.mkdir(parents=True, exist_ok=True)
    (data_flow_dir / "data_flow.md").write_text("# 数据流追踪：demo\n\n| 📌 USED | 1 |\nINPUT-1\n", encoding="utf-8")

    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile["profile_id"],
            "title": "business scan custom workspace",
            "workspace_dir": {"source": "project_filesystem", "path": "/case-custom/runs"},
            "data_flow": {"source": "project_filesystem", "path": "/case-custom/data_flow"},
            "source_dir": {"source": "project_filesystem", "path": "/case-custom/source"},
            "model": "mock/model",
            "thinking": "medium",
            "review_profile": "fast",
            "max_review_cycles": 1,
            "result_review_concurrency": 1,
        },
    )
    assert task.status_code == 201
    created_payload = task.json()
    task_id = created_payload["task_id"]
    expected_run_name = "business-scan-custom-workspace"
    service_root = Path(project_root) / "files" / "default" / "app" / "secflow-app-dataflow-vuln-scanner"
    assert created_payload["run_name"] == expected_run_name
    assert created_payload["runs_root"] == str(service_root.resolve())
    assert Path(created_payload["run_path"]).parent == service_root.resolve()
    assert created_payload["run"]["name"] == expected_run_name
    assert created_payload["run"]["root_path"] == str(service_root.resolve())

    list_payload = client.get("/api/dataflow-vuln-scanner/tasks", params={"project_id": "default"})
    assert list_payload.status_code == 200
    listed_task = next(item for item in list_payload.json()["items"] if item["task_id"] == task_id)
    assert listed_task["run_name"] == expected_run_name
    assert listed_task["runs_root"] == str(service_root.resolve())
    assert Path(listed_task["run_path"]).parent == service_root.resolve()
    assert listed_task["run"]["name"] == expected_run_name
    assert listed_task["run"]["root_path"] == str(service_root.resolve())

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}")
    assert detail.status_code == 200
    cli_plan = detail.json()["task_metadata"]["dataflow_cli"]
    assert cli_plan["runs_root"] == str(service_root.resolve())

    detail_payload = _wait_for_task_status(client, task_id)
    assert detail_payload["attempts"]
    execution_id = detail_payload["attempts"][0]["execution_id"]
    expected_run_root = Path(detail_payload["attempts"][0]["workspace_root"])
    assert expected_run_root.parent == service_root.resolve()
    assert expected_run_root.name == expected_run_name

    run_resolve = client.get(
        "/api/dataflow-vuln-scanner/runs/by-task",
        params={"project_id": "default", "task_id": task_id, "execution_id": execution_id},
    )
    assert run_resolve.status_code == 200
    assert run_resolve.json()["run_id"]
    run_detail = client.get(f"/api/dataflow-vuln-scanner/runs/{run_resolve.json()['run_id']}")
    assert run_detail.status_code == 200
    assert run_detail.json()["run_id"] == run_resolve.json()["run_id"]
    assert run_detail.json()["path"] == str(expected_run_root.resolve())

    runtime_config = json.loads((expected_run_root / "run" / "config.json").read_text(encoding="utf-8"))
    assert runtime_config["global"]["workspace_root"] == str((expected_run_root / "run" / "workspace").resolve())
    assert runtime_config["execution"]["output_dir"] == str((expected_run_root / "output").resolve())


def test_business_dataflow_task_without_title_uses_task_id_for_run_name(service_config_path, patch_mock_agent_runtime):
    config = get_config()
    project_root = config.fileserver_service.data_mount_path
    from pathlib import Path

    case_root = Path(project_root) / "files" / "default" / "case-no-title"
    source_dir = case_root / "source"
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "demo.c").write_text("int demo(char *p) { return p[0]; }\n", encoding="utf-8")
    data_flow_dir = case_root / "data_flow"
    data_flow_dir.mkdir(parents=True, exist_ok=True)
    (data_flow_dir / "custom_flow.md").write_text("# 数据流追踪：demo\n\n| 📌 USED | 1 |\nINPUT-1\n", encoding="utf-8")

    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile["profile_id"],
            "data_flow": {"source": "project_filesystem", "path": "/case-no-title/data_flow"},
            "source_dir": {"source": "project_filesystem", "path": "/case-no-title/source"},
            "model": "mock/model",
            "review_profile": "fast",
            "max_review_cycles": 1,
            "result_review_concurrency": 1,
        },
    )
    assert task.status_code == 201
    payload = task.json()
    assert payload["run_name"] == payload["task_id"]
    assert payload["title"] == payload["task_id"]

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{payload['task_id']}")
    assert detail.status_code == 200
    cli_plan = detail.json()["task_metadata"]["dataflow_cli"]
    assert cli_plan["run_name"] == payload["run_name"]
    assert Path(cli_plan["run_dir"]).name == payload["run_name"]


def test_dataflow_run_resolve_by_task_reinitializes_missing_pending_run(
    service_config_path,
    patch_mock_agent_runtime,
    monkeypatch,
):
    from pathlib import Path
    import shutil

    from app.api import tasks as task_api

    class NoopScheduler:
        def start_execution_now(self, execution_id):
            return False

    monkeypatch.setattr(task_api, "get_scheduler_service", lambda: NoopScheduler())

    config = get_config()
    project_root = Path(config.fileserver_service.data_mount_path)
    case_root = project_root / "files" / "default" / "case-pending-resolve"
    source_dir = case_root / "source"
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "demo.c").write_text("int demo(char *p) { return p[0]; }\n", encoding="utf-8")
    data_flow_dir = case_root / "data_flow"
    data_flow_dir.mkdir(parents=True, exist_ok=True)
    (data_flow_dir / "data_flow.md").write_text("# 数据流追踪：demo\n\n| 📌 USED | 1 |\nINPUT-1\n", encoding="utf-8")

    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile["profile_id"],
            "title": "pending resolve scan",
            "data_flow": {"source": "project_filesystem", "path": "/case-pending-resolve/data_flow"},
            "source_dir": {"source": "project_filesystem", "path": "/case-pending-resolve/source"},
            "model": "mock/model",
            "review_profile": "fast",
            "max_review_cycles": 1,
        },
    )
    assert task.status_code == 201
    payload = task.json()
    run_root = Path(payload["run_path"])
    shutil.rmtree(run_root)

    run_resolve = client.get(
        "/api/dataflow-vuln-scanner/runs/by-task",
        params={
            "project_id": "default",
            "task_id": payload["task_id"],
            "execution_id": payload["latest_execution_id"],
        },
    )
    assert run_resolve.status_code == 200
    assert run_resolve.json()["linked_task_id"] == payload["task_id"]
    assert run_root.is_dir()
    assert (run_root / "run" / "input" / "task.md").is_file()


def test_dataflow_run_resolve_by_task_recovers_from_metadata_when_workspace_root_missing(
    service_config_path,
    patch_mock_agent_runtime,
    monkeypatch,
):
    from pathlib import Path

    from app.api import tasks as task_api
    from app.services.run_index_service import get_run_index_service

    class NoopScheduler:
        def start_execution_now(self, execution_id):
            return False

    monkeypatch.setattr(task_api, "get_scheduler_service", lambda: NoopScheduler())

    config = get_config()
    project_root = Path(config.fileserver_service.data_mount_path)
    case_root = project_root / "files" / "default" / "case-metadata-resolve"
    source_dir = case_root / "source"
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "demo.c").write_text("int demo(char *p) { return p[0]; }\n", encoding="utf-8")
    data_flow_dir = case_root / "data_flow"
    data_flow_dir.mkdir(parents=True, exist_ok=True)
    (data_flow_dir / "data_flow.md").write_text("# 数据流追踪：demo\n\n| 📌 USED | 1 |\nINPUT-1\n", encoding="utf-8")

    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile["profile_id"],
            "title": "metadata resolve scan",
            "data_flow": {"source": "project_filesystem", "path": "/case-metadata-resolve/data_flow"},
            "source_dir": {"source": "project_filesystem", "path": "/case-metadata-resolve/source"},
            "model": "mock/model",
            "review_profile": "fast",
            "max_review_cycles": 1,
        },
    )
    assert task.status_code == 201
    payload = task.json()
    task_id = payload["task_id"]
    execution_id = payload["latest_execution_id"]
    run_root = Path(payload["run_path"]).resolve()

    db = get_db_session()
    try:
        for record in db.query(RunIndex).filter(RunIndex.linked_task_id == task_id).all():
            get_run_index_service()._delete_children(db, record.id)
            db.delete(record)
        execution = db.get(WorkflowExecution, execution_id)
        assert execution is not None
        execution.workspace_root = None
        db.add(execution)
        db.commit()
    finally:
        db.close()

    run_resolve = client.get(
        "/api/dataflow-vuln-scanner/runs/by-task",
        params={
            "project_id": "default",
            "task_id": task_id,
            "execution_id": execution_id,
        },
    )
    assert run_resolve.status_code == 200
    assert run_resolve.json()["linked_task_id"] == task_id
    assert run_resolve.json()["linked_execution_id"] == execution_id
    assert Path(run_resolve.json()["root_path"]) == run_root.parent

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        assert execution is not None
        assert Path(execution.workspace_root).resolve() == run_root
    finally:
        db.close()


def test_business_dataflow_task_rejects_output_dir_with_cli_launcher(service_config_path, patch_mock_agent_runtime):
    config = get_config()
    project_root = config.fileserver_service.data_mount_path
    from pathlib import Path

    case_root = Path(project_root) / "files" / "default" / "case-workspace-only"
    source_dir = case_root / "source"
    runs_root = case_root / "runs"
    output_dir = runs_root / "nested-output"
    source_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "demo.c").write_text("int demo(char *p) { return p[0]; }\n", encoding="utf-8")
    data_flow_dir = case_root / "data_flow"
    data_flow_dir.mkdir(parents=True, exist_ok=True)
    (data_flow_dir / "data_flow.md").write_text("# 数据流追踪：demo\n\n| 📌 USED | 1 |\nINPUT-1\n", encoding="utf-8")

    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile["profile_id"],
            "title": "business scan default output",
            "workspace_dir": {"source": "project_filesystem", "path": "/case-workspace-only/runs"},
            "data_flow": {"source": "project_filesystem", "path": "/case-workspace-only/data_flow"},
            "source_dir": {"source": "project_filesystem", "path": "/case-workspace-only/source"},
            "output_dir": {"source": "project_filesystem", "path": "/case-workspace-only/runs/nested-output"},
            "model": "mock/model",
            "thinking": "medium",
            "review_profile": "fast",
            "max_review_cycles": 1,
            "result_review_concurrency": 1,
        },
    )
    assert task.status_code == 422
    assert "output_dir is not supported" in task.text


def test_dataflow_task_creates_missing_profile_version_snapshot(service_config_path, patch_mock_agent_runtime):
    config = get_config()
    project_root = config.fileserver_service.data_mount_path
    from pathlib import Path

    case_root = Path(project_root) / "files" / "default" / "case-missing-profile-version"
    source_dir = case_root / "source"
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "demo.c").write_text("int demo(char *p) { return p[0]; }\n", encoding="utf-8")
    data_flow_dir = case_root / "data_flow"
    data_flow_dir.mkdir(parents=True, exist_ok=True)
    (data_flow_dir / "data_flow.md").write_text("# 数据流追踪：demo\n\nINPUT-1\n", encoding="utf-8")

    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()
    profile_id = profile["profile_id"]

    db = get_db_session()
    try:
        db.query(WorkflowDefinitionVersion).filter(
            WorkflowDefinitionVersion.workflow_definition_id == profile_id
        ).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile_id,
            "title": "business scan with repaired profile version",
            "data_flow": {"source": "project_filesystem", "path": "/case-missing-profile-version/data_flow"},
            "source_dir": {"source": "project_filesystem", "path": "/case-missing-profile-version/source"},
        },
    )
    assert task.status_code == 201
    assert task.json()["profile_version"] == 1

    versions = client.get(f"/api/dataflow-vuln-scanner/profiles/{profile_id}/versions")
    assert versions.status_code == 200
    assert versions.json()[0]["version"] == 1


def test_create_evolution_task_from_normal_task_inherits_defaults_and_derivation(service_config_path, patch_mock_agent_runtime, monkeypatch):
    _disable_scheduler_start(monkeypatch)
    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()
    source = _create_business_dataflow_task(
        client,
        profile_id=profile["profile_id"],
        case_name="case-evolution-source",
        title="normal source scan",
    )
    source_detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{source['task_id']}").json()
    source_execution_id = source_detail["latest_execution_id"]
    source_run = client.get(
        "/api/dataflow-vuln-scanner/runs/by-task",
        params={"project_id": "default", "task_id": source["task_id"], "execution_id": source_execution_id},
    )
    assert source_run.status_code == 200
    source_run_id = source_run.json()["run_id"]

    created = client.post(
        f"/api/dataflow-vuln-scanner/tasks/{source['task_id']}/create-evolution",
        json={},
    )
    assert created.status_code == 201
    payload = created.json()
    assert payload["task_purpose"] == "evolution"
    assert payload["derived_from_task_id"] == source["task_id"]
    assert payload["derived_from_execution_id"] == source_execution_id
    assert payload["derived_from_run_id"] == source_run_id
    assert payload["derivation_kind"] == "evolution_replay"
    assert payload["task_origin_type"] == source["task_origin_type"]
    assert payload["title"] == "Evolution of normal source scan"

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{payload['task_id']}").json()
    assert detail["task_purpose"] == "evolution"
    assert detail["derived_from_task_id"] == source["task_id"]
    assert detail["task_metadata"]["derivation"]["kind"] == "evolution_replay"
    assert detail["task_metadata"]["derivation"]["source_task_id"] == source["task_id"]
    assert detail["task_metadata"]["derivation"]["source_execution_id"] == source_execution_id
    assert detail["task_metadata"]["derivation"]["source_run_id"] == source_run_id
    assert detail["task_metadata"]["derivation"]["source_task_purpose"] == "normal"
    assert detail["task_metadata"]["dataflow_scan_request"]["data_flow"] == source_detail["task_metadata"]["dataflow_scan_request"]["data_flow"]
    assert detail["task_metadata"]["dataflow_scan_request"]["source_dir"] == source_detail["task_metadata"]["dataflow_scan_request"]["source_dir"]

    db = get_db_session()
    try:
        event = (
            db.query(WorkflowExecutionEvent)
            .filter(
                WorkflowExecutionEvent.execution_id == payload["latest_execution_id"],
                WorkflowExecutionEvent.event_type == "task_evolution_created",
            )
            .order_by(WorkflowExecutionEvent.created_at.desc())
            .first()
        )
        assert event is not None
        assert event.payload_json["source_task_id"] == source["task_id"]
        assert event.payload_json["source_execution_id"] == source_execution_id
        assert event.payload_json["source_run_id"] == source_run_id
        assert event.payload_json["created_task_id"] == detail["task_id"]
        assert event.payload_json["task_purpose"] == "evolution"
    finally:
        db.close()


def test_create_evolution_task_allows_running_failed_and_cancelled_source_statuses(service_config_path, patch_mock_agent_runtime, monkeypatch):
    _disable_scheduler_start(monkeypatch)
    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()
    source = _create_business_dataflow_task(
        client,
        profile_id=profile["profile_id"],
        case_name="case-evolution-statuses",
        title="status source scan",
    )
    source_detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{source['task_id']}").json()
    source_execution_id = source_detail["latest_execution_id"]

    for status_name in ("running", "failed", "cancelled"):
        db = get_db_session()
        try:
            trigger = db.get(TriggerTask, source["task_id"])
            execution = db.get(WorkflowExecution, source_execution_id)
            assert trigger is not None and execution is not None
            trigger.status = status_name
            execution.status = status_name
            if status_name == "running":
                trigger.finished_at = None
                execution.finished_at = None
            db.add(trigger)
            db.add(execution)
            db.commit()
        finally:
            db.close()

        response = client.post(
            f"/api/dataflow-vuln-scanner/tasks/{source['task_id']}/create-evolution",
            json={"title": f"evolution from {status_name}"},
        )
        assert response.status_code == 201
        created = response.json()
        assert created["task_purpose"] == "evolution"
        assert created["derived_from_task_id"] == source["task_id"]


def test_create_evolution_task_rejects_evolution_source_and_non_cli_source(service_config_path, patch_mock_agent_runtime, monkeypatch):
    _disable_scheduler_start(monkeypatch)
    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()
    source = _create_business_dataflow_task(
        client,
        profile_id=profile["profile_id"],
        case_name="case-evolution-reject",
        title="reject source scan",
    )
    evolution = client.post(
        f"/api/dataflow-vuln-scanner/tasks/{source['task_id']}/create-evolution",
        json={"title": "first evolution"},
    )
    assert evolution.status_code == 201
    second_hop = client.post(
        f"/api/dataflow-vuln-scanner/tasks/{evolution.json()['task_id']}/create-evolution",
        json={},
    )
    assert second_hop.status_code == 409
    assert "only normal tasks" in second_hop.text

    manual = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile["profile_id"],
            "title": "manual non cli task",
            "task_markdown": "# Manual\n",
        },
    )
    assert manual.status_code == 201
    rejected = client.post(
        f"/api/dataflow-vuln-scanner/tasks/{manual.json()['task_id']}/create-evolution",
        json={},
    )
    assert rejected.status_code == 422
    assert "run_vuln_scan.py launcher" in rejected.text


def test_create_evolution_task_applies_overrides_and_agent_state_roots(service_config_path, patch_mock_agent_runtime, monkeypatch):
    _disable_scheduler_start(monkeypatch)
    app = create_app()
    client = TestClient(app)
    base_profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()
    alt_profile_payload = _profile_payload()
    alt_profile_payload["name"] = "alternate scanner"
    alt_profile_payload["config_payload"]["review_profile"] = "audit"
    alt_profile = client.post("/api/dataflow-vuln-scanner/profiles", json=alt_profile_payload).json()
    source = _create_business_dataflow_task(
        client,
        profile_id=base_profile["profile_id"],
        case_name="case-evolution-overrides",
        title="override source scan",
        extra_payload={
            "workspace_dir": {"source": "project_filesystem", "path": "/case-evolution-overrides/workspace"},
            "runtime_overrides": {"base_toggle": True},
        },
    )
    source_detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{source['task_id']}").json()

    project_root = Path(get_config().fileserver_service.data_mount_path) / "files" / "default"
    worker_root = project_root / "evolution-roots" / "worker-a"
    worker_root.mkdir(parents=True, exist_ok=True)

    created = client.post(
        f"/api/dataflow-vuln-scanner/tasks/{source['task_id']}/create-evolution",
        json={
            "title": "custom evolution replay",
            "profile_id": alt_profile["profile_id"],
            "priority": 77,
            "model": "mock/override-model",
            "review_profile": "audit",
            "max_review_cycles": 3,
            "agent_run_timeout_seconds": 99,
            "agent_timeout_retry_enabled": False,
            "agent_timeout_max_retries": 1,
            "timeout_max_retries": 2,
            "timeout_retry_interval_seconds": 0,
            "result_review_concurrency": 2,
            "runtime_overrides": {"extra_toggle": "yes"},
            "scan_options": {"custom_option": "enabled"},
            "auto_report_vulnerabilities": False,
            "agent_state_roots": {
                "pi-worker": {
                    "root_dir": {"source": "project_filesystem", "path": "/evolution-roots/worker-a"}
                }
            },
        },
    )
    assert created.status_code == 201
    payload = created.json()
    assert payload["profile_id"] == alt_profile["profile_id"]
    assert payload["priority"] == 77
    assert payload["task_purpose"] == "evolution"
    assert payload["agent_state_dirs"]["pi-worker"]["source"] == "task_override"
    assert payload["agent_state_dirs"]["pi-worker"]["root_dir"] == str(worker_root.resolve())

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{payload['task_id']}").json()
    request_payload = detail["task_metadata"]["dataflow_scan_request"]
    assert detail["task_origin_type"] == source["task_origin_type"]
    assert detail["auto_report_vulnerabilities"] is False
    assert detail["runtime_overrides"]["base_toggle"] is True
    assert detail["runtime_overrides"]["extra_toggle"] == "yes"
    assert request_payload["data_flow"] == source_detail["task_metadata"]["dataflow_scan_request"]["data_flow"]
    assert request_payload["source_dir"] == source_detail["task_metadata"]["dataflow_scan_request"]["source_dir"]
    assert request_payload["workspace_dir"] == source_detail["task_metadata"]["dataflow_scan_request"]["workspace_dir"]
    assert request_payload["model"] == "mock/override-model"
    assert request_payload["review_profile"] == "audit"
    assert request_payload["max_review_cycles"] == 3
    assert request_payload["agent_run_timeout_seconds"] == 99
    assert request_payload["agent_timeout_retry_enabled"] is False
    assert request_payload["agent_timeout_max_retries"] == 1
    assert request_payload["timeout_max_retries"] == 2
    assert request_payload["timeout_retry_interval_seconds"] == 0
    assert request_payload["result_review_concurrency"] == 2
    assert request_payload["options"]["custom_option"] == "enabled"


def test_task_mutation_timeline_records_create_cancel_priority_and_projection(service_config_path, patch_mock_agent_runtime, monkeypatch):
    _disable_scheduler_start(monkeypatch)
    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()

    created = _create_business_dataflow_task(
        client,
        profile_id=profile["profile_id"],
        case_name="case-task-mutation-timeline",
        title="timeline mutation scan",
    )
    task_id = created["task_id"]

    timeline = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/timeline")
    assert timeline.status_code == 200
    items = timeline.json()["items"]
    task_created = next((item for item in items if item["event_type"] == "task_created"), None)
    execution_queued = next((item for item in items if item["event_type"] == "execution_queued"), None)
    assert task_created is not None
    assert execution_queued is not None
    assert task_created["payload"]["task_id"] == task_id
    assert task_created["payload"]["project_id"] == "default"
    assert task_created["payload"]["task_purpose"] == "normal"
    assert task_created["payload"]["dataflow_cli_task"] is True

    priority_response = client.post(
        f"/api/dataflow-vuln-scanner/tasks/{task_id}/priority",
        json={"priority": 77},
    )
    assert priority_response.status_code == 200
    projection_response = client.post(f"/api/dataflow-vuln-scanner/tasks/{task_id}/projection/rebuild")
    assert projection_response.status_code == 200
    cancel_response = client.post(f"/api/dataflow-vuln-scanner/tasks/{task_id}/cancel")
    assert cancel_response.status_code == 200

    timeline = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/timeline")
    assert timeline.status_code == 200
    items = timeline.json()["items"]
    priority_event = next((item for item in items if item["event_type"] == "task_priority_updated"), None)
    projection_event = next((item for item in items if item["event_type"] == "task_projection_rebuilt"), None)
    cancel_event = next((item for item in items if item["event_type"] == "task_cancel_requested"), None)
    assert priority_event is not None
    assert priority_event["payload"]["old_priority"] == 120
    assert priority_event["payload"]["new_priority"] == 77
    assert projection_event is not None
    assert projection_event["payload"]["task_id"] == task_id
    assert cancel_event is not None
    assert cancel_event["payload"]["task_id"] == task_id
    assert cancel_event["payload"]["signal_process"] is True
    assert cancel_event["payload"]["status_before"] == "pending"


def test_timeline_clear_and_delete_do_not_create_extra_events(service_config_path, patch_mock_agent_runtime, monkeypatch):
    _disable_scheduler_start(monkeypatch)
    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()

    created = _create_business_dataflow_task(
        client,
        profile_id=profile["profile_id"],
        case_name="case-timeline-clear-delete",
        title="timeline clear delete scan",
    )
    task_id = created["task_id"]

    timeline = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/timeline")
    assert timeline.status_code == 200
    first_items = timeline.json()["items"]
    assert len(first_items) >= 2
    first_event_id = first_items[0]["id"]

    delete_one = client.delete(f"/api/dataflow-vuln-scanner/tasks/{task_id}/timeline/{first_event_id}")
    assert delete_one.status_code == 200
    after_delete = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/timeline")
    assert after_delete.status_code == 200
    after_delete_items = after_delete.json()["items"]
    assert all(item["event_type"] != "timeline_event_deleted" for item in after_delete_items)

    clear_response = client.delete(f"/api/dataflow-vuln-scanner/tasks/{task_id}/timeline")
    assert clear_response.status_code == 200
    assert clear_response.json()["deleted_event_count"] == len(after_delete_items)
    final_timeline = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/timeline")
    assert final_timeline.status_code == 200
    assert final_timeline.json()["items"] == []


def test_project_filesystem_browser_uses_local_project_tree(service_config_path):
    config = get_config()
    project_root = config.fileserver_service.data_mount_path
    from pathlib import Path

    case_root = Path(project_root) / "files" / "default" / "case-browser"
    nested_dir = case_root / "source"
    nested_dir.mkdir(parents=True, exist_ok=True)
    data_flow_dir = case_root / "data_flow"
    data_flow_dir.mkdir(parents=True, exist_ok=True)
    (data_flow_dir / "data_flow.md").write_text("# browser test\n", encoding="utf-8")
    (nested_dir / "demo.c").write_text("int demo(void) { return 0; }\n", encoding="utf-8")

    app = create_app()
    client = TestClient(app)

    root = client.get("/api/dataflow-vuln-scanner/project-filesystem/root", params={"project_id": "default"})
    assert root.status_code == 200
    items = {item["name"]: item for item in root.json()["items"]}
    assert items["case-browser"]["node_type"] == "subproject"
    assert items["case-browser"]["path"] == "/case-browser"

    children = client.get(
        "/api/dataflow-vuln-scanner/project-filesystem/children",
        params={"project_id": "default", "path": "/case-browser"},
    )
    assert children.status_code == 200
    payload = children.json()
    assert payload["current_path"] == "/case-browser"
    assert payload["breadcrumbs"][-1]["path"] == "/case-browser"
    directories = {item["name"]: item for item in payload["directories"]}
    files = {item["name"]: item for item in payload["files"]}
    assert directories["source"]["node_type"] == "directory"
    assert directories["data_flow"]["node_type"] == "directory"

    escaped = client.get(
        "/api/dataflow-vuln-scanner/project-filesystem/children",
        params={"project_id": "default", "path": "/../etc"},
    )
    assert escaped.status_code == 422


def test_service_config_is_redacted(service_config_path):
    from app.config import get_config

    config = get_config()
    config.database.password = "top-secret"
    config.auth_service.service_machine_token = "machine-secret"

    app = create_app()
    client = TestClient(app)

    response = client.get("/api/dataflow-vuln-scanner/service/config/effective")
    assert response.status_code == 200
    payload = response.json()["config"]
    assert payload["database"]["password"] == "***"
    assert payload["auth_service"]["service_machine_token"] == "***"


def test_service_runtime_config_roundtrip(service_config_path):
    app = create_app()
    client = TestClient(app)

    response = client.get("/api/dataflow-vuln-scanner/service/config")
    assert response.status_code == 200
    payload = response.json()
    assert set(payload["config"]["scheduler"].keys()) == {
        "enabled",
        "role",
        "worker_capacity",
        "poll_interval_seconds",
        "heartbeat_interval_seconds",
        "worker_timeout_seconds",
        "worker_retention_seconds",
        "cleanup_interval_seconds",
        "reservation_lease_seconds",
        "worker_queue_depth",
        "dispatch_batch_size",
        "requeue_stuck_dispatch_after_seconds",
        "cluster_capacity_summary_refresh_interval_seconds",
        "cluster_capacity_summary_stale_after_seconds",
    }
    assert set(payload["config"]["dataflow_worker"].keys()) == {
        "advertise_url_template",
        "timeout",
        "dispatch_retry_interval_seconds",
        "dispatch_max_retries",
    }

    save_response = client.put(
        "/api/dataflow-vuln-scanner/service/config",
        json={
            "config": {
                "scheduler": {
                    "worker_capacity": 3,
                    "reservation_lease_seconds": 45,
                },
                "dataflow_worker": {
                    "advertise_url_template": "http://{pod_id}.{headless_service_name}.{pod_namespace}.svc.cluster.local:8080",
                    "dispatch_retry_interval_seconds": 4,
                },
            }
        },
    )
    assert save_response.status_code == 200
    saved = save_response.json()
    assert saved["config"]["scheduler"]["worker_capacity"] == 3
    assert saved["config"]["dataflow_worker"]["advertise_url_template"] == "http://{pod_id}.{headless_service_name}.{pod_namespace}.svc.cluster.local:8080"


def test_service_runtime_config_drops_legacy_registry_incompatible_fields(service_config_path):
    from app.models.database import ServiceRuntimeConfig, get_db_session
    from app.services.runtime_config_service import SERVICE_RUNTIME_CONFIG_KEY

    db = get_db_session()
    try:
        db.merge(
            ServiceRuntimeConfig(
                config_key=SERVICE_RUNTIME_CONFIG_KEY,
                config_json={
                    "scheduler": {
                        "enabled": True,
                        "worker_capacity": 2,
                        "discovery_mode": "legacy-mixed",
                    },
                    "dataflow_worker": {
                        "timeout": 15,
                        "base_url": "http://legacy-worker",
                        "worker_urls": ["http://legacy-a", "http://legacy-b"],
                        "worker_url_template": "http://legacy-{pod_id}",
                    },
                },
            )
        )
        db.commit()
    finally:
        db.close()

    app = create_app()
    client = TestClient(app)
    response = client.get("/api/dataflow-vuln-scanner/service/config")
    assert response.status_code == 200
    payload = response.json()["config"]
    assert payload["scheduler"]["worker_capacity"] == 2
    assert "discovery_mode" not in payload["scheduler"]
    assert payload["dataflow_worker"]["timeout"] == 15
    assert "base_url" not in payload["dataflow_worker"]
    assert "worker_urls" not in payload["dataflow_worker"]
    assert "worker_url_template" not in payload["dataflow_worker"]
