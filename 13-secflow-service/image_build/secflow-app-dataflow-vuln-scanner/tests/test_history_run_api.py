from __future__ import annotations

import json
import signal
import time
from pathlib import Path

from fastapi.testclient import TestClient
import yaml

from app.config import get_config, reset_config
from app.main import create_app
from app.models.database import HistoryRun, TriggerTask, WorkflowExecution, WorkflowExecutionEvent, get_db_session
from app.services.execution_service import get_execution_service
from app.services.scheduler import get_scheduler_service


def _wait_for_task_status(client: TestClient, task_id: str, expected: set[str] | None = None, timeout: float = 10.0) -> dict:
    expected = expected or {"succeeded"}
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
        "max_concurrency": 1,
        "default_priority": 120,
        "max_retry_count": 2,
        "execution_timeout_seconds": 600,
    }


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, data: dict) -> None:
    _write(path, json.dumps(data, ensure_ascii=False))


def _create_legacy_run(run_root: Path) -> None:
    atomic = run_root / "workspace" / "pipeline_demo_run_001" / "stage_01_vuln_scan" / "vuln_scan_initial_001"
    _write_json(run_root / "config.json", {
        "global": {
            "max_review_cycles": 3,
            "parallel_result_review": True,
            "workspace_root": f"/home/mock/secflow/runs/{run_root.name}/workspace",
        },
        "agents": [{
            "id": "pi-worker",
            "runtime_config": {
                "model": "mock/model",
                "timeout_seconds": 1800,
                "sdk_specific": {"provider": "mock", "thinking": "high"},
            },
        }],
        "execution": {"execution_id": run_root.name, "input_task": {"task_file": "input/task.md"}},
    })
    _write(run_root / "input" / "task.md", "# Task\n")
    _write(run_root / "run.log", "line1\nline2\n")
    _write_json(run_root / "_meta" / "run_timestamps.json", {
        "started_at": "2026-04-28T01:02:03",
        "finished_at": "2026-04-28T01:12:03",
        "status": "completed",
    })
    _write_json(run_root / "workspace" / "pipeline_demo_run_001" / "_meta" / "pipeline_state.json", {"status": "completed"})
    _write_json(run_root / "workspace" / "pipeline_demo_run_001" / "stage_01_vuln_scan" / "_meta" / "stage_state.json", {"status": "completed"})
    _write_json(atomic / "_meta" / "state.json", {"current_state": "completed", "timestamp": "2026-04-28T01:12:03Z"})
    _write_json(atomic / "_meta" / "workflow_result.json", {"status": "completed", "timestamp": "2026-04-28T01:12:03Z", "detail": {"cycles_used": 1}})
    _write_json(atomic / "_meta" / "review_summaries" / "cycle_001.json", {
        "cycle": 1,
        "timestamp": "2026-04-28T01:12:03Z",
        "workflow_mode": "discovery",
        "global_review": {"passed": True, "advisor_results": []},
        "result_review": {"total": 1, "passed_count": 1, "failed_count": 0, "passed_files": ["result_001.md"], "failed_files": []},
        "outcome": "all_passed",
    })
    _write_json(atomic / "_meta" / "cycle_metrics" / "cycle_001.json", {
        "cycle": 1,
        "scores": {"input_coverage": 0.95},
        "global_failure_scope": "",
        "issue_count": 0,
        "issue_ids": [],
        "summary_size": 42,
        "historical_removed_result_count": 0,
    })
    _write_json(atomic / "_meta" / "result_relations_manifest.json", {
        "all_results": ["result_001.md"],
        "taskable_results": ["result_001.md"],
        "supplemental_results": [],
        "inactive_results": [],
        "relationships": [{
            "filename": "result_001.md",
            "role": "finding",
            "lifecycle_status": "candidate",
            "active": True,
            "taskable": True,
            "delivery_bucket": "results",
            "vulnerability_headings": ["VULN-001"],
        }],
    })
    _write_json(atomic / "_meta" / "results_manifest.json", {
        "total_result_files": 1,
        "active_result_count": 1,
        "inactive_result_count": 0,
        "taskable_result_count": 1,
        "supplemental_result_count": 0,
        "excluded_results": [],
        "entries": [{
            "filename": "result_001.md",
            "role": "finding",
            "lifecycle_status": "candidate",
            "active": True,
            "taskable": True,
            "delivery_bucket": "results",
            "vulnerability_headings": ["VULN-001"],
        }],
    })
    _write_json(atomic / "_meta" / "coverage_ledger.json", {
        "missing_referenced_results": [],
        "unreferenced_active_results": [],
    })
    _write(atomic / "summary.md", "# Summary\n")
    _write(atomic / "results" / "result_001.md", "# Confirmed issue\nbody")
    _write_json(atomic / "reviews" / "global" / "cycle_001" / "global_completeness.json", {
        "advisor_instance_id": "global_completeness",
        "role_name": "completeness",
        "cycle": 1,
        "passed": True,
        "verdict": "PASS",
        "scores": {"input_coverage": 0.95},
        "confidence": 0.9,
        "feedback": "ok",
        "schema_valid": True,
        "repair_attempts": 0,
    })
    _write_json(atomic / "reviews" / "results" / "result_001" / "cycle_001" / "result_fp_check.json", {
        "result_file": "result_001.md",
        "advisor_instance_id": "result_fp_check",
        "cycle": 1,
        "passed": True,
        "verdict": "CONFIRMED",
        "scores": {"issue_truth": 0.95},
        "confidence": 0.9,
        "feedback": "ok",
        "schema_valid": True,
        "repair_attempts": 0,
    })
    call = atomic / "sessions" / "worker" / "calls" / "001_abcd"
    _write_json(call / "request.json", {"turn_number": 1, "agent_id": "pi-worker", "user_prompt_len": 9, "sys_prompt_len": 0})
    _write_json(call / "response.json", {"status": "completed", "duration_ms": 1000, "output_len": 12})
    _write(call / "user_prompt.md", "prompt")
    _write(call / "stdout.txt", "stdout")


class _FakeCliProcess:
    def __init__(self, pid: int = 4242):
        self.pid = pid
        self.returncode = None
        self.signals: list[int] = []
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def send_signal(self, sig):
        self.signals.append(sig)

    def wait(self, timeout=None):
        self.returncode = 130
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = self.returncode if self.returncode is not None else 143

    def kill(self):
        self.killed = True
        self.returncode = self.returncode if self.returncode is not None else 137


def test_history_runs_api_lists_legacy_and_execution_runs_and_resolves_legacy_links(service_config_path, patch_mock_agent_runtime):
    config = get_config()
    project_root = Path(config.fileserver_service.data_mount_path) / "files" / "default"
    legacy_run = project_root / "dataflow-vuln-scanner" / "runs" / "legacy_target_20260428_010203"
    _create_legacy_run(legacy_run)

    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()
    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile["profile_id"],
            "title": "scan demo package",
            "task_markdown": "# Package List\n\n- demo.tar.gz\n",
            "artifact_refs": [],
            "runtime_overrides": {},
        },
    )
    assert task.status_code == 201
    task_id = task.json()["task_id"]
    task_detail = _wait_for_task_status(client, task_id)
    execution_id = task_detail["attempts"][0]["execution_id"]

    history_runs = client.get("/api/dataflow-vuln-scanner/history-runs", params={"project_id": "default"})
    assert history_runs.status_code == 200
    items = history_runs.json()
    names = {item["name"] for item in items}
    assert legacy_run.name in names
    assert execution_id in names

    legacy_summary = next(item for item in items if item["name"] == legacy_run.name)
    assert legacy_summary["source_type"] == "legacy_runs_root"

    resolve = client.get(
        "/api/dataflow-vuln-scanner/history-runs/resolve",
        params={"project_id": "default", "run_name": legacy_run.name, "root_path": "/dataflow-vuln-scanner/runs"},
    )
    assert resolve.status_code == 200
    assert resolve.json()["history_run_id"] == legacy_summary["history_run_id"]

    task_resolve = client.get(
        "/api/dataflow-vuln-scanner/history-runs/by-task",
        params={"project_id": "default", "task_id": task_id, "execution_id": execution_id},
    )
    assert task_resolve.status_code == 200
    assert task_resolve.json()["linked_task_id"] == task_id
    assert task_resolve.json()["linked_execution_id"] == execution_id
    task_history_detail = client.get(f"/api/dataflow-vuln-scanner/history-runs/{task_resolve.json()['history_run_id']}")
    assert task_history_detail.status_code == 200
    assert task_history_detail.json()["linked_execution_id"] == execution_id

    legacy_detail = client.get(f"/api/dataflow-vuln-scanner/history-runs/{legacy_summary['history_run_id']}")
    assert legacy_detail.status_code == 200
    assert legacy_detail.json()["atomic_work_path"].endswith("vuln_scan_initial_001")
    assert legacy_detail.json()["cycles"]
    assert any(item["path"] == "results/result_001.md" for item in legacy_detail.json()["files"])

    file_payload = client.get(
        f"/api/dataflow-vuln-scanner/history-runs/{legacy_summary['history_run_id']}/file",
        params={"path": "results/result_001.md"},
    )
    assert file_payload.status_code == 200
    assert file_payload.json()["type"] == "markdown"
    assert "Confirmed issue" in file_payload.json()["content"]

    path_escape = client.get(
        f"/api/dataflow-vuln-scanner/history-runs/{legacy_summary['history_run_id']}/file",
        params={"path": "../outside.txt"},
    )
    assert path_escape.status_code == 404


def test_history_run_refreshes_after_legacy_directory_changes(service_config_path):
    config = get_config()
    project_root = Path(config.fileserver_service.data_mount_path) / "files" / "default"
    legacy_run = project_root / "DATAFLOW_VULN_SCANNER" / "runs" / "legacy_target_20260429_010203"
    _create_legacy_run(legacy_run)

    app = create_app()
    client = TestClient(app)
    list_response = client.get("/api/dataflow-vuln-scanner/history-runs", params={"project_id": "default"})
    assert list_response.status_code == 200
    history_run_id = next(item["history_run_id"] for item in list_response.json() if item["name"] == legacy_run.name)

    detail_before = client.get(f"/api/dataflow-vuln-scanner/history-runs/{history_run_id}")
    assert detail_before.status_code == 200
    assert not any(item["path"] == "supporting_docs/new_note.md" for item in detail_before.json()["files"])

    atomic = legacy_run / "workspace" / "pipeline_demo_run_001" / "stage_01_vuln_scan" / "vuln_scan_initial_001"
    _write(atomic / "supporting_docs" / "new_note.md", "# New note\n")

    detail_after = client.get(f"/api/dataflow-vuln-scanner/history-runs/{history_run_id}")
    assert detail_after.status_code == 200
    assert any(item["path"] == "supporting_docs/new_note.md" for item in detail_after.json()["files"])


def test_history_run_reparses_when_atomic_work_path_was_stale(service_config_path):
    config = get_config()
    project_root = Path(config.fileserver_service.data_mount_path) / "files" / "default"
    legacy_run = project_root / "dataflow-vuln-scanner" / "runs" / "legacy_atomic_refresh_20260429_020304"
    _create_legacy_run(legacy_run)

    app = create_app()
    client = TestClient(app)
    list_response = client.get("/api/dataflow-vuln-scanner/history-runs", params={"project_id": "default"})
    assert list_response.status_code == 200
    history_run_id = next(item["history_run_id"] for item in list_response.json() if item["name"] == legacy_run.name)

    db = get_db_session()
    try:
        row = db.get(HistoryRun, history_run_id)
        assert row is not None
        row.atomic_work_path = ""
        row.cycles_used = 0
        row.result_count = 0
        row.manifests_json = {}
        db.add(row)
        db.commit()
    finally:
        db.close()

    detail = client.get(f"/api/dataflow-vuln-scanner/history-runs/{history_run_id}")
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["atomic_work_path"].endswith("vuln_scan_initial_001")
    assert payload["cycles"]
    assert payload["results"]


def test_history_runs_list_does_not_re_refresh_synced_rows(service_config_path, monkeypatch):
    from app.services import history_run_service as history_run_service_module

    config = get_config()
    project_root = Path(config.fileserver_service.data_mount_path) / "files" / "default"
    legacy_run = project_root / "dataflow-vuln-scanner" / "runs" / "legacy_no_double_refresh_20260507_010203"
    _create_legacy_run(legacy_run)

    app = create_app()
    client = TestClient(app)

    first_list = client.get("/api/dataflow-vuln-scanner/history-runs", params={"project_id": "default"})
    assert first_list.status_code == 200
    assert any(item["name"] == legacy_run.name for item in first_list.json())

    def fail_refresh(*args, **kwargs):
        raise AssertionError("list_history_runs should not refresh already synced rows")

    monkeypatch.setattr(history_run_service_module.HistoryRunService, "refresh_history_run", fail_refresh)

    second_list = client.get("/api/dataflow-vuln-scanner/history-runs", params={"project_id": "default"})
    assert second_list.status_code == 200
    assert any(item["name"] == legacy_run.name for item in second_list.json())


def test_history_runs_ignore_stale_fixed_project_override_and_use_requested_project(service_config_path):
    stale_fixed_project_id = "stale-fixed-project-id"
    config_payload = yaml.safe_load(service_config_path.read_text(encoding="utf-8")) or {}
    config_payload["history_runs"] = {
        "enabled": True,
        "fixed_project_id": stale_fixed_project_id,
        "legacy_root_candidates": [
            "{data_mount_path}/{project_files_dirname}/{project_id}/dataflow-vuln-scanner/runs",
            "{data_mount_path}/{project_files_dirname}/{project_id}/DATAFLOW_VULN_SCANNER/runs",
        ],
    }
    service_config_path.write_text(yaml.safe_dump(config_payload, allow_unicode=True), encoding="utf-8")
    reset_config()

    config = get_config()
    requested_project_root = Path(config.fileserver_service.data_mount_path) / "files" / "default"
    legacy_run = requested_project_root / "dataflow-vuln-scanner" / "runs" / "legacy_fixed_project_20260506_010203"
    _create_legacy_run(legacy_run)
    stale_project_root = Path(config.fileserver_service.data_mount_path) / "files" / stale_fixed_project_id
    _create_legacy_run(stale_project_root / "dataflow-vuln-scanner" / "runs" / "legacy_should_be_ignored_20260506_010204")

    app = create_app()
    client = TestClient(app)
    history_runs = client.get("/api/dataflow-vuln-scanner/history-runs", params={"project_id": "default"})
    assert history_runs.status_code == 200
    items = history_runs.json()
    summary = next(item for item in items if item["name"] == legacy_run.name)
    assert "/files/default/" in summary["path"]
    assert not any(item["name"] == "legacy_should_be_ignored_20260506_010204" for item in items)

    resolve = client.get(
        "/api/dataflow-vuln-scanner/history-runs/resolve",
        params={"project_id": "default", "run_name": legacy_run.name, "root_path": "/dataflow-vuln-scanner/runs"},
    )
    assert resolve.status_code == 200
    assert resolve.json()["history_run_id"] == summary["history_run_id"]


def test_history_runs_rebind_existing_legacy_index_to_requested_project(service_config_path):
    config = get_config()
    project_root = Path(config.fileserver_service.data_mount_path) / "files" / "default"
    legacy_run = project_root / "dataflow-vuln-scanner" / "runs" / "legacy_rebind_project_20260506_020304"
    _create_legacy_run(legacy_run)

    app = create_app()
    client = TestClient(app)

    first_list = client.get("/api/dataflow-vuln-scanner/history-runs", params={"project_id": "default"})
    assert first_list.status_code == 200
    summary = next(item for item in first_list.json() if item["name"] == legacy_run.name)

    db = get_db_session()
    try:
        row = db.get(HistoryRun, summary["history_run_id"])
        assert row is not None
        row.project_id = "stale-project"
        db.add(row)
        db.commit()
    finally:
        db.close()

    rebound_list = client.get("/api/dataflow-vuln-scanner/history-runs", params={"project_id": "default"})
    assert rebound_list.status_code == 200
    rebound_summary = next(item for item in rebound_list.json() if item["name"] == legacy_run.name)
    assert rebound_summary["project_id"] == "default"


def test_history_run_retry_queue_cancel_and_delete(service_config_path, monkeypatch):
    config = get_config()
    project_root = Path(config.fileserver_service.data_mount_path) / "files" / "default"
    legacy_run = project_root / "dataflow-vuln-scanner" / "runs" / "legacy_resume_delete_20260507_101500"
    _create_legacy_run(legacy_run)

    app = create_app()
    client = TestClient(app)
    monkeypatch.setattr(get_scheduler_service(), "start_execution_now", lambda execution_id: False)

    list_response = client.get("/api/dataflow-vuln-scanner/history-runs", params={"project_id": "default"})
    assert list_response.status_code == 200
    history_run_id = next(item["history_run_id"] for item in list_response.json() if item["name"] == legacy_run.name)

    completed_retry_response = client.post(
        f"/api/dataflow-vuln-scanner/history-runs/{history_run_id}/retry",
        json={"extra_cycles": 2},
    )
    assert completed_retry_response.status_code == 409
    assert "must be cancelled" in completed_retry_response.json()["detail"]

    db = get_db_session()
    try:
        history_run = db.get(HistoryRun, history_run_id)
        assert history_run is not None
        history_run.status = "cancelled"
        db.add(history_run)
        db.commit()
    finally:
        db.close()

    retry_response = client.post(
        f"/api/dataflow-vuln-scanner/history-runs/{history_run_id}/retry",
        json={"extra_cycles": 2},
    )
    assert retry_response.status_code == 202
    retry_payload = retry_response.json()
    assert retry_payload["status"] == "queued"
    assert retry_payload["linked_task_id"]
    assert retry_payload["linked_execution_id"]

    detail_queued = client.get(f"/api/dataflow-vuln-scanner/history-runs/{history_run_id}")
    assert detail_queued.status_code == 200
    assert detail_queued.json()["status"] == "queued"

    cancel_response = client.post(f"/api/dataflow-vuln-scanner/history-runs/{history_run_id}/cancel")
    assert cancel_response.status_code == 200
    assert cancel_response.json()["status"] == "cancelled"

    delete_response = client.delete(f"/api/dataflow-vuln-scanner/history-runs/{history_run_id}")
    assert delete_response.status_code == 200
    assert delete_response.json()["status"] == "deleted"
    assert not legacy_run.exists()

    missing_detail = client.get(f"/api/dataflow-vuln-scanner/history-runs/{history_run_id}")
    assert missing_detail.status_code == 404


def test_history_run_adopt_links_legacy_run_without_queueing(service_config_path):
    config = get_config()
    project_root = Path(config.fileserver_service.data_mount_path) / "files" / "default"
    legacy_run = project_root / "dataflow-vuln-scanner" / "runs" / "legacy_adopt_20260507_111500"
    _create_legacy_run(legacy_run)

    app = create_app()
    client = TestClient(app)

    list_response = client.get("/api/dataflow-vuln-scanner/history-runs", params={"project_id": "default"})
    assert list_response.status_code == 200
    summary = next(item for item in list_response.json() if item["name"] == legacy_run.name)
    assert summary["linked_task_id"] is None
    assert summary["linked_execution_id"] is None

    adopt_response = client.post(f"/api/dataflow-vuln-scanner/history-runs/{summary['history_run_id']}/adopt")
    assert adopt_response.status_code == 200
    adopt_payload = adopt_response.json()
    assert adopt_payload["history_run_id"] == summary["history_run_id"]
    assert adopt_payload["status"] == "completed"
    assert adopt_payload["linked_task_id"]
    assert adopt_payload["linked_execution_id"]

    detail = client.get(f"/api/dataflow-vuln-scanner/history-runs/{summary['history_run_id']}")
    assert detail.status_code == 200
    assert detail.json()["linked_task_id"] == adopt_payload["linked_task_id"]
    assert detail.json()["linked_execution_id"] == adopt_payload["linked_execution_id"]


def test_history_run_cancel_active_run_signals_bound_process(service_config_path):
    config = get_config()
    project_root = Path(config.fileserver_service.data_mount_path) / "files" / "default"
    legacy_run = project_root / "dataflow-vuln-scanner" / "runs" / "legacy_cancel_active_20260507_121500"
    _create_legacy_run(legacy_run)

    app = create_app()
    client = TestClient(app)
    summary = next(
        item
        for item in client.get("/api/dataflow-vuln-scanner/history-runs", params={"project_id": "default"}).json()
        if item["name"] == legacy_run.name
    )
    adopt_payload = client.post(f"/api/dataflow-vuln-scanner/history-runs/{summary['history_run_id']}/adopt").json()
    execution_id = adopt_payload["linked_execution_id"]

    db = get_db_session()
    try:
        history_run = db.get(HistoryRun, summary["history_run_id"])
        execution = db.get(WorkflowExecution, execution_id)
        trigger = db.get(TriggerTask, adopt_payload["linked_task_id"])
        assert history_run is not None and execution is not None and trigger is not None
        history_run.status = "running"
        execution.status = "running"
        execution.process_pid = 4242
        execution.process_status = "running"
        trigger.status = "running"
        db.add_all([history_run, execution, trigger])
        db.commit()
    finally:
        db.close()

    fake_process = _FakeCliProcess()
    get_execution_service()._register_cli_process(execution_id, fake_process)

    cancel_response = client.post(f"/api/dataflow-vuln-scanner/history-runs/{summary['history_run_id']}/cancel")
    assert cancel_response.status_code == 200
    cancel_payload = cancel_response.json()
    assert cancel_payload["status"] == "cancel_requested"
    assert cancel_payload["process_pid"] == 4242
    assert cancel_payload["process_signal"] == "sigint"
    assert fake_process.signals
    assert fake_process.signals[-1] == signal.SIGINT

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        history_run = db.get(HistoryRun, summary["history_run_id"])
        assert execution is not None and execution.status == "cancel_requested"
        assert history_run is not None and history_run.status == "cancel_requested"
    finally:
        db.close()


def test_history_run_delete_active_run_stops_process_and_removes_records(service_config_path, monkeypatch):
    config = get_config()
    project_root = Path(config.fileserver_service.data_mount_path) / "files" / "default"
    legacy_run = project_root / "dataflow-vuln-scanner" / "runs" / "legacy_delete_active_20260507_121501"
    _create_legacy_run(legacy_run)

    app = create_app()
    client = TestClient(app)
    summary = next(
        item
        for item in client.get("/api/dataflow-vuln-scanner/history-runs", params={"project_id": "default"}).json()
        if item["name"] == legacy_run.name
    )
    adopt_payload = client.post(f"/api/dataflow-vuln-scanner/history-runs/{summary['history_run_id']}/adopt").json()
    history_run_id = summary["history_run_id"]
    task_id = adopt_payload["linked_task_id"]
    execution_id = adopt_payload["linked_execution_id"]

    db = get_db_session()
    try:
        history_run = db.get(HistoryRun, history_run_id)
        execution = db.get(WorkflowExecution, execution_id)
        trigger = db.get(TriggerTask, task_id)
        assert history_run is not None and execution is not None and trigger is not None
        history_run.status = "running"
        execution.status = "running"
        execution.process_pid = 4242
        execution.process_status = "running"
        trigger.status = "running"
        db.add_all([history_run, execution, trigger])
        db.add(WorkflowExecutionEvent(
            id="evt-active-delete",
            execution_id=execution_id,
            event_type="run_vuln_scan_process_started",
            message="started",
            payload_json={"pid": 4242},
        ))
        db.commit()
    finally:
        db.close()

    service = get_execution_service()
    fake_process = _FakeCliProcess()
    service._register_cli_process(execution_id, fake_process)
    monkeypatch.setattr(type(service), "_wait_until_execution_inactive", lambda self, db, execution_id, timeout_seconds: True)

    delete_response = client.delete(f"/api/dataflow-vuln-scanner/history-runs/{history_run_id}")
    assert delete_response.status_code == 200
    delete_payload = delete_response.json()
    assert delete_payload["status"] == "deleted"
    assert delete_payload["process_pid"] == 4242
    assert delete_payload["process_signal"] == "sigint"
    assert fake_process.signals
    assert fake_process.signals[-1] == signal.SIGINT
    assert not legacy_run.exists()

    db = get_db_session()
    try:
        assert db.get(HistoryRun, history_run_id) is None
        assert db.get(TriggerTask, task_id) is None
        assert db.get(WorkflowExecution, execution_id) is None
        assert db.query(WorkflowExecutionEvent).filter(WorkflowExecutionEvent.execution_id == execution_id).count() == 0
    finally:
        db.close()


def test_history_run_retry_execution_uses_resume_cli_argv(service_config_path, monkeypatch):
    config = get_config()
    project_root = Path(config.fileserver_service.data_mount_path) / "files" / "default"
    legacy_run = project_root / "dataflow-vuln-scanner" / "runs" / "legacy_resume_cli_20260507_101501"
    _create_legacy_run(legacy_run)

    app = create_app()
    client = TestClient(app)

    list_response = client.get("/api/dataflow-vuln-scanner/history-runs", params={"project_id": "default"})
    assert list_response.status_code == 200
    history_run_id = next(item["history_run_id"] for item in list_response.json() if item["name"] == legacy_run.name)

    db = get_db_session()
    try:
        history_run = db.get(HistoryRun, history_run_id)
        assert history_run is not None
        history_run.status = "cancelled"
        db.add(history_run)
        db.commit()
    finally:
        db.close()

    captured: dict[str, list[str]] = {}

    def fake_invoke(self, *, argv, db, execution, trigger):
        captured["argv"] = list(argv)
        return 0

    monkeypatch.setattr(type(get_execution_service()), "_invoke_run_vuln_scan_cli", fake_invoke)

    retry_response = client.post(
        f"/api/dataflow-vuln-scanner/history-runs/{history_run_id}/retry",
        json={"extra_cycles": 2, "model": "mock/override", "thinking": "low"},
    )
    assert retry_response.status_code == 202
    execution_id = retry_response.json()["linked_execution_id"]

    deadline = time.time() + 5
    while "argv" not in captured and time.time() < deadline:
        time.sleep(0.05)
    assert "argv" in captured

    assert captured["argv"][:4] == ["--resume-run-dir", str(legacy_run), "--extra-cycles", "2"]
    assert "--model" in captured["argv"]
    assert "mock/override" in captured["argv"]
    assert "--thinking" not in captured["argv"]


def test_history_run_status_prefers_active_run_meta_over_stale_terminal_state(service_config_path):
    config = get_config()
    project_root = Path(config.fileserver_service.data_mount_path) / "files" / "default"
    legacy_run = project_root / "dataflow-vuln-scanner" / "runs" / "legacy_running_meta_20260507_101502"
    _create_legacy_run(legacy_run)
    _write_json(legacy_run / "_meta" / "run_timestamps.json", {
        "started_at": "2026-05-07T10:15:02",
        "status": "running",
    })

    app = create_app()
    client = TestClient(app)

    list_response = client.get("/api/dataflow-vuln-scanner/history-runs", params={"project_id": "default"})
    assert list_response.status_code == 200
    summary = next(item for item in list_response.json() if item["name"] == legacy_run.name)
    assert summary["status"] == "running"

    detail = client.get(f"/api/dataflow-vuln-scanner/history-runs/{summary['history_run_id']}")
    assert detail.status_code == 200
    assert detail.json()["status"] == "running"
