from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
import yaml

from app.config import get_config, reset_config
from app.main import create_app
from app.models.database import HistoryRun, get_db_session
from app.services.execution_service import get_execution_service
from app.services.scheduler import SchedulerService


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
    execution_id = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/attempts").json()[0]["execution_id"]
    assert SchedulerService()._claim_next_execution() == execution_id
    get_execution_service().run_claimed_execution(execution_id)

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

    task_runs = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/runs")
    assert task_runs.status_code == 200
    assert task_runs.json()[0]["history_run_id"]

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


def test_history_runs_can_pin_legacy_project_root(service_config_path):
    config_payload = yaml.safe_load(service_config_path.read_text(encoding="utf-8")) or {}
    config_payload["history_runs"] = {
        "enabled": True,
        "fixed_project_id": "44f9029d00650a10",
        "legacy_root_candidates": [
            "{data_mount_path}/{project_files_dirname}/{project_id}/dataflow-vuln-scanner/runs",
            "{data_mount_path}/{project_files_dirname}/{project_id}/DATAFLOW_VULN_SCANNER/runs",
        ],
    }
    service_config_path.write_text(yaml.safe_dump(config_payload, allow_unicode=True), encoding="utf-8")
    reset_config()

    config = get_config()
    fixed_project_id = str(config.history_runs.fixed_project_id)
    project_root = Path(config.fileserver_service.data_mount_path) / "files" / fixed_project_id
    legacy_run = project_root / "dataflow-vuln-scanner" / "runs" / "legacy_fixed_project_20260506_010203"
    _create_legacy_run(legacy_run)

    app = create_app()
    client = TestClient(app)
    history_runs = client.get("/api/dataflow-vuln-scanner/history-runs", params={"project_id": "default"})
    assert history_runs.status_code == 200
    items = history_runs.json()
    summary = next(item for item in items if item["name"] == legacy_run.name)
    assert fixed_project_id in summary["path"]

    resolve = client.get(
        "/api/dataflow-vuln-scanner/history-runs/resolve",
        params={"project_id": "default", "run_name": legacy_run.name, "root_path": "/dataflow-vuln-scanner/runs"},
    )
    assert resolve.status_code == 200
    assert resolve.json()["history_run_id"] == summary["history_run_id"]


def test_history_runs_rebind_existing_legacy_index_to_requested_project(service_config_path):
    config_payload = yaml.safe_load(service_config_path.read_text(encoding="utf-8")) or {}
    config_payload["history_runs"] = {
        "enabled": True,
        "fixed_project_id": "44f9029d00650a10",
        "legacy_root_candidates": [
            "{data_mount_path}/{project_files_dirname}/{project_id}/dataflow-vuln-scanner/runs",
            "{data_mount_path}/{project_files_dirname}/{project_id}/DATAFLOW_VULN_SCANNER/runs",
        ],
    }
    service_config_path.write_text(yaml.safe_dump(config_payload, allow_unicode=True), encoding="utf-8")
    reset_config()

    config = get_config()
    fixed_project_id = str(config.history_runs.fixed_project_id)
    project_root = Path(config.fileserver_service.data_mount_path) / "files" / fixed_project_id
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
