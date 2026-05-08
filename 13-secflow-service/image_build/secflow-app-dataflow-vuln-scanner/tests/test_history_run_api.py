from __future__ import annotations

import json
import signal
import time
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import get_config
from app.main import create_app
from app.models.database import (
    HistoryRun,
    TriggerTask,
    WorkflowDefinitionVersion,
    WorkflowExecution,
    WorkflowExecutionEvent,
    get_db_session,
)
from app.services.execution_service import get_execution_service
from app.services.history_run_service import get_history_run_service
from app.services.scheduler import get_scheduler_service


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _profile_payload(name: str | None = None) -> dict:
    return {
        "project_id": "default",
        "name": name or f"default scanner {_new_id('profile')}",
        "description": "scanner profile",
        "template_kind": "vuln_scan_default",
        "config_payload": {
            "model": "mock/model",
            "review_profile": "balanced",
            "max_review_cycles": 2,
            "worker_timeout": 60,
            "advisor_timeout": 60,
            "result_review_concurrency": 2,
            "runtime_overrides": {},
        },
        "is_default": False,
        "enabled": True,
        "default_priority": 120,
        "max_retry_count": 2,
        "execution_timeout_seconds": 600,
    }


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, data: dict) -> None:
    _write(path, json.dumps(data, ensure_ascii=False))


def _create_run_workspace(run_root: Path) -> None:
    atomic = run_root / "workspace" / "pipeline_demo_run_001" / "stage_01_vuln_scan" / "vuln_scan_initial_001"
    _write_json(run_root / "config.json", {
        "global": {
            "max_review_cycles": 3,
            "parallel_result_review": True,
            "workspace_root": str(run_root / "workspace"),
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


def _create_execution_bound_run(client: TestClient, run_root: Path, *, title: str = "scan demo package") -> dict:
    _create_run_workspace(run_root)
    profile_response = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload())
    assert profile_response.status_code == 201
    profile = profile_response.json()

    with get_db_session() as db:
        definition_version = (
            db.query(WorkflowDefinitionVersion)
            .filter(WorkflowDefinitionVersion.workflow_definition_id == profile["profile_id"])
            .order_by(WorkflowDefinitionVersion.version_no.desc())
            .first()
        )
        assert definition_version is not None
        trigger = TriggerTask(
            id=_new_id("tt"),
            workflow_definition_id=profile["profile_id"],
            workflow_definition_version_id=definition_version.id,
            profile_id=profile["profile_id"],
            project_id="default",
            trigger_type="manual",
            input_tasks_json={
                "tasks": [{
                    "task_id": _new_id("task"),
                    "task_type": "dataflow_vuln_scan_cli",
                    "title": title,
                    "task_md_path": str(run_root / "input" / "task.md"),
                    "metadata": {"task_title": title},
                    "upstream_refs": [],
                }]
            },
            priority=120,
            status="succeeded",
            submitted_by="tester",
            retry_count=0,
            max_retry_count=2,
            message="completed",
        )
        db.add(trigger)
        db.flush()
        execution = WorkflowExecution(
            id=_new_id("exec"),
            trigger_task_id=trigger.id,
            workflow_definition_id=profile["profile_id"],
            workflow_definition_version_id=definition_version.id,
            project_id="default",
            attempt_no=1,
            status="succeeded",
            workspace_root=str(run_root.resolve()),
            output_manifest_path=str(run_root / "workspace" / "pipeline_demo_run_001" / "stage_01_vuln_scan" / "vuln_scan_initial_001" / "_meta" / "results_manifest.json"),
            output_task_count=1,
            message="completed",
        )
        db.add(execution)
        db.flush()
        trigger.latest_execution_id = execution.id
        db.add(trigger)
        history_run = get_history_run_service().sync_execution_run(db, execution)
        assert history_run is not None
        db.commit()
        return {
            "profile_id": profile["profile_id"],
            "task_id": trigger.id,
            "execution_id": execution.id,
            "history_run_id": history_run.id,
            "run_root": str(run_root.resolve()),
            "run_name": run_root.name,
        }


def _project_runs_root() -> Path:
    config = get_config()
    return (
        Path(config.fileserver_service.data_mount_path)
        / "files"
        / "default"
        / config.fileserver_service.dataflow_subproject_name
        / "runs"
    )


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


def test_history_runs_list_uses_execution_bound_runs_and_ignores_unbound_directories(service_config_path):
    runs_root = _project_runs_root()
    unbound_run = runs_root / "unbound_run_20260508_010203"
    _create_run_workspace(unbound_run)

    app = create_app()
    client = TestClient(app)
    bound_run = runs_root / "bound_run_20260508_010204"
    bound = _create_execution_bound_run(client, bound_run, title="DB bound scan")

    history_runs = client.get("/api/dataflow-vuln-scanner/history-runs", params={"project_id": "default"})
    assert history_runs.status_code == 200
    items = history_runs.json()
    names = {item["name"] for item in items}
    assert bound_run.name in names
    assert unbound_run.name not in names

    summary = next(item for item in items if item["name"] == bound_run.name)
    assert summary["source_type"] == "execution_workspace"
    assert summary["linked_task_id"] == bound["task_id"]
    assert summary["linked_execution_id"] == bound["execution_id"]

    tasks = client.get("/api/dataflow-vuln-scanner/tasks", params={"project_id": "default"})
    assert tasks.status_code == 200
    task_summary = next(item for item in tasks.json() if item["task_id"] == bound["task_id"])
    assert task_summary["title"] == "DB bound scan"
    assert task_summary["latest_run"]["history_run_id"] == summary["history_run_id"]


def test_history_run_resolve_only_returns_execution_bound_records(service_config_path):
    runs_root = _project_runs_root()
    unbound_run = runs_root / "unbound_resolve_20260508_010203"
    _create_run_workspace(unbound_run)

    app = create_app()
    client = TestClient(app)
    bound_run = runs_root / "bound_resolve_20260508_010204"
    bound = _create_execution_bound_run(client, bound_run)

    resolve_bound = client.get(
        "/api/dataflow-vuln-scanner/history-runs/resolve",
        params={"project_id": "default", "run_name": bound_run.name, "root_path": str(bound_run.parent)},
    )
    assert resolve_bound.status_code == 200
    assert resolve_bound.json()["history_run_id"] == bound["history_run_id"]

    resolve_unbound = client.get(
        "/api/dataflow-vuln-scanner/history-runs/resolve",
        params={"project_id": "default", "run_name": unbound_run.name, "root_path": str(unbound_run.parent)},
    )
    assert resolve_unbound.status_code == 404


def test_history_run_refreshes_after_execution_directory_changes(service_config_path):
    app = create_app()
    client = TestClient(app)
    bound_run = _project_runs_root() / "bound_refresh_20260508_010203"
    bound = _create_execution_bound_run(client, bound_run)

    detail_before = client.get(f"/api/dataflow-vuln-scanner/history-runs/{bound['history_run_id']}")
    assert detail_before.status_code == 200
    assert not any(item["path"] == "supporting_docs/new_note.md" for item in detail_before.json()["files"])

    time.sleep(0.02)
    atomic = bound_run / "workspace" / "pipeline_demo_run_001" / "stage_01_vuln_scan" / "vuln_scan_initial_001"
    _write(atomic / "supporting_docs" / "new_note.md", "# New note\n")

    detail_after = client.get(f"/api/dataflow-vuln-scanner/history-runs/{bound['history_run_id']}")
    assert detail_after.status_code == 200
    assert any(item["path"] == "supporting_docs/new_note.md" for item in detail_after.json()["files"])


def test_history_run_reparses_when_atomic_work_path_was_stale(service_config_path):
    app = create_app()
    client = TestClient(app)
    bound = _create_execution_bound_run(client, _project_runs_root() / "bound_atomic_refresh_20260508_010203")

    with get_db_session() as db:
        row = db.get(HistoryRun, bound["history_run_id"])
        assert row is not None
        row.atomic_work_path = ""
        row.cycles_used = 0
        row.result_count = 0
        row.manifests_json = {}
        db.add(row)
        db.commit()

    detail = client.get(f"/api/dataflow-vuln-scanner/history-runs/{bound['history_run_id']}")
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["atomic_work_path"].endswith("vuln_scan_initial_001")
    assert payload["cycles"]
    assert payload["results"]


def test_history_run_retry_queue_cancel_and_delete(service_config_path, monkeypatch):
    app = create_app()
    client = TestClient(app)
    monkeypatch.setattr(get_scheduler_service(), "start_execution_now", lambda execution_id: False)
    run_root = _project_runs_root() / "bound_resume_delete_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)

    completed_retry_response = client.post(
        f"/api/dataflow-vuln-scanner/history-runs/{bound['history_run_id']}/retry",
        json={"extra_cycles": 2},
    )
    assert completed_retry_response.status_code == 409
    assert "not retryable" in completed_retry_response.json()["detail"]

    with get_db_session() as db:
        history_run = db.get(HistoryRun, bound["history_run_id"])
        assert history_run is not None
        history_run.status = "failed"
        db.add(history_run)
        db.commit()

    retry_response = client.post(
        f"/api/dataflow-vuln-scanner/history-runs/{bound['history_run_id']}/retry",
        json={"extra_cycles": 2},
    )
    assert retry_response.status_code == 202
    retry_payload = retry_response.json()
    assert retry_payload["status"] == "queued"
    assert retry_payload["linked_task_id"]
    assert retry_payload["linked_execution_id"]

    detail_queued = client.get(f"/api/dataflow-vuln-scanner/history-runs/{bound['history_run_id']}")
    assert detail_queued.status_code == 200
    assert detail_queued.json()["status"] == "queued"

    cancel_response = client.post(f"/api/dataflow-vuln-scanner/history-runs/{bound['history_run_id']}/cancel")
    assert cancel_response.status_code == 200
    assert cancel_response.json()["status"] == "cancelled"

    delete_response = client.delete(f"/api/dataflow-vuln-scanner/history-runs/{bound['history_run_id']}")
    assert delete_response.status_code == 200
    assert delete_response.json()["status"] == "deleted"
    assert not run_root.exists()

    missing_detail = client.get(f"/api/dataflow-vuln-scanner/history-runs/{bound['history_run_id']}")
    assert missing_detail.status_code == 404


def test_history_run_cancel_active_run_signals_bound_process(service_config_path):
    app = create_app()
    client = TestClient(app)
    bound = _create_execution_bound_run(client, _project_runs_root() / "bound_cancel_active_20260508_010203")

    with get_db_session() as db:
        history_run = db.get(HistoryRun, bound["history_run_id"])
        execution = db.get(WorkflowExecution, bound["execution_id"])
        trigger = db.get(TriggerTask, bound["task_id"])
        assert history_run is not None and execution is not None and trigger is not None
        history_run.status = "running"
        execution.status = "running"
        execution.process_pid = 4242
        execution.process_status = "running"
        trigger.status = "running"
        db.add_all([history_run, execution, trigger])
        db.commit()

    fake_process = _FakeCliProcess()
    get_execution_service()._register_cli_process(bound["execution_id"], fake_process)

    cancel_response = client.post(f"/api/dataflow-vuln-scanner/history-runs/{bound['history_run_id']}/cancel")
    assert cancel_response.status_code == 200
    cancel_payload = cancel_response.json()
    assert cancel_payload["status"] == "cancel_requested"
    assert cancel_payload["process_pid"] == 4242
    assert cancel_payload["process_signal"] == "sigint"
    assert fake_process.signals
    assert fake_process.signals[-1] == signal.SIGINT

    with get_db_session() as db:
        execution = db.get(WorkflowExecution, bound["execution_id"])
        history_run = db.get(HistoryRun, bound["history_run_id"])
        assert execution is not None and execution.status == "cancel_requested"
        assert history_run is not None and history_run.status == "cancel_requested"


def test_history_run_delete_active_run_stops_process_and_removes_records(service_config_path, monkeypatch):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_delete_active_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)

    with get_db_session() as db:
        history_run = db.get(HistoryRun, bound["history_run_id"])
        execution = db.get(WorkflowExecution, bound["execution_id"])
        trigger = db.get(TriggerTask, bound["task_id"])
        assert history_run is not None and execution is not None and trigger is not None
        history_run.status = "running"
        execution.status = "running"
        execution.process_pid = 4242
        execution.process_status = "running"
        trigger.status = "running"
        db.add_all([history_run, execution, trigger])
        db.add(WorkflowExecutionEvent(
            id="evt-active-delete",
            execution_id=bound["execution_id"],
            event_type="run_vuln_scan_process_started",
            message="started",
            payload_json={"pid": 4242},
        ))
        db.commit()

    service = get_execution_service()
    fake_process = _FakeCliProcess()
    service._register_cli_process(bound["execution_id"], fake_process)
    monkeypatch.setattr(type(service), "_wait_until_execution_inactive", lambda self, db, execution_id, timeout_seconds: True)

    delete_response = client.delete(f"/api/dataflow-vuln-scanner/history-runs/{bound['history_run_id']}")
    assert delete_response.status_code == 200
    delete_payload = delete_response.json()
    assert delete_payload["status"] == "deleted"
    assert delete_payload["process_pid"] == 4242
    assert delete_payload["process_signal"] == "sigint"
    assert fake_process.signals
    assert fake_process.signals[-1] == signal.SIGINT
    assert not run_root.exists()

    with get_db_session() as db:
        assert db.get(HistoryRun, bound["history_run_id"]) is None
        assert db.get(TriggerTask, bound["task_id"]) is None
        assert db.get(WorkflowExecution, bound["execution_id"]) is None
        assert db.query(WorkflowExecutionEvent).filter(WorkflowExecutionEvent.execution_id == bound["execution_id"]).count() == 0


def test_history_run_retry_execution_uses_resume_cli_argv(service_config_path, monkeypatch):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_resume_cli_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)

    with get_db_session() as db:
        history_run = db.get(HistoryRun, bound["history_run_id"])
        assert history_run is not None
        history_run.status = "cancelled"
        db.add(history_run)
        db.commit()

    captured: dict[str, list[str]] = {}

    def fake_invoke(self, *, argv, db, execution, trigger):
        captured["argv"] = list(argv)
        return 0

    monkeypatch.setattr(type(get_execution_service()), "_invoke_run_vuln_scan_cli", fake_invoke)

    retry_response = client.post(
        f"/api/dataflow-vuln-scanner/history-runs/{bound['history_run_id']}/retry",
        json={"extra_cycles": 2, "model": "mock/override", "thinking": "low"},
    )
    assert retry_response.status_code == 202

    deadline = time.time() + 5
    while "argv" not in captured and time.time() < deadline:
        time.sleep(0.05)
    assert "argv" in captured

    assert captured["argv"][:4] == ["--resume-run-dir", str(run_root.resolve()), "--extra-cycles", "2"]
    assert "--model" in captured["argv"]
    assert "mock/override" in captured["argv"]
    assert "--thinking" not in captured["argv"]


def test_history_run_status_prefers_active_run_meta_over_stale_terminal_state(service_config_path):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_running_meta_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)
    time.sleep(0.02)
    _write_json(run_root / "_meta" / "run_timestamps.json", {
        "started_at": "2026-05-07T10:15:02",
        "status": "running",
    })

    detail = client.get(f"/api/dataflow-vuln-scanner/history-runs/{bound['history_run_id']}")
    assert detail.status_code == 200
    assert detail.json()["status"] == "running"


def test_history_run_status_preserves_specific_terminal_workflow_result(service_config_path):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_specific_failed_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)
    atomic = run_root / "workspace" / "pipeline_demo_run_001" / "stage_01_vuln_scan" / "vuln_scan_initial_001"
    time.sleep(0.02)
    _write_json(run_root / "_meta" / "run_timestamps.json", {
        "started_at": "2026-05-07T10:15:03",
        "finished_at": "2026-05-07T10:20:03",
        "status": "failed",
    })
    _write_json(atomic / "_meta" / "workflow_result.json", {
        "status": "summary_incomplete",
        "timestamp": "2026-05-07T10:20:03Z",
        "detail": {"cycles_used": 2, "error": "summary/ledger sync incomplete"},
    })

    detail = client.get(f"/api/dataflow-vuln-scanner/history-runs/{bound['history_run_id']}")
    assert detail.status_code == 200
    assert detail.json()["status"] == "summary_incomplete"


def test_history_run_sessions_expose_stdout_soft_limit_metadata(service_config_path):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_session_limit_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)
    atomic = run_root / "workspace" / "pipeline_demo_run_001" / "stage_01_vuln_scan" / "vuln_scan_initial_001"
    time.sleep(0.02)
    _write_json(atomic / "sessions" / "worker" / "calls" / "001_abcd" / "response.json", {
        "status": "completed",
        "duration_ms": 1000,
        "output_len": 12,
        "output_total_bytes": 2048,
        "stdout_truncated": True,
        "stdout_soft_limit_exceeded": True,
        "trace_limits": {"stdout_bytes": 512},
        "events_truncated_count": 3,
    })

    sessions_response = client.get(f"/api/dataflow-vuln-scanner/history-runs/{bound['history_run_id']}/sessions")
    assert sessions_response.status_code == 200
    call_session = next(item for item in sessions_response.json() if item["format"] == "calls")
    call = call_session["calls"][0]
    assert call["output_total_bytes"] == 2048
    assert call["stdout_truncated"] is True
    assert call["stdout_soft_limit_exceeded"] is True
    assert call["events_truncated_count"] == 3
