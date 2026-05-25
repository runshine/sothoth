from __future__ import annotations

import json
import signal
import time
import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import inspect, text

from app.config import get_config
from app.main import create_app
from app.models.database import (
    RunIndex,
    RunIndexCycle,
    TriggerTask,
    WorkflowDefinitionVersion,
    WorkflowExecution,
    WorkflowExecutionEvent,
    get_db_session,
    init_database,
    run_source_hash,
)
from app.services.execution_service import get_execution_service
from app.services.run_index_service import get_run_index_service
from app.services.run_inspector import inspect_cycle_detail, inspect_run_detail
from app.services.scheduler import get_scheduler_service
from app.time_utils import now_local


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
        "workflows": {
            "atomic": [{
                "id": "vuln_scan",
                "engine": {"review_profile": "audit"},
            }],
        },
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


def _add_new_result_cycle_fixture(run_root: Path) -> None:
    atomic = run_root / "workspace" / "pipeline_demo_run_001" / "stage_01_vuln_scan" / "vuln_scan_initial_001"
    _write_json(atomic / "_meta" / "workflow_result.json", {
        "status": "completed",
        "timestamp": "2026-04-28T01:22:03Z",
        "detail": {"cycles_used": 3},
    })
    _write_json(atomic / "_meta" / "review_summaries" / "cycle_001.json", {
        "cycle": 1,
        "timestamp": "2026-04-28T01:12:03Z",
        "workflow_mode": "discovery",
        "global_review": {"passed": False, "advisor_results": []},
        "result_review": {
            "total": 2,
            "passed_count": 2,
            "failed_count": 0,
            "passed_files": ["result_001.md", "result_003.md"],
            "failed_files": [],
        },
        "outcome": "global_failed",
    })
    _write_json(atomic / "_meta" / "review_summaries" / "cycle_002.json", {
        "cycle": 2,
        "timestamp": "2026-04-28T01:17:03Z",
        "workflow_mode": "discovery",
        "global_review": {"passed": False, "advisor_results": []},
        "result_review": {
            "total": 3,
            "passed_count": 3,
            "failed_count": 0,
            "passed_files": ["result_001.md", "result_002.md", "result_003.md"],
            "failed_files": [],
        },
        "outcome": "global_failed",
    })
    _write_json(atomic / "_meta" / "review_summaries" / "cycle_003.json", {
        "cycle": 3,
        "timestamp": "2026-04-28T01:22:03Z",
        "workflow_mode": "closure",
        "global_review": {"passed": True, "advisor_results": []},
        "result_review": {
            "total": 2,
            "passed_count": 2,
            "failed_count": 0,
            "passed_files": ["result_001.md", "result_002.md"],
            "failed_files": [],
        },
        "outcome": "all_passed",
    })
    for cycle in (2, 3):
        _write_json(atomic / "_meta" / "cycle_metrics" / f"cycle_{cycle:03d}.json", {
            "cycle": cycle,
            "scores": {"input_coverage": 0.95},
            "global_failure_scope": "",
            "issue_count": 0,
            "issue_ids": [],
            "summary_size": 42,
            "historical_removed_result_count": 1 if cycle >= 3 else 0,
        })
    _write_json(atomic / "_meta" / "results_manifest.json", {
        "total_result_files": 3,
        "active_result_count": 2,
        "inactive_result_count": 1,
        "taskable_result_count": 2,
        "supplemental_result_count": 0,
        "excluded_results": [],
        "entries": [
            {
                "filename": "result_001.md",
                "role": "finding",
                "lifecycle_status": "candidate",
                "active": True,
                "taskable": True,
                "delivery_bucket": "results",
                "vulnerability_headings": ["VULN-001"],
            },
            {
                "filename": "result_002.md",
                "role": "finding",
                "lifecycle_status": "candidate",
                "active": True,
                "taskable": True,
                "delivery_bucket": "results",
                "vulnerability_headings": ["VULN-002"],
            },
            {
                "filename": "result_003.md",
                "role": "finding",
                "lifecycle_status": "inactive",
                "active": False,
                "taskable": False,
                "delivery_bucket": "removed_results",
                "vulnerability_headings": ["VULN-003"],
            },
        ],
    })
    _write_json(atomic / "_meta" / "result_relations_manifest.json", {
        "all_results": ["result_001.md", "result_002.md", "result_003.md"],
        "taskable_results": ["result_001.md", "result_002.md"],
        "supplemental_results": [],
        "inactive_results": ["result_003.md"],
        "relationships": [],
    })
    _write(atomic / "results" / "result_002.md", "# Second confirmed issue\nbody")
    _write(atomic / "removed_results" / "cycle_003" / "result_003.md", "# Removed issue\nbody")
    _write_json(atomic / "removed_results" / "cycle_003" / "result_003.json", {
        "original_filename": "result_003.md",
        "removed_in_cycle": 3,
        "lifecycle_status": "inactive",
        "reason": "merged into stronger result",
        "signals": [],
    })
    _write_json(atomic / "reviews" / "results" / "result_001" / "cycle_002" / "result_fp_check.json", {
        "result_file": "result_001.md",
        "advisor_instance_id": "result_fp_check",
        "cycle": 2,
        "passed": True,
        "verdict": "CONFIRMED",
        "confidence": 0.91,
        "feedback": "still valid",
        "schema_valid": True,
        "repair_attempts": 0,
    })
    _write_json(atomic / "reviews" / "results" / "result_002" / "cycle_002" / "result_fp_check.json", {
        "result_file": "result_002.md",
        "advisor_instance_id": "result_fp_check",
        "cycle": 2,
        "passed": True,
        "verdict": "CONFIRMED",
        "confidence": 0.88,
        "feedback": "ok",
        "schema_valid": True,
        "repair_attempts": 0,
    })
    _write_json(atomic / "reviews" / "results" / "result_003" / "cycle_001" / "result_fp_check.json", {
        "result_file": "result_003.md",
        "advisor_instance_id": "result_fp_check",
        "cycle": 1,
        "passed": True,
        "verdict": "CONFIRMED",
        "confidence": 0.82,
        "feedback": "ok",
        "schema_valid": True,
        "repair_attempts": 0,
    })


def _create_execution_bound_run(
    client: TestClient,
    run_root: Path,
    *,
    title: str = "scan demo package",
    task_purpose: str = "normal",
    agent_state_roots: dict | None = None,
) -> dict:
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
                    "metadata": {
                        "task_title": title,
                        "task_purpose": task_purpose,
                        "agent_state_roots": agent_state_roots or {},
                    },
                    "upstream_refs": [],
                }]
            },
            priority=120,
            status="succeeded",
            submitted_by="tester",
            task_purpose=task_purpose,
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
        run_index = get_run_index_service().sync_execution_run(db, execution)
        assert run_index is not None
        db.commit()
        return {
            "profile_id": profile["profile_id"],
            "task_id": trigger.id,
            "execution_id": execution.id,
            "run_id": run_index.id,
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


def test_runs_list_uses_execution_bound_runs_and_ignores_unbound_directories(service_config_path):
    runs_root = _project_runs_root()
    unbound_run = runs_root / "unbound_run_20260508_010203"
    _create_run_workspace(unbound_run)

    app = create_app()
    client = TestClient(app)
    bound_run = runs_root / "bound_run_20260508_010204"
    bound = _create_execution_bound_run(client, bound_run, title="DB bound scan")

    response = client.get("/api/dataflow-vuln-scanner/runs", params={"project_id": "default"})
    assert response.status_code == 200
    items = response.json()
    run_items = items
    names = {item["name"] for item in items}
    run_names = {item["name"] for item in run_items}
    assert bound_run.name in names
    assert bound_run.name in run_names
    assert unbound_run.name not in names
    assert unbound_run.name not in run_names

    summary = next(item for item in items if item["name"] == bound_run.name)
    run_summary = next(item for item in run_items if item["name"] == bound_run.name)
    assert run_summary["run_id"] == summary["run_id"]
    assert summary["source_type"] == "execution_workspace"
    assert summary["linked_task_id"] == bound["task_id"]
    assert summary["linked_execution_id"] == bound["execution_id"]
    assert summary["review_profile"] == "audit"

    tasks = client.get("/api/dataflow-vuln-scanner/tasks", params={"project_id": "default"})
    assert tasks.status_code == 200
    task_summary = next(item for item in tasks.json() if item["task_id"] == bound["task_id"])
    assert task_summary["title"] == "DB bound scan"
    assert task_summary["run"]["run_id"] == run_summary["run_id"]
    assert task_summary["run"]["review_profile"] == "audit"
    assert task_summary["latest_run"]["run_id"] == summary["run_id"]

    detail = client.get(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}")
    assert detail.status_code == 200
    detail_payload = detail.json()
    assert detail_payload["review_profile"] == "audit"
    assert detail_payload["config"]["review_profile"] == "audit"


def test_run_detail_groups_new_results_by_first_review_cycle(tmp_path):
    run_root = tmp_path / "new_results_by_cycle_20260512_010203"
    _create_run_workspace(run_root)
    _add_new_result_cycle_fixture(run_root)

    detail = inspect_run_detail(run_root)
    cycles = {item["cycle"]: item for item in detail["cycles"]}

    assert cycles[1]["new_result_count"] == 2
    assert [item["filename"] for item in cycles[1]["new_results"]] == ["result_001.md", "result_003.md"]
    assert cycles[2]["new_result_count"] == 1
    assert [item["filename"] for item in cycles[2]["new_results"]] == ["result_002.md"]
    assert cycles[3]["new_result_count"] == 0

    result_001 = next(item for item in cycles[1]["new_results"] if item["filename"] == "result_001.md")
    assert result_001["first_seen_cycle"] == 1
    assert result_001["current_review_cycle"] == 2
    assert result_001["current_verdict"] == "CONFIRMED"

    result_003 = next(item for item in cycles[1]["new_results"] if item["filename"] == "result_003.md")
    assert result_003["removed"] is True
    assert result_003["removed_cycle"] == 3
    assert result_003["path"] == "removed_results/cycle_003/result_003.md"
    assert result_003["active"] is False
    assert result_003["taskable"] is False

    cycle_detail = inspect_cycle_detail(run_root, 1)
    assert cycle_detail["new_result_count"] == 2
    assert [item["filename"] for item in cycle_detail["new_results"]] == ["result_001.md", "result_003.md"]


def test_run_api_exposes_new_results_and_derives_legacy_cycle_cache(service_config_path, monkeypatch):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_new_results_20260512_010203"
    bound = _create_execution_bound_run(client, run_root, title="new results scan")
    _add_new_result_cycle_fixture(run_root)

    with get_db_session() as db:
        execution = db.get(WorkflowExecution, bound["execution_id"])
        assert execution is not None
        run_index = get_run_index_service().sync_execution_run(db, execution)
        db.commit()
        assert run_index is not None

    detail = client.get(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}")
    assert detail.status_code == 200
    detail_payload = detail.json()
    cycle_1 = next(item for item in detail_payload["cycles"] if item["cycle"] == 1)
    assert cycle_1["new_result_count"] == 2
    assert [item["filename"] for item in cycle_1["new_results"]] == ["result_001.md", "result_003.md"]

    with get_db_session() as db:
        cycle_row = (
            db.query(RunIndexCycle)
            .filter(RunIndexCycle.run_index_id == bound["run_id"], RunIndexCycle.cycle == 1)
            .first()
        )
        assert cycle_row is not None
        raw_file = Path(bound["run_root"]) / cycle_row.raw_json["raw_file"]
        raw_payload = json.loads(raw_file.read_text(encoding="utf-8"))
        raw_payload.pop("new_result_count", None)
        raw_payload.pop("new_results", None)
        _write_json(raw_file, raw_payload)

    import app.services.run_index_service as run_index_service_module

    monkeypatch.setattr(run_index_service_module, "_source_mtime_is_current", lambda *args, **kwargs: True)
    legacy_cycle = client.get(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}/cycles/1")
    assert legacy_cycle.status_code == 200
    legacy_payload = legacy_cycle.json()
    assert legacy_payload["new_result_count"] == 2
    assert [item["filename"] for item in legacy_payload["new_results"]] == ["result_001.md", "result_003.md"]


def test_run_resolve_only_returns_execution_bound_records(service_config_path):
    runs_root = _project_runs_root()
    unbound_run = runs_root / "unbound_resolve_20260508_010203"
    _create_run_workspace(unbound_run)

    app = create_app()
    client = TestClient(app)
    bound_run = runs_root / "bound_resolve_20260508_010204"
    bound = _create_execution_bound_run(client, bound_run)

    resolve_bound = client.get(
        "/api/dataflow-vuln-scanner/runs/resolve",
        params={"project_id": "default", "run_name": bound_run.name, "root_path": str(bound_run.parent)},
    )
    assert resolve_bound.status_code == 200
    assert resolve_bound.json()["run_id"] == bound["run_id"]

    resolve_unbound = client.get(
        "/api/dataflow-vuln-scanner/runs/resolve",
        params={"project_id": "default", "run_name": unbound_run.name, "root_path": str(unbound_run.parent)},
    )
    assert resolve_unbound.status_code == 404


def test_run_refreshes_after_execution_directory_changes(service_config_path):
    app = create_app()
    client = TestClient(app)
    bound_run = _project_runs_root() / "bound_refresh_20260508_010203"
    bound = _create_execution_bound_run(client, bound_run)

    detail_before = client.get(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}")
    assert detail_before.status_code == 200
    assert not any(item["path"] == "supporting_docs/new_note.md" for item in detail_before.json()["files"])

    time.sleep(0.02)
    atomic = bound_run / "workspace" / "pipeline_demo_run_001" / "stage_01_vuln_scan" / "vuln_scan_initial_001"
    _write(atomic / "supporting_docs" / "new_note.md", "# New note\n")

    detail_after = client.get(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}")
    assert detail_after.status_code == 200
    assert any(item["path"] == "supporting_docs/new_note.md" for item in detail_after.json()["files"])


def test_run_reparses_when_atomic_work_path_was_stale(service_config_path):
    app = create_app()
    client = TestClient(app)
    bound = _create_execution_bound_run(client, _project_runs_root() / "bound_atomic_refresh_20260508_010203")

    with get_db_session() as db:
        row = db.get(RunIndex, bound["run_id"])
        assert row is not None
        row.atomic_work_path = ""
        row.cycles_used = 0
        row.result_count = 0
        row.manifests_json = {}
        db.add(row)
        db.commit()

    detail = client.get(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}")
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["atomic_work_path"].endswith("vuln_scan_initial_001")
    assert payload["cycles"]
    assert payload["results"]


def test_run_cycle_marks_profile_gate_failure_separately(service_config_path):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_profile_gate_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)
    atomic = run_root / "workspace" / "pipeline_demo_run_001" / "stage_01_vuln_scan" / "vuln_scan_initial_001"
    feedback = (
        "[框架范围验收硬门槛未通过]\n"
        "- SCOPE-metadata-sync: 本轮验收发现结果清单元数据不同步。"
    )
    profile_issue = {
        "id": "PROFILE-audit-metadata-sync",
        "category": "metadata_sync",
        "target": "_meta/results_manifest.json",
        "required_action": "同步结果清单元数据",
        "blocking_type": "metadata_sync",
    }

    time.sleep(0.02)
    _write_json(atomic / "_meta" / "review_summaries" / "cycle_001.json", {
        "cycle": 1,
        "timestamp": "2026-04-28T01:12:03Z",
        "workflow_mode": "closure",
        "global_review": {
            "passed": False,
            "feedback_preview": feedback,
            "issues": [profile_issue],
            "advisor_results": [
                {"advisor_id": "global_completeness", "passed": True},
                {"advisor_id": "global_depth", "passed": True},
            ],
            "total_advisor_count": 2,
            "passed_advisor_count": 2,
            "failed_advisor_id": "",
            "failed_role_name": "",
        },
        "result_review": {
            "total": 1,
            "passed_count": 1,
            "failed_count": 0,
            "passed_files": ["result_001.md"],
            "failed_files": [],
        },
        "outcome": "global_failed",
    })
    _write_json(atomic / "_meta" / "cycle_metrics" / "cycle_001.json", {
        "cycle": 1,
        "scores": {"input_coverage": 0.95},
        "global_failure_scope": "analysis",
        "global_feedback_preview": feedback,
        "issue_count": 1,
        "issue_ids": [profile_issue["id"]],
        "summary_size": 42,
        "historical_removed_result_count": 0,
    })
    _write_json(atomic / "_meta" / "review_feedback" / "cycle_001.json", {
        "cycle": 1,
        "issues": [profile_issue],
        "last_global_feedback": feedback,
    })

    detail = client.get(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}")
    assert detail.status_code == 200
    cycle = detail.json()["cycles"][0]
    assert cycle["outcome"] == "global_failed"
    assert cycle["profile_gate"]["failed"] is True
    assert cycle["profile_gate"]["advisor_all_passed"] is True
    assert cycle["global_advisor_total"] == 2
    assert cycle["global_advisor_passed"] == 2

    cycle_detail = client.get(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}/cycles/1")
    assert cycle_detail.status_code == 200
    assert cycle_detail.json()["profile_gate"]["failed"] is True


def test_run_detail_latest_issues_prefers_latest_review_feedback(tmp_path):
    run_root = tmp_path / "latest_issues_20260512_010203"
    _create_run_workspace(run_root)
    atomic = run_root / "workspace" / "pipeline_demo_run_001" / "stage_01_vuln_scan" / "vuln_scan_initial_001"
    stale_issue = {
        "id": "CMP-old",
        "category": "coverage_gap",
        "target": "result_001.md",
        "required_action": "旧 advisor 问题",
        "actionable_by": "worker",
    }
    active_issue = {
        "id": "CMP-active-export",
        "category": "analysis_gap",
        "target": "IPSEC_SOCK_SendToSocket",
        "required_action": "继续跟入 EXPORT 链",
        "actionable_by": "worker",
        "blocking_type": "analysis_gap",
    }
    _write_json(atomic / "_meta" / "review_feedback" / "cycle_001.json", {
        "cycle": 1,
        "issue_count": 1,
        "issues": [stale_issue],
    })
    _write_json(atomic / "_meta" / "review_feedback" / "cycle_002.json", {
        "cycle": 2,
        "issue_count": 1,
        "issues": [active_issue],
    })

    detail = inspect_run_detail(run_root)
    assert [item["id"] for item in detail["latest_issues"]] == ["CMP-active-export"]
    assert detail["latest_issues"][0]["blocking_type"] == "analysis_gap"


def test_run_retry_queue_cancel_and_delete(service_config_path, monkeypatch):
    app = create_app()
    client = TestClient(app)
    monkeypatch.setattr(get_scheduler_service(), "start_execution_now", lambda execution_id: False)
    monkeypatch.setattr(
        type(get_execution_service()),
        "_preflight_run_resume",
        lambda self, run_index, payload: {"preview_path": "mock_resume_preview.json"},
    )
    run_root = _project_runs_root() / "bound_resume_delete_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)

    completed_retry_response = client.post(
        f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}/retry",
        json={"extra_cycles": 2},
    )
    assert completed_retry_response.status_code == 202
    retry_payload = completed_retry_response.json()
    assert retry_payload["status"] == "queued"
    assert retry_payload["linked_task_id"]
    assert retry_payload["linked_execution_id"]

    detail_queued = client.get(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}")
    assert detail_queued.status_code == 200
    detail_payload = detail_queued.json()
    assert detail_payload["status"] == "queued"
    assert detail_payload["process_state"]["can_retry"] is False
    assert "--resume-run-dir" in detail_payload["retry_command_display"]

    duplicate_retry_response = client.post(
        f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}/retry",
        json={"extra_cycles": 2},
    )
    assert duplicate_retry_response.status_code == 409
    assert "pending/queued" in duplicate_retry_response.json()["detail"]

    cancel_response = client.post(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}/cancel")
    assert cancel_response.status_code == 200
    assert cancel_response.json()["status"] == "cancelled"

    delete_response = client.delete(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}")
    assert delete_response.status_code == 200
    assert delete_response.json()["status"] == "deleted"
    assert not run_root.exists()

    missing_detail = client.get(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}")
    assert missing_detail.status_code == 404


def test_run_retry_rejects_live_process_state(service_config_path, monkeypatch):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_retry_live_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)

    with get_db_session() as db:
        run_index = db.get(RunIndex, bound["run_id"])
        execution = db.get(WorkflowExecution, bound["execution_id"])
        trigger = db.get(TriggerTask, bound["task_id"])
        assert run_index is not None and execution is not None and trigger is not None
        run_index.status = "running"
        execution.status = "running"
        execution.process_status = "running"
        trigger.status = "running"
        db.add_all([run_index, execution, trigger])
        db.commit()

    service = get_execution_service()
    fake_process = _FakeCliProcess()
    service._register_cli_process(bound["execution_id"], fake_process)
    try:
        retry_response = client.post(
            f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}/retry",
            json={"extra_cycles": 2},
        )
        assert retry_response.status_code == 409
        assert "仍持有" in retry_response.json()["detail"]
    finally:
        service._forget_cli_process(bound["execution_id"], fake_process)


def test_run_retry_allows_stale_running_heartbeat(service_config_path, monkeypatch):
    app = create_app()
    client = TestClient(app)
    monkeypatch.setattr(get_scheduler_service(), "start_execution_now", lambda execution_id: False)
    monkeypatch.setattr(
        type(get_execution_service()),
        "_preflight_run_resume",
        lambda self, run_index, payload: {"preview_path": "mock_resume_preview.json"},
    )
    run_root = _project_runs_root() / "bound_retry_stale_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)
    _write_json(run_root / "_meta" / "process.json", {
        "execution_id": bound["execution_id"],
        "trigger_task_id": bound["task_id"],
        "pid": 4242,
        "pod_id": "old-pod",
        "status": "running",
        "heartbeat_at": "2026-04-28T01:02:03+08:00",
    })

    with get_db_session() as db:
        run_index = db.get(RunIndex, bound["run_id"])
        execution = db.get(WorkflowExecution, bound["execution_id"])
        trigger = db.get(TriggerTask, bound["task_id"])
        assert run_index is not None and execution is not None and trigger is not None
        run_index.status = "running"
        execution.status = "running"
        execution.process_status = "running"
        trigger.status = "running"
        db.add_all([run_index, execution, trigger])
        db.commit()

    retry_response = client.post(
        f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}/retry",
        json={"extra_cycles": 2},
    )
    assert retry_response.status_code == 202
    with get_db_session() as db:
        old_execution = db.get(WorkflowExecution, bound["execution_id"])
        assert old_execution is not None and old_execution.status == "failed"


def test_run_retry_preflight_error_returns_frontend_message(service_config_path):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_retry_preflight_error_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)

    with get_db_session() as db:
        before_count = db.query(WorkflowExecution).filter(WorkflowExecution.trigger_task_id == bound["task_id"]).count()

    retry_response = client.post(
        f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}/retry",
        json={"extra_cycles": 2},
    )
    assert retry_response.status_code == 422
    assert "resume preflight failed" in retry_response.json()["detail"]
    with get_db_session() as db:
        after_count = db.query(WorkflowExecution).filter(WorkflowExecution.trigger_task_id == bound["task_id"]).count()
    assert after_count == before_count


def test_run_cancel_active_run_signals_bound_process(service_config_path):
    app = create_app()
    client = TestClient(app)
    bound = _create_execution_bound_run(client, _project_runs_root() / "bound_cancel_active_20260508_010203")

    with get_db_session() as db:
        run_index = db.get(RunIndex, bound["run_id"])
        execution = db.get(WorkflowExecution, bound["execution_id"])
        trigger = db.get(TriggerTask, bound["task_id"])
        assert run_index is not None and execution is not None and trigger is not None
        run_index.status = "running"
        execution.status = "running"
        execution.process_pid = 4242
        execution.process_status = "running"
        trigger.status = "running"
        db.add_all([run_index, execution, trigger])
        db.commit()

    fake_process = _FakeCliProcess()
    get_execution_service()._register_cli_process(bound["execution_id"], fake_process)

    cancel_response = client.post(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}/cancel")
    assert cancel_response.status_code == 200
    cancel_payload = cancel_response.json()
    assert cancel_payload["status"] == "cancel_requested"
    assert cancel_payload["process_pid"] == 4242
    assert cancel_payload["process_signal"] == "sigint"
    assert fake_process.signals
    assert fake_process.signals[-1] == signal.SIGINT

    with get_db_session() as db:
        execution = db.get(WorkflowExecution, bound["execution_id"])
        run_index = db.get(RunIndex, bound["run_id"])
        assert execution is not None and execution.status == "cancel_requested"
        assert run_index is not None and run_index.status == "cancel_requested"


def test_run_process_state_uses_startup_grace_before_marking_stale(service_config_path):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_startup_grace_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)

    with get_db_session() as db:
        run_index = db.get(RunIndex, bound["run_id"])
        execution = db.get(WorkflowExecution, bound["execution_id"])
        trigger = db.get(TriggerTask, bound["task_id"])
        assert run_index is not None and execution is not None and trigger is not None
        now = now_local()
        run_index.status = "running"
        execution.status = "running"
        execution.started_at = now
        execution.process_status = None
        trigger.status = "running"
        trigger.started_at = now
        db.add_all([run_index, execution, trigger])
        db.commit()

        service = get_execution_service()
        process_state = service._run_process_state(db, run_index, trigger=trigger, execution=execution)
        assert process_state["source"] == "startup_grace"
        assert process_state["is_running"] is True
        assert process_state["can_retry"] is False
        assert process_state.get("stale") is not True
        assert service._reconcile_stale_runtime(db, run_index=run_index, trigger=trigger, execution=execution) is False
        db.refresh(execution)
        db.refresh(trigger)
        assert execution.status == "running"
        assert trigger.status == "running"


def test_run_delete_active_run_stops_process_and_removes_records(service_config_path, monkeypatch):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_delete_active_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)

    with get_db_session() as db:
        run_index = db.get(RunIndex, bound["run_id"])
        execution = db.get(WorkflowExecution, bound["execution_id"])
        trigger = db.get(TriggerTask, bound["task_id"])
        assert run_index is not None and execution is not None and trigger is not None
        run_index.status = "running"
        execution.status = "running"
        execution.process_pid = 4242
        execution.process_status = "running"
        trigger.status = "running"
        db.add_all([run_index, execution, trigger])
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

    delete_response = client.delete(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}")
    assert delete_response.status_code == 200
    delete_payload = delete_response.json()
    assert delete_payload["status"] == "deleted"
    assert delete_payload["process_pid"] == 4242
    assert delete_payload["process_signal"] == "sigint"
    assert fake_process.signals
    assert fake_process.signals[-1] == signal.SIGINT
    assert not run_root.exists()

    with get_db_session() as db:
        assert db.get(RunIndex, bound["run_id"]) is None
        assert db.get(TriggerTask, bound["task_id"]) is None
        assert db.get(WorkflowExecution, bound["execution_id"]) is None
        assert db.query(WorkflowExecutionEvent).filter(WorkflowExecutionEvent.execution_id == bound["execution_id"]).count() == 0


def test_run_delete_active_run_does_not_wait_after_local_process_stopped(service_config_path, monkeypatch):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_delete_local_stopped_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)

    with get_db_session() as db:
        run_index = db.get(RunIndex, bound["run_id"])
        execution = db.get(WorkflowExecution, bound["execution_id"])
        trigger = db.get(TriggerTask, bound["task_id"])
        assert run_index is not None and execution is not None and trigger is not None
        run_index.status = "running"
        execution.status = "running"
        execution.process_pid = 4242
        execution.process_status = "running"
        trigger.status = "running"
        db.add_all([run_index, execution, trigger])
        db.commit()

    service = get_execution_service()
    fake_process = _FakeCliProcess()
    service._register_cli_process(bound["execution_id"], fake_process)

    def fail_wait(*_args, **_kwargs):
        raise AssertionError("delete_run should not wait for DB inactivity after local process.wait() returned")

    monkeypatch.setattr(type(service), "_wait_until_execution_inactive", fail_wait)

    delete_response = client.delete(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}")
    assert delete_response.status_code == 200
    assert delete_response.json()["status"] == "deleted"
    assert fake_process.signals[-1] == signal.SIGINT
    assert not run_root.exists()



def test_run_delete_stale_active_record_deletes_without_endless_stopping_conflict(service_config_path, monkeypatch):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_delete_stale_active_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)

    with get_db_session() as db:
        run_index = db.get(RunIndex, bound["run_id"])
        execution = db.get(WorkflowExecution, bound["execution_id"])
        trigger = db.get(TriggerTask, bound["task_id"])
        assert run_index is not None and execution is not None and trigger is not None
        run_index.status = "running"
        execution.status = "running"
        execution.process_pid = 4242
        execution.process_status = "running"
        trigger.status = "running"
        db.add_all([run_index, execution, trigger])
        db.commit()

    service = get_execution_service()
    service._forget_cli_process(bound["execution_id"])
    monkeypatch.setattr(type(service), "_wait_until_execution_inactive", lambda self, db, execution_id, timeout_seconds: False)

    delete_response = client.delete(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}")
    assert delete_response.status_code == 200
    payload = delete_response.json()
    assert payload["status"] == "deleted"
    assert payload["process_signal"] == "db_flag_only"
    assert not run_root.exists()

    with get_db_session() as db:
        assert db.get(RunIndex, bound["run_id"]) is None
        assert db.get(TriggerTask, bound["task_id"]) is None
        assert db.get(WorkflowExecution, bound["execution_id"]) is None



def test_run_retry_execution_uses_resume_cli_argv(service_config_path, monkeypatch):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_resume_cli_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)
    monkeypatch.setattr(
        type(get_execution_service()),
        "_preflight_run_resume",
        lambda self, run_index, payload: {"preview_path": "mock_resume_preview.json"},
    )

    with get_db_session() as db:
        run_index = db.get(RunIndex, bound["run_id"])
        assert run_index is not None
        run_index.status = "cancelled"
        db.add(run_index)
        db.commit()

    captured: dict[str, list[str]] = {}

    def fake_invoke(self, *, argv, db, execution, trigger):
        captured["argv"] = list(argv)
        return 0

    monkeypatch.setattr(type(get_execution_service()), "_invoke_run_vuln_scan_cli", fake_invoke)

    retry_response = client.post(
        f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}/retry",
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


def test_run_status_prefers_active_run_meta_over_stale_terminal_state(service_config_path):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_running_meta_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)
    time.sleep(0.02)
    _write_json(run_root / "_meta" / "run_timestamps.json", {
        "started_at": "2026-05-07T10:15:02",
        "status": "running",
    })

    detail = client.get(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}")
    assert detail.status_code == 200
    assert detail.json()["status"] == "running"


def test_run_detail_uses_failed_task_status_when_index_is_stale_running(service_config_path):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_failed_task_running_index_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)
    with get_db_session() as db:
        trigger = db.get(TriggerTask, bound["task_id"])
        execution = db.get(WorkflowExecution, bound["execution_id"])
        run_index = db.get(RunIndex, bound["run_id"])
        assert trigger is not None and execution is not None and run_index is not None
        trigger.status = "failed"
        trigger.message = "stale active runtime assumed failed"
        execution.status = "failed"
        execution.message = "stale active runtime assumed failed"
        execution.process_status = "exited"
        run_index.status = "running"
        db.add_all([trigger, execution, run_index])
        db.commit()
        enriched = get_execution_service()._enrich_run_payload(db, run_index, {"status": "running"})

    assert enriched["status"] == "failed"
    assert enriched["process_state"]["display_status"] == "runtime_lost"


def test_run_status_uses_terminal_control_status_without_finished_at(service_config_path):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_stale_failed_meta_20260508_010203"
    bound = _create_execution_bound_run(client, run_root)
    atomic = run_root / "workspace" / "pipeline_demo_run_001" / "stage_01_vuln_scan" / "vuln_scan_initial_001"
    time.sleep(0.02)
    _write_json(run_root / "_meta" / "run_timestamps.json", {
        "started_at": "2026-05-07T10:15:02",
        "finished_at": None,
        "status": "failed",
        "control_message": "stale active runtime assumed failed",
    })
    _write_json(atomic / "_meta" / "state.json", {
        "current_state": "running",
        "timestamp": "2026-05-07T10:19:58Z",
    })
    _write_json(atomic / "_meta" / "workflow_result.json", {
        "status": "running",
        "timestamp": "2026-05-07T10:19:58Z",
        "detail": {"cycles_used": 2},
    })

    detail = client.get(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}")
    assert detail.status_code == 200
    assert detail.json()["status"] == "failed"


def test_run_control_state_sets_finished_at_for_terminal_status(service_config_path):
    run_root = _project_runs_root() / "bound_control_finished_at_20260508_010203"
    _create_run_workspace(run_root)
    _write_json(run_root / "_meta" / "run_timestamps.json", {
        "started_at": "2026-05-07T10:15:02",
        "finished_at": None,
        "status": "running",
    })

    get_execution_service()._write_run_control_state(run_root, status_text="failed", message="stale active runtime assumed failed")

    payload = json.loads((run_root / "_meta" / "run_timestamps.json").read_text(encoding="utf-8"))
    assert payload["status"] == "failed"
    assert payload["finished_at"]


def test_run_status_preserves_specific_terminal_workflow_result(service_config_path):
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
        "detail": {"cycles_used": 2, "error": "summary sync incomplete"},
    })

    detail = client.get(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}")
    assert detail.status_code == 200
    assert detail.json()["status"] == "summary_incomplete"


def test_run_sessions_expose_stdout_soft_limit_metadata(service_config_path):
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

    sessions_response = client.get(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}/sessions")
    assert sessions_response.status_code == 200
    call_session = next(item for item in sessions_response.json() if item["format"] == "calls")
    call = call_session["calls"][0]
    assert call["output_total_bytes"] == 2048
    assert call["stdout_truncated"] is True
    assert call["stdout_soft_limit_exceeded"] is True
    assert call["events_truncated_count"] == 3


def test_run_table_migration_copies_legacy_rows_and_hashes_source(service_config_path):
    legacy_base = "history" + "_run"
    legacy_fk = legacy_base + "_id"
    legacy_run_table = RunIndex.__tablename__.replace("run_index", legacy_base)
    legacy_cycle_table = RunIndexCycle.__tablename__.replace("run_index", legacy_base)
    run_root = service_config_path.parent / "legacy_migrated_run"
    run_root.mkdir(parents=True, exist_ok=True)

    db = get_db_session()
    try:
        run_columns = [column.name for column in RunIndex.__table__.columns if column.name != "source_hash"]
        run_select = ", ".join(run_columns)
        db.execute(text(f"CREATE TABLE {legacy_run_table} AS SELECT {run_select} FROM {RunIndex.__tablename__} WHERE 0"))
        run_values = {column: None for column in run_columns}
        run_values.update({
            "id": "ri-legacy-001",
            "project_id": "default",
            "source_type": "execution_workspace",
            "source_key": str(run_root.resolve()),
            "run_name": run_root.name,
            "run_root_path": str(run_root.resolve()),
            "status": "completed",
            "duration_seconds": 12,
            "model": "",
            "provider": "",
            "thinking": "",
            "max_cycles": 1,
            "cycles_used": 1,
            "result_count": 0,
            "passed_count": 0,
            "failed_count": 0,
            "workflow_mode": "",
            "config_json": "{}",
            "manifests_json": "{}",
            "latest_issues_json": "[]",
            "raw_summary_json": "{}",
            "log_size_bytes": 0,
            "source_mtime": 0,
        })
        db.execute(
            text(
                f"INSERT INTO {legacy_run_table} ({', '.join(run_columns)}) "
                f"VALUES ({', '.join(f':{column}' for column in run_columns)})"
            ),
            run_values,
        )

        cycle_select = []
        for column in RunIndexCycle.__table__.columns:
            if column.name == "run_index_id":
                cycle_select.append(f"{column.name} AS {legacy_fk}")
            else:
                cycle_select.append(column.name)
        db.execute(
            text(
                f"CREATE TABLE {legacy_cycle_table} AS "
                f"SELECT {', '.join(cycle_select)} FROM {RunIndexCycle.__tablename__} WHERE 0"
            )
        )
        cycle_columns = [legacy_fk if column.name == "run_index_id" else column.name for column in RunIndexCycle.__table__.columns]
        cycle_values = {column: None for column in cycle_columns}
        cycle_values.update({
            "id": "ric-legacy-001",
            legacy_fk: "ri-legacy-001",
            "cycle": 1,
            "timestamp": "2026-05-08T01:02:03Z",
            "outcome": "all_passed",
            "workflow_mode": "discovery",
            "global_passed": True,
            "failed_advisor_id": "",
            "failed_role_name": "",
            "result_total": 0,
            "result_passed": 0,
            "result_failed": 0,
            "scores_json": "{}",
            "metrics_json": "{}",
            "issues_json": "[]",
            "plateau_status_json": "{}",
            "raw_json": "{}",
        })
        db.execute(
            text(
                f"INSERT INTO {legacy_cycle_table} ({', '.join(cycle_columns)}) "
                f"VALUES ({', '.join(f':{column}' for column in cycle_columns)})"
            ),
            cycle_values,
        )
        db.commit()
    finally:
        db.close()

    init_database()

    db = get_db_session()
    try:
        migrated = db.get(RunIndex, "ri-legacy-001")
        assert migrated is not None
        assert migrated.source_hash == run_source_hash("execution_workspace", str(run_root.resolve()))
        assert db.query(RunIndexCycle).filter(RunIndexCycle.run_index_id == migrated.id).count() == 1
        indexes = {item["name"]: item for item in inspect(db.bind).get_indexes(RunIndex.__tablename__)}
        assert indexes["ux_dfvs_ri_source_hash"]["unique"] in (True, 1)
        assert indexes["ix_dfvs_ri_source_key"].get("unique") in (False, 0, None)
        tables = set(inspect(db.bind).get_table_names())
        assert legacy_run_table not in tables
        assert legacy_cycle_table not in tables
    finally:
        db.close()


def test_run_sync_allows_long_common_prefix_source_keys(service_config_path):
    common = service_config_path.parent / "long_prefix_runs"
    for index in range(12):
        common = common / f"segment_{index:02d}_{'a' * 42}"
    run_one = common / "run_one"
    run_two = common / "run_two"
    assert len(str(common.resolve())) > 512
    _create_run_workspace(run_one)
    _create_run_workspace(run_two)

    db = get_db_session()
    try:
        service = get_run_index_service()
        first = service.sync_run_path(
            db,
            project_id="default",
            run_root=run_one,
            source_type="execution_workspace",
        )
        second = service.sync_run_path(
            db,
            project_id="default",
            run_root=run_two,
            source_type="execution_workspace",
        )
        db.commit()
        assert first.id != second.id
        assert first.source_hash != second.source_hash
        records = db.query(RunIndex).filter(RunIndex.id.in_([first.id, second.id])).all()
        assert len(records) == 2
    finally:
        db.close()


def test_run_table_migration_drops_legacy_rows_already_synced_by_hash(service_config_path):
    legacy_base = "history" + "_run"
    legacy_run_table = RunIndex.__tablename__.replace("run_index", legacy_base)
    run_root = service_config_path.parent / "legacy_already_synced_run"
    run_root.mkdir(parents=True, exist_ok=True)
    source_key = str(run_root.resolve())

    db = get_db_session()
    try:
        existing = RunIndex(
            id="ri-existing-001",
            project_id="default",
            source_type="execution_workspace",
            source_key=source_key,
            source_hash=run_source_hash("execution_workspace", source_key),
            run_name=run_root.name,
            run_root_path=source_key,
            status="completed",
            duration_seconds=0,
            model="",
            provider="",
            thinking="",
            max_cycles=0,
            cycles_used=0,
            result_count=0,
            passed_count=0,
            failed_count=0,
            workflow_mode="",
            config_json={},
            manifests_json={},
            latest_issues_json=[],
            raw_summary_json={},
            log_size_bytes=0,
            source_mtime=0,
        )
        db.add(existing)
        run_columns = [column.name for column in RunIndex.__table__.columns if column.name != "source_hash"]
        db.execute(
            text(
                f"CREATE TABLE {legacy_run_table} AS "
                f"SELECT {', '.join(run_columns)} FROM {RunIndex.__tablename__} WHERE 0"
            )
        )
        legacy_values = {column: getattr(existing, column, None) for column in run_columns}
        legacy_values["id"] = "ri-legacy-duplicate"
        for column in ("config_json", "manifests_json", "latest_issues_json", "raw_summary_json"):
            legacy_values[column] = json.dumps(legacy_values[column])
        db.execute(
            text(
                f"INSERT INTO {legacy_run_table} ({', '.join(run_columns)}) "
                f"VALUES ({', '.join(f':{column}' for column in run_columns)})"
            ),
            legacy_values,
        )
        db.commit()
    finally:
        db.close()

    init_database()

    db = get_db_session()
    try:
        assert db.get(RunIndex, "ri-existing-001") is not None
        assert db.get(RunIndex, "ri-legacy-duplicate") is None
        assert legacy_run_table not in set(inspect(db.bind).get_table_names())
    finally:
        db.close()


def test_task_list_survives_run_summary_sync_failure(service_config_path, monkeypatch):
    app = create_app()
    client = TestClient(app)
    run_root = _project_runs_root() / "bound_sync_failure_20260508_010203"
    bound = _create_execution_bound_run(client, run_root, title="sync failure tolerant")

    def fail_sync(*args, **kwargs):
        raise RuntimeError("simulated run index sync failure")

    monkeypatch.setattr(get_run_index_service(), "get_run_index_by_execution", fail_sync)
    response = client.get("/api/dataflow-vuln-scanner/tasks", params={"project_id": "default"})
    assert response.status_code == 200
    task = next(item for item in response.json() if item["task_id"] == bound["task_id"])
    assert task["title"] == "sync failure tolerant"
    assert task["run"]["name"] == bound["run_name"]
    assert task["run"]["path"] == bound["run_root"]


def test_task_create_defaults_normal_purpose_and_shared_agent_dirs(service_config_path):
    app = create_app()
    client = TestClient(app)
    profile_response = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload("purpose default profile"))
    assert profile_response.status_code == 201
    profile = profile_response.json()

    response = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile["profile_id"],
            "title": "default purpose task",
            "task_markdown": "# Demo\n",
        },
    )
    assert response.status_code == 201
    payload = response.json()
    assert payload["task_purpose"] == "normal"
    assert payload["agent_state_dirs"]
    for item in payload["agent_state_dirs"].values():
        assert item["source"] == "shared_default"
        assert item["root_dir"].endswith(f"/agent-state/shared/{item['agent_id']}")
        assert item["skills_dir"] == f"{item['root_dir']}/skills"
        assert item["memory_dir"] == f"{item['root_dir']}/memory"

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{payload['task_id']}")
    assert detail.status_code == 200
    detail_payload = detail.json()
    assert detail_payload["task_purpose"] == "normal"
    assert detail_payload["agent_state_dirs"] == payload["agent_state_dirs"]


def test_task_create_rejects_agent_state_root_escape(service_config_path):
    app = create_app()
    client = TestClient(app)
    profile_response = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload("purpose escape profile"))
    assert profile_response.status_code == 201
    profile = profile_response.json()

    response = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile["profile_id"],
            "title": "bad evolution task",
            "task_markdown": "# Demo\n",
            "task_purpose": "evolution",
            "agent_state_roots": {
                "pi-worker": {
                    "root_dir": {
                        "source": "project_filesystem",
                        "path": "/../../escape",
                    }
                }
            },
        },
    )
    assert response.status_code == 422
    assert "escapes project root" in response.json()["detail"]


def test_run_detail_exposes_linked_task_purpose_and_agent_state_dirs(service_config_path):
    app = create_app()
    client = TestClient(app)
    project_root = (
        Path(get_config().fileserver_service.data_mount_path)
        / "files"
        / "default"
    )
    worker_root = project_root / "DATAFLOW_VULN_SCANNER" / "evolution" / "pi-worker-custom"
    worker_root.mkdir(parents=True, exist_ok=True)
    bound = _create_execution_bound_run(
        client,
        _project_runs_root() / "bound_evolution_task_20260512_010203",
        title="evolution bound scan",
        task_purpose="evolution",
        agent_state_roots={
            "pi-worker": {
                "root_dir": {
                    "source": "project_filesystem",
                    "path": "/DATAFLOW_VULN_SCANNER/evolution/pi-worker-custom",
                }
            }
        },
    )

    detail = client.get(f"/api/dataflow-vuln-scanner/runs/{bound['run_id']}")
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["linked_task_purpose"] == "evolution"
    assert payload["linked_task_agent_state_dirs"]
    assert payload["linked_task_agent_state_dirs"]["pi-worker"]["source"] == "task_override"
    assert payload["linked_task_agent_state_dirs"]["pi-worker"]["root_dir"] == str(worker_root.resolve())
    assert payload["linked_task_agent_state_dirs"]["pi-worker"]["skills_dir"] == f"{worker_root.resolve()}/skills"
    assert payload["linked_task_agent_state_dirs"]["pi-worker"]["memory_dir"] == f"{worker_root.resolve()}/memory"
