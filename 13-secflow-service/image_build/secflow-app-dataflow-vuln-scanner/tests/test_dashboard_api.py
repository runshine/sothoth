import json
from pathlib import Path

from fastapi.testclient import TestClient

from dashboard import server


def _write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, data: dict):
    _write(path, json.dumps(data, ensure_ascii=False))


def test_dashboard_observability_api(monkeypatch, tmp_path):
    runs_dir = tmp_path / "runs"
    run = runs_dir / "demo_target_20260428_010203"
    older_run = runs_dir / "demo_target_20260427_235959"
    atomic = run / "workspace" / "pipeline_demo_run_001" / "stage_01_vuln_scan" / "vuln_scan_initial_001"

    _write_json(run / "config.json", {
        "global": {"max_review_cycles": 3, "parallel_result_review": True},
        "agents": [{
            "id": "pi-worker",
            "runtime_config": {
                "model": "github-copilot/gpt-test",
                "timeout_seconds": 1800,
                "sdk_specific": {"provider": "github-copilot", "thinking": "high"},
            },
        }],
        "execution": {"execution_id": "demo", "input_task": {"task_file": "input/task.md"}},
    })
    _write(run / "input" / "task.md", "# Task\n")
    _write(run / "run.log", "line1\nline2\n")
    _write_json(older_run / "config.json", {
        "global": {"max_review_cycles": 2, "parallel_result_review": False},
        "agents": [{"id": "pi-worker", "runtime_config": {"model": "github-copilot/gpt-old", "sdk_specific": {"thinking": "low"}}}],
        "execution": {"execution_id": "older", "input_task": {"task_file": "input/task.md"}},
    })

    _write_json(atomic / "_meta" / "state.json", {"current_state": "completed", "timestamp": "2026-04-28T01:12:03Z"})
    _write_json(atomic / "_meta" / "workflow_result.json", {"status": "completed", "timestamp": "2026-04-28T01:12:03Z", "detail": {"cycles_used": 1}})
    _write_json(atomic / "_meta" / "review_summaries" / "cycle_001.json", {
        "cycle": 1,
        "timestamp": "now",
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
        "historical_removed_result_count": 1,
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
    _write_json(atomic / "_meta" / "issues" / "cycle_001.json", {"cycle": 1, "issues": []})
    _write(atomic / "summary.md", "# Summary\n")
    _write(atomic / "previous_limitations.md", "# Limits\n")
    _write(atomic / "supporting_docs" / "coverage.md", "# Coverage\n")
    _write(atomic / "results" / "result_001.md", "# Confirmed issue\nbody")
    _write(atomic / "removed_results" / "cycle_002" / "result_002.md", "# Removed\n")
    _write_json(atomic / "removed_results" / "cycle_002" / "result_002.json", {
        "original_filename": "result_002.md",
        "removed_in_cycle": 2,
        "lifecycle_status": "false_positive",
        "reason": "误报迁移出 results/",
    })
    _write_json(atomic / "_meta" / "checkpoints" / "current_step.json", {"status": "completed"})
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

    monkeypatch.setattr(server, "RUNS_DIR", runs_dir)
    client = TestClient(server.app)

    runs = client.get("/api/runs").json()
    assert runs[0]["name"] == run.name
    assert runs[0]["status"] == "completed"
    assert runs[0]["cycles_used"] == 1
    assert runs[0]["duration_seconds"] == 600
    assert runs[0]["start_date"] == "2026-04-28"
    assert runs[1]["name"] == older_run.name

    detail = client.get(f"/api/runs/{run.name}").json()
    assert detail["duration_seconds"] == 600
    assert detail["cycles"][0]["scores"]["input_coverage"] == 0.95
    assert detail["cycles"][0]["historical_removed_result_count"] == 1
    assert detail["manifests"]["taskable_result_count"] == 1
    assert detail["results"][0]["path"] == "results/result_001.md"
    assert detail["results"][0]["lifecycle_status"] == "candidate"
    assert detail["results"][0]["review_path"].endswith("result_fp_check.json")
    assert detail["removed_results"][0]["filename"] == "result_002.md"

    cycle = client.get(f"/api/runs/{run.name}/cycles/1").json()
    assert cycle["global_reviews"][0]["path"].endswith("global_completeness.json")
    assert cycle["result_reviews"][0]["path"].endswith("result_fp_check.json")
    assert cycle["metrics"]["historical_removed_result_count"] == 1

    sessions = client.get(f"/api/runs/{run.name}/sessions").json()
    assert sessions[0]["calls"][0]["files"]["user_prompt"].endswith("user_prompt.md")

    files = client.get(f"/api/runs/{run.name}/files").json()
    assert any(f["path"] == "config.json" for f in files)
    assert any(f["path"] == "results/result_001.md" for f in files)
    assert any(f["path"] == "supporting_docs/coverage.md" for f in files)
    assert any(f["path"] == "_meta/results_manifest.json" for f in files)
    assert any(f["path"] == "removed_results/cycle_002/result_002.md" for f in files)

    result_file = client.get(f"/api/runs/{run.name}/file", params={"path": "results/result_001.md"}).json()
    assert result_file["type"] == "markdown"
    assert "Confirmed issue" in result_file["content"]

    log = client.get(f"/api/runs/{run.name}/log", params={"lines": 1}).json()
    assert log["content"] == "line2"

    assert server._normalize_run_status("review_error") == "review_error"
    assert server._normalize_run_status("summary_incomplete") == "summary_incomplete"
    assert server._normalize_run_status("global_review") == "running"
