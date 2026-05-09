from __future__ import annotations

import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient


def _configure_service(tmp_path: Path, monkeypatch):
    from app import model as model_module
    from app.config import reload_config

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "database:\n"
        "  type: sqlite\n"
        f"  path: {tmp_path / 'service.db'}\n"
        "auth_service:\n"
        "  enabled: false\n"
        "project_service:\n"
        "  enabled: false\n"
        "registry:\n"
        "  enabled: false\n"
        "agentflow:\n"
        f"  runs_dir: {tmp_path / 'runs'}\n"
        "  max_concurrent_runs: 1\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CONFIG_PATH", str(config_path))
    model_module._engine = None
    model_module._SessionFactory = None
    reload_config(str(config_path))


def _client(tmp_path: Path, monkeypatch) -> TestClient:
    _configure_service(tmp_path, monkeypatch)
    from app.api.dependencies import get_current_subject
    from app.api.agentflow_runs import _runtime
    from app.main import app
    from app.model import init_database

    init_database()
    _runtime()
    app.dependency_overrides[get_current_subject] = lambda: ({}, "token")
    return TestClient(app)


def test_firmware_unpacker_exposes_agentflow_runs_api(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    try:
        validate = client.post(
            "/api/app/firmware-unpacker/api/runs/validate",
            json={
                "pipeline": {
                    "name": "fw-api",
                    "working_dir": str(tmp_path),
                    "nodes": [{"id": "alpha", "agent": "python", "prompt": "print('firmware api ok')"}],
                }
            },
        )
        assert validate.status_code == 200
        assert validate.json()["ok"] is True

        create = client.post(
            "/api/app/firmware-unpacker/api/runs",
            json={
                "pipeline": {
                    "name": "fw-api",
                    "working_dir": str(tmp_path),
                    "nodes": [{"id": "alpha", "agent": "python", "prompt": "print('firmware api ok')"}],
                }
            },
        )
        assert create.status_code == 200
        run_id = create.json()["id"]

        detail = None
        for _ in range(50):
            detail = client.get(f"/api/app/firmware-unpacker/api/runs/{run_id}")
            assert detail.status_code == 200
            if detail.json()["status"] in {"completed", "failed", "cancelled"}:
                break
            time.sleep(0.1)

        assert detail is not None
        assert detail.json()["status"] == "completed"
        assert detail.json()["nodes"]["alpha"]["output"].strip() == "firmware api ok"

        listing = client.get("/api/app/firmware-unpacker/agentflow/runs")
        assert listing.status_code == 200
        assert any(run["id"] == run_id for run in listing.json())

        artifact = client.get(f"/api/app/firmware-unpacker/agentflow/runs/{run_id}/artifacts/alpha/output.txt")
        assert artifact.status_code == 200
        assert artifact.text.strip() == "firmware api ok"

        events = client.get(f"/api/app/firmware-unpacker/api/runs/{run_id}/events")
        assert events.status_code == 200
        assert any(event["type"] == "run_completed" for event in events.json())
    finally:
        from app.api.dependencies import get_current_subject
        from app.main import app

        app.dependency_overrides.pop(get_current_subject, None)


def test_firmware_unpacker_agentflow_api_rejects_non_json(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    try:
        response = client.post(
            "/api/app/firmware-unpacker/api/runs/validate",
            data="{}",
            headers={"Content-Type": "text/plain"},
        )
        assert response.status_code == 415
        assert response.json()["detail"] == "application/json content type required"
    finally:
        from app.api.dependencies import get_current_subject
        from app.main import app

        app.dependency_overrides.pop(get_current_subject, None)


def test_task_agentflow_helpers_expose_node_timing_and_files(tmp_path):
    from app.api.firmware import (
        _extract_failed_nodes,
        _list_stage_files,
        _list_trace_files,
        _normalize_agentflow_nodes,
    )

    run_json = {
        "nodes": {
            "alpha": {
                "status": "failed",
                "started_at": "2026-05-08T00:00:00+00:00",
                "finished_at": "2026-05-08T00:00:02+00:00",
                "error": "boom",
            },
            "beta": {"status": "completed"},
        }
    }

    nodes = _normalize_agentflow_nodes(run_json, None)
    assert nodes["alpha"]["completed_at"] == "2026-05-08T00:00:02+00:00"
    assert nodes["alpha"]["duration_seconds"] == 2.0
    assert nodes["alpha"]["error"] == "boom"
    assert _extract_failed_nodes(run_json, None, None)[0]["node_id"] == "alpha"

    run_dir = tmp_path / "run"
    (run_dir / "artifacts" / "alpha").mkdir(parents=True)
    (run_dir / "run.json").write_text("{}", encoding="utf-8")
    (run_dir / "events.jsonl").write_text("", encoding="utf-8")
    (run_dir / "artifacts" / "alpha" / "trace.jsonl").write_text("", encoding="utf-8")
    trace_paths = {item["path"] for item in _list_trace_files(run_dir)}
    assert trace_paths == {"run.json", "events.jsonl", "artifacts/alpha/trace.jsonl"}

    task_run_dir = tmp_path / "task-run"
    task_run_dir.mkdir()
    (task_run_dir / "final_result.json").write_text("{}", encoding="utf-8")
    (task_run_dir / "tokens_summary.json").write_text("{}", encoding="utf-8")
    stage_paths = {item["path"] for item in _list_stage_files(task_run_dir)}
    assert stage_paths == {"final_result.json", "tokens_summary.json"}


def test_metrics_endpoint_exposes_agentflow_gauges(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    try:
        response = client.get("/metrics")
        assert response.status_code == 200
        body = response.text
        assert "firmware_unpacker_tasks_total" in body
        assert "firmware_unpacker_agentflow_active_runs" in body
        assert "firmware_unpacker_agentflow_tokens_total" in body
    finally:
        from app.api.dependencies import get_current_subject
        from app.main import app

        app.dependency_overrides.pop(get_current_subject, None)
