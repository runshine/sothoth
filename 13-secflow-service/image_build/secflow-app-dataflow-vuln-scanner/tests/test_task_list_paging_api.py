from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


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


def test_task_list_supports_paged_lightweight_response(service_config_path, patch_mock_agent_runtime):
    app = create_app()
    client = TestClient(app)

    profile_response = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload())
    assert profile_response.status_code == 201
    profile_id = profile_response.json()["profile_id"]

    for index in range(3):
        task_response = client.post(
            "/api/dataflow-vuln-scanner/tasks",
            json={
                "project_id": "default",
                "profile_id": profile_id,
                "title": f"scan demo package {index}",
                "task_markdown": f"# Package List\n\n- demo-{index}.tar.gz\n",
                "artifact_refs": [],
                "runtime_overrides": {},
            },
        )
        assert task_response.status_code == 201

    response = client.get(
        "/api/dataflow-vuln-scanner/tasks",
        params={
            "project_id": "default",
            "page": 1,
            "per_page": 2,
            "mode": "manual",
            "sort_by": "created_at",
            "sort_order": "desc",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["page"] == 1
    assert payload["per_page"] == 2
    assert payload["total"] >= 3
    assert len(payload["items"]) == 2
    assert payload["items"][0]["task_origin_type"] == "manual"
    assert "run" in payload["items"][0]
    assert "latest_run" in payload["items"][0]
