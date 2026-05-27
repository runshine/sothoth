from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app
from app.models.database import DfvsTaskListProjection, TriggerTask, get_db_session
from app.services.execution_service import get_execution_service


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
    with TestClient(app) as client:
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
        assert "task_markdown" not in payload["items"][0]


def test_task_list_stats_and_backfill_projection(service_config_path, patch_mock_agent_runtime):
    app = create_app()
    with TestClient(app) as client:
        profile_response = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload())
        assert profile_response.status_code == 201
        profile_id = profile_response.json()["profile_id"]

        created_ids: list[str] = []
        for index in range(2):
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
            created_ids.append(task_response.json()["task_id"])

        with get_db_session() as db:
            first = db.get(TriggerTask, created_ids[0])
            assert first is not None
            first.status = "succeeded"
            first.public_status = "succeeded"
            first.message = "done"
            db.add(first)
            get_execution_service()._refresh_task_list_projection_for_task_id(db, first.id)
            db.commit()

            db.query(DfvsTaskListProjection).filter(DfvsTaskListProjection.task_id == created_ids[1]).delete()
            db.commit()

        list_response = client.get(
            "/api/dataflow-vuln-scanner/tasks",
            params={"project_id": "default", "page": 1, "per_page": 20, "sort_by": "created_at", "sort_order": "desc"},
        )
        assert list_response.status_code == 200
        listed_ids = [item["task_id"] for item in list_response.json()["items"]]
        assert created_ids[0] in listed_ids
        assert created_ids[1] in listed_ids

        stats_response = client.get("/api/dataflow-vuln-scanner/tasks/stats", params={"project_id": "default"})
        assert stats_response.status_code == 200
        stats = stats_response.json()
        assert stats["total"] >= 2

        with get_db_session() as db:
            projection = db.get(DfvsTaskListProjection, created_ids[1])
            assert projection is not None


def test_task_list_rejects_unsupported_sort(service_config_path, patch_mock_agent_runtime):
    app = create_app()
    with TestClient(app) as client:
        response = client.get(
            "/api/dataflow-vuln-scanner/tasks",
            params={"project_id": "default", "page": 1, "per_page": 20, "sort_by": "bad_field"},
        )
        assert response.status_code == 422


def test_task_projection_rebuild_endpoints(service_config_path, patch_mock_agent_runtime):
    app = create_app()
    with TestClient(app) as client:
        profile_response = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload())
        assert profile_response.status_code == 201
        profile_id = profile_response.json()["profile_id"]

        task_response = client.post(
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
        assert task_response.status_code == 201
        task_id = task_response.json()["task_id"]

        single_response = client.post(f"/api/dataflow-vuln-scanner/tasks/{task_id}/projection/rebuild")
        assert single_response.status_code == 200
        single_payload = single_response.json()
        assert single_payload["task_id"] == task_id
        assert single_payload["repaired_count"] == 1

        batch_response = client.post("/api/dataflow-vuln-scanner/tasks/projection/rebuild", params={"project_id": "default"})
        assert batch_response.status_code == 200
        batch_payload = batch_response.json()
        assert batch_payload["project_id"] == "default"
        assert batch_payload["repaired_count"] >= 1
