from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app


def test_definition_and_trigger_rest_lifecycle(service_config_path: Path, framework_root: Path, framework_config_payload: dict):
    app = create_app()
    client = TestClient(app)

    create_response = client.post(
        "/api/ai-agent-framework/workflow-definitions",
        json={
            "name": "demo pipeline",
            "description": "demo",
            "project_id": "default",
            "definition_json": framework_config_payload,
            "trigger_type": "manual",
            "trigger_enabled": False,
            "is_active": False,
            "enabled": True,
            "max_concurrency": 1,
            "priority_default": 100,
        },
    )
    assert create_response.status_code == 201
    definition = create_response.json()
    definition_id = definition["id"]
    assert definition["root_workflow_id"] == framework_config_payload["root_workflow_id"]

    versions_response = client.get(f"/api/ai-agent-framework/workflow-definitions/{definition_id}/versions")
    assert versions_response.status_code == 200
    assert len(versions_response.json()) == 1

    update_response = client.put(
        f"/api/ai-agent-framework/workflow-definitions/{definition_id}",
        json={"name": "demo pipeline v2"},
    )
    assert update_response.status_code == 200
    assert update_response.json()["name"] == "demo pipeline v2"

    versions_response = client.get(f"/api/ai-agent-framework/workflow-definitions/{definition_id}/versions")
    assert len(versions_response.json()) == 2

    activate_response = client.post(f"/api/ai-agent-framework/workflow-definitions/{definition_id}/activate")
    assert activate_response.status_code == 200
    assert activate_response.json()["is_active"] is True

    input_tasks = json.loads((framework_root / "examples" / "input_tasks.json").read_text(encoding="utf-8"))["tasks"]
    trigger_response = client.post(
        f"/api/ai-agent-framework/workflow-definitions/{definition_id}/trigger-tasks",
        json={"input_tasks": input_tasks},
    )
    assert trigger_response.status_code == 201
    trigger_task_id = trigger_response.json()["id"]
    assert trigger_response.json()["status"] == "pending"

    execution_list_response = client.get("/api/ai-agent-framework/executions")
    assert execution_list_response.status_code == 200
    assert len(execution_list_response.json()) == 1
    assert execution_list_response.json()[0]["status"] == "pending"

    cancel_response = client.post(f"/api/ai-agent-framework/trigger-tasks/{trigger_task_id}/cancel")
    assert cancel_response.status_code == 200

    trigger_detail_response = client.get(f"/api/ai-agent-framework/trigger-tasks/{trigger_task_id}")
    assert trigger_detail_response.status_code == 200
    assert trigger_detail_response.json()["status"] == "cancelled"

