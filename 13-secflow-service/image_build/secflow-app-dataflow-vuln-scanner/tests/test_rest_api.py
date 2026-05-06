from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app
from app.models.database import WorkflowExecution, get_db_session
from app.services.execution_service import get_execution_service
from app.services.scheduler import SchedulerService
from app.services.workflow_service import get_workflow_service


def test_definition_and_trigger_rest_lifecycle(
    service_config_path: Path,
    framework_root: Path,
    framework_config_payload: dict,
    patch_mock_agent_runtime,
):
    app = create_app()
    client = TestClient(app)
    validated = get_workflow_service().validate_definition_payload(framework_config_payload)

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
    assert definition["root_workflow_id"] == framework_config_payload["execution"]["entry_workflow"]
    assert definition["entry_input_task_type"] == validated.resolve_entry_input_task_type()
    assert definition["final_output_task_type"] == validated.resolve_final_output_task_type()

    versions_response = client.get(f"/api/ai-agent-framework/workflow-definitions/{definition_id}/versions")
    assert versions_response.status_code == 200
    assert len(versions_response.json()) == 1

    trigger_response = client.post(
        f"/api/ai-agent-framework/workflow-definitions/{definition_id}/trigger-tasks",
        json={
            "input_tasks": [
                {
                    "task_id": "task-001",
                    "title": "样例输入任务",
                    "task_markdown": "# Package List\n\n- demo.tar.gz\n",
                    "metadata": {"source": "rest-test"},
                    "upstream_refs": [],
                }
            ]
        },
    )
    assert trigger_response.status_code == 201
    trigger_task_id = trigger_response.json()["id"]
    assert trigger_response.json()["status"] == "pending"

    execution_list_response = client.get("/api/ai-agent-framework/executions")
    assert execution_list_response.status_code == 200
    assert len(execution_list_response.json()) == 1
    execution_id = execution_list_response.json()[0]["id"]

    db = get_db_session()
    try:
        execution = db.get(WorkflowExecution, execution_id)
        assert execution is not None
        assert execution.workspace_root is not None
        workspace_root = Path(execution.workspace_root)
        assert workspace_root.exists()
        assert (workspace_root / "input" / "tasks.json").exists()
        assert (workspace_root / "trigger_inputs" / "task-001" / "input" / "task.md").exists()
    finally:
        db.close()

    claimed_execution_id = SchedulerService()._claim_next_execution()
    assert claimed_execution_id == execution_id
    get_execution_service().run_claimed_execution(execution_id)

    execution_detail = client.get(f"/api/ai-agent-framework/executions/{execution_id}")
    assert execution_detail.status_code == 200
    assert execution_detail.json()["status"] == "succeeded"
    assert execution_detail.json()["output_task_count"] == 2

    events_response = client.get(f"/api/ai-agent-framework/executions/{execution_id}/events")
    assert events_response.status_code == 200
    event_types = [item["event_type"] for item in events_response.json()]
    assert "execution_started" in event_types
    assert "stage_started" in event_types
    assert "plugin_completed" in event_types
    assert "global_review_result" in event_types
    assert "result_review_result" in event_types
    assert "execution_finished" in event_types

    artifacts_response = client.get(f"/api/ai-agent-framework/executions/{execution_id}/artifacts")
    assert artifacts_response.status_code == 200
    artifact_paths = [item["path"] for item in artifacts_response.json()["files"]]
    assert "output/tasks.json" in artifact_paths

    wrong_type_trigger = client.post(
        f"/api/ai-agent-framework/workflow-definitions/{definition_id}/trigger-tasks",
        json={
            "input_tasks": [
                {
                    "task_id": "task-002",
                    "task_type": "wrong_type",
                    "title": "错误类型任务",
                    "task_markdown": "# Wrong Type\n",
                    "metadata": {},
                    "upstream_refs": [],
                }
            ]
        },
    )
    assert wrong_type_trigger.status_code == 422

    second_trigger = client.post(
        f"/api/ai-agent-framework/workflow-definitions/{definition_id}/trigger-tasks",
        json={
            "input_tasks": [
                {
                    "task_id": "task-003",
                    "title": "待取消任务",
                    "task_markdown": "# To Cancel\n",
                    "metadata": {},
                    "upstream_refs": [],
                }
            ]
        },
    )
    assert second_trigger.status_code == 201
    cancel_response = client.post(f"/api/ai-agent-framework/trigger-tasks/{second_trigger.json()['id']}/cancel")
    assert cancel_response.status_code == 200
    trigger_detail_response = client.get(f"/api/ai-agent-framework/trigger-tasks/{second_trigger.json()['id']}")
    assert trigger_detail_response.status_code == 200
    assert trigger_detail_response.json()["status"] == "cancelled"
