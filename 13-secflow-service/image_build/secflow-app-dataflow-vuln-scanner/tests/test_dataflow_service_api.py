from __future__ import annotations

from fastapi.testclient import TestClient

from app.config import get_config
from app.main import create_app
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


def test_profiles_tasks_and_effective_config(service_config_path, patch_mock_agent_runtime):
    app = create_app()
    client = TestClient(app)

    create_profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload())
    assert create_profile.status_code == 201
    profile = create_profile.json()
    assert profile["template_kind"] == "vuln_scan_default"
    assert profile["is_default"] is True
    profile_id = profile["profile_id"]

    versions = client.get(f"/api/dataflow-vuln-scanner/profiles/{profile_id}/versions")
    assert versions.status_code == 200
    assert versions.json()[0]["version"] == 1

    effective = client.get("/api/dataflow-vuln-scanner/projects/default/config/effective")
    assert effective.status_code == 200
    assert effective.json()["default_profile_id"] == profile_id

    task = client.post(
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
    assert task.status_code == 201
    task_payload = task.json()
    task_id = task_payload["task_id"]
    assert task_payload["status"] == "pending"

    attempts = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/attempts")
    assert attempts.status_code == 200
    execution_id = attempts.json()[0]["execution_id"]

    claimed_execution_id = SchedulerService()._claim_next_execution()
    assert claimed_execution_id == execution_id
    get_execution_service().run_claimed_execution(execution_id)

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}")
    assert detail.status_code == 200
    assert detail.json()["status"] == "succeeded"

    events = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/events")
    assert events.status_code == 200
    event_types = [item["event_type"] for item in events.json()]
    assert "execution_started" in event_types
    assert "execution_finished" in event_types

    artifacts = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/artifacts")
    assert artifacts.status_code == 200
    artifact_paths = [item["path"] for item in artifacts.json()["files"]]
    assert "output/tasks.json" in artifact_paths


def test_create_task_bootstraps_default_profile_when_missing(service_config_path, patch_mock_agent_runtime):
    app = create_app()
    client = TestClient(app)

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "title": "scan without precreated profile",
            "task_markdown": "# Package List\n\n- demo.tar.gz\n",
            "artifact_refs": [],
            "runtime_overrides": {},
        },
    )
    assert task.status_code == 201
    task_payload = task.json()
    assert task_payload["status"] == "pending"
    assert task_payload["profile_id"]

    profiles = client.get("/api/dataflow-vuln-scanner/profiles", params={"project_id": "default"})
    assert profiles.status_code == 200
    profile_items = profiles.json()
    assert len(profile_items) == 1
    assert profile_items[0]["profile_id"] == task_payload["profile_id"]
    assert profile_items[0]["is_default"] is True
    assert profile_items[0]["enabled"] is True


def test_business_dataflow_task_materializes_inputs_and_runs(service_config_path, patch_mock_agent_runtime):
    config = get_config()
    project_root = config.fileserver_service.data_mount_path
    from pathlib import Path

    case_root = Path(project_root) / "files" / "default" / "case-a"
    source_dir = case_root / "source"
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "demo.c").write_text("int demo(char *p) { return p[0]; }\n", encoding="utf-8")
    (case_root / "data_flow.md").write_text("# 数据流追踪：demo\n\n| 📌 USED | 1 |\nINPUT-1\n", encoding="utf-8")

    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile["profile_id"],
            "title": "business scan",
            "data_flow": {"source": "project_filesystem", "path": "/case-a/data_flow.md"},
            "source_dir": {"source": "project_filesystem", "path": "/case-a/source"},
            "model": "mock/model",
            "thinking": "medium",
            "review_profile": "fast",
            "max_review_cycles": 1,
            "result_review_concurrency": 1,
            "priority": 80,
        },
    )
    assert task.status_code == 201
    task_id = task.json()["task_id"]

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}")
    assert detail.status_code == 200
    payload = detail.json()
    assert "漏洞挖掘任务" in payload["task_markdown"]
    materialized = payload["task_metadata"]["dataflow_scan_materialized"]
    assert materialized["data_flow_file"].endswith("data_flow.md")
    assert materialized["source_dir"].endswith("source")

    execution_id = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/attempts").json()[0]["execution_id"]
    assert SchedulerService()._claim_next_execution() == execution_id
    get_execution_service().run_claimed_execution(execution_id)

    runs = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/runs")
    assert runs.status_code == 200
    assert runs.json()[0]["execution_id"] == execution_id

    run_detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/runs/{execution_id}")
    assert run_detail.status_code == 200
    assert run_detail.json()["detail"]["config"]["thinking"] == "medium"

    run_files = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/runs/{execution_id}/files")
    assert run_files.status_code == 200
    assert any(item["path"].endswith("task.md") for item in run_files.json())


def test_business_dataflow_task_uses_selected_workspace_and_output_dirs(service_config_path, patch_mock_agent_runtime):
    config = get_config()
    project_root = config.fileserver_service.data_mount_path
    from pathlib import Path
    import json

    case_root = Path(project_root) / "files" / "default" / "case-custom"
    source_dir = case_root / "source"
    workspace_dir = case_root / "workspace"
    output_dir = workspace_dir / "nested-output"
    source_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "demo.c").write_text("int demo(char *p) { return p[0]; }\n", encoding="utf-8")
    (case_root / "data_flow.md").write_text("# 数据流追踪：demo\n\n| 📌 USED | 1 |\nINPUT-1\n", encoding="utf-8")

    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile["profile_id"],
            "title": "business scan custom workspace",
            "workspace_dir": {"source": "project_filesystem", "path": "/case-custom/workspace"},
            "data_flow": {"source": "project_filesystem", "path": "/case-custom/data_flow.md"},
            "source_dir": {"source": "project_filesystem", "path": "/case-custom/source"},
            "output_dir": {"source": "project_filesystem", "path": "/case-custom/workspace/nested-output"},
            "model": "mock/model",
            "thinking": "medium",
            "review_profile": "fast",
            "max_review_cycles": 1,
            "result_review_concurrency": 1,
            "priority": 80,
        },
    )
    assert task.status_code == 201
    task_id = task.json()["task_id"]

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}")
    assert detail.status_code == 200
    materialized = detail.json()["task_metadata"]["dataflow_scan_materialized"]
    assert materialized["workspace_dir"] == str(workspace_dir.resolve())
    assert materialized["output_dir"] == str(output_dir.resolve())

    attempts = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/attempts")
    assert attempts.status_code == 200
    execution_id = attempts.json()[0]["execution_id"]
    expected_workspace_root = workspace_dir / execution_id
    expected_output_root = expected_workspace_root / "nested-output"
    assert attempts.json()[0]["workspace_root"] == str(expected_workspace_root.resolve())

    assert SchedulerService()._claim_next_execution() == execution_id
    get_execution_service().run_claimed_execution(execution_id)

    run_detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/runs/{execution_id}")
    assert run_detail.status_code == 200
    assert run_detail.json()["execution"]["workspace_root"] == str(expected_workspace_root.resolve())

    runtime_config = json.loads((expected_workspace_root / "config.json").read_text(encoding="utf-8"))
    assert runtime_config["global_config"]["workspace_root"] == str(expected_workspace_root.resolve())
    assert runtime_config["execution"]["output_dir"] == str(expected_output_root.resolve())


def test_business_dataflow_task_defaults_output_dir_inside_selected_workspace(service_config_path, patch_mock_agent_runtime):
    config = get_config()
    project_root = config.fileserver_service.data_mount_path
    from pathlib import Path
    import json

    case_root = Path(project_root) / "files" / "default" / "case-workspace-only"
    source_dir = case_root / "source"
    workspace_dir = case_root / "workspace"
    source_dir.mkdir(parents=True, exist_ok=True)
    workspace_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "demo.c").write_text("int demo(char *p) { return p[0]; }\n", encoding="utf-8")
    (case_root / "data_flow.md").write_text("# 数据流追踪：demo\n\n| 📌 USED | 1 |\nINPUT-1\n", encoding="utf-8")

    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile["profile_id"],
            "title": "business scan default output",
            "workspace_dir": {"source": "project_filesystem", "path": "/case-workspace-only/workspace"},
            "data_flow": {"source": "project_filesystem", "path": "/case-workspace-only/data_flow.md"},
            "source_dir": {"source": "project_filesystem", "path": "/case-workspace-only/source"},
            "model": "mock/model",
            "thinking": "medium",
            "review_profile": "fast",
            "max_review_cycles": 1,
            "result_review_concurrency": 1,
            "priority": 80,
        },
    )
    assert task.status_code == 201
    task_id = task.json()["task_id"]

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}")
    assert detail.status_code == 200
    materialized = detail.json()["task_metadata"]["dataflow_scan_materialized"]
    assert materialized["workspace_dir"] == str(workspace_dir.resolve())
    assert materialized["output_dir"] == str((workspace_dir / "output").resolve())
    assert materialized["output_dir_mode"] == "auto_workspace_output"

    attempts = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}/attempts")
    assert attempts.status_code == 200
    execution_id = attempts.json()[0]["execution_id"]
    expected_workspace_root = workspace_dir / execution_id
    expected_output_root = expected_workspace_root / "output"
    assert attempts.json()[0]["workspace_root"] == str(expected_workspace_root.resolve())

    assert SchedulerService()._claim_next_execution() == execution_id
    get_execution_service().run_claimed_execution(execution_id)

    runtime_config = json.loads((expected_workspace_root / "config.json").read_text(encoding="utf-8"))
    assert runtime_config["global_config"]["workspace_root"] == str(expected_workspace_root.resolve())
    assert runtime_config["execution"]["output_dir"] == str(expected_output_root.resolve())


def test_project_filesystem_browser_uses_local_project_tree(service_config_path):
    config = get_config()
    project_root = config.fileserver_service.data_mount_path
    from pathlib import Path

    case_root = Path(project_root) / "files" / "default" / "case-browser"
    nested_dir = case_root / "source"
    nested_dir.mkdir(parents=True, exist_ok=True)
    (case_root / "data_flow.md").write_text("# browser test\n", encoding="utf-8")
    (nested_dir / "demo.c").write_text("int demo(void) { return 0; }\n", encoding="utf-8")

    app = create_app()
    client = TestClient(app)

    root = client.get("/api/dataflow-vuln-scanner/project-filesystem/root", params={"project_id": "default"})
    assert root.status_code == 200
    items = {item["name"]: item for item in root.json()["items"]}
    assert items["case-browser"]["node_type"] == "subproject"
    assert items["case-browser"]["path"] == "/case-browser"

    children = client.get(
        "/api/dataflow-vuln-scanner/project-filesystem/children",
        params={"project_id": "default", "path": "/case-browser"},
    )
    assert children.status_code == 200
    payload = children.json()
    assert payload["current_path"] == "/case-browser"
    assert payload["breadcrumbs"][-1]["path"] == "/case-browser"
    directories = {item["name"]: item for item in payload["directories"]}
    files = {item["name"]: item for item in payload["files"]}
    assert directories["source"]["node_type"] == "directory"
    assert files["data_flow.md"]["node_type"] == "file"

    escaped = client.get(
        "/api/dataflow-vuln-scanner/project-filesystem/children",
        params={"project_id": "default", "path": "/../etc"},
    )
    assert escaped.status_code == 422


def test_service_config_is_redacted(service_config_path):
    from app.config import get_config

    config = get_config()
    config.database.password = "top-secret"
    config.auth_service.service_machine_token = "machine-secret"

    app = create_app()
    client = TestClient(app)

    response = client.get("/api/dataflow-vuln-scanner/service/config/effective")
    assert response.status_code == 200
    payload = response.json()["config"]
    assert payload["database"]["password"] == "***"
    assert payload["auth_service"]["service_machine_token"] == "***"
