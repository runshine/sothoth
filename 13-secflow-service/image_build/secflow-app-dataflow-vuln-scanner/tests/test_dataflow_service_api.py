from __future__ import annotations

import time

from fastapi.testclient import TestClient

from app.config import get_config
from app.main import create_app
from app.models.database import WorkflowDefinitionVersion, get_db_session


def _wait_for_task_status(client: TestClient, task_id: str, expected: set[str] | None = None, timeout: float = 10.0) -> dict:
    expected = expected or {"succeeded"}
    deadline = time.time() + timeout
    last_payload: dict = {}
    while time.time() < deadline:
        response = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}")
        assert response.status_code == 200
        last_payload = response.json()
        if last_payload.get("status") in expected:
            return last_payload
        time.sleep(0.1)
    raise AssertionError(f"task {task_id} did not reach {expected}, last payload: {last_payload}")


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
    assert task_payload["status"] in {"running", "succeeded"}

    detail_payload = _wait_for_task_status(client, task_id)
    assert detail_payload["status"] == "succeeded"
    assert detail_payload["attempts"]
    execution_id = detail_payload["attempts"][0]["execution_id"]

    history_resolve = client.get(
        "/api/dataflow-vuln-scanner/history-runs/by-task",
        params={"project_id": "default", "task_id": task_id, "execution_id": execution_id},
    )
    assert history_resolve.status_code == 200

    history_detail = client.get(f"/api/dataflow-vuln-scanner/history-runs/{history_resolve.json()['history_run_id']}")
    assert history_detail.status_code == 200
    artifact_paths = [item["path"] for item in history_detail.json()["files"]]
    assert "input/task.md" in artifact_paths
    assert "run.log" in artifact_paths


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
    assert task_payload["status"] in {"running", "succeeded"}
    assert task_payload["profile_id"]
    _wait_for_task_status(client, task_payload["task_id"])

    profiles = client.get("/api/dataflow-vuln-scanner/profiles", params={"project_id": "default"})
    assert profiles.status_code == 200
    profile_items = profiles.json()
    assert len(profile_items) == 1
    assert profile_items[0]["profile_id"] == task_payload["profile_id"]
    assert profile_items[0]["is_default"] is True
    assert profile_items[0]["enabled"] is True


def test_create_task_rejects_profile_from_different_project(service_config_path, patch_mock_agent_runtime):
    app = create_app()
    client = TestClient(app)

    profile_payload = _profile_payload()
    profile_payload["project_id"] = "project-1"
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=profile_payload)
    assert profile.status_code == 201

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile.json()["profile_id"],
            "title": "scan with wrong project profile",
            "task_markdown": "# Package List\n\n- demo.tar.gz\n",
            "artifact_refs": [],
            "runtime_overrides": {},
        },
    )
    assert task.status_code == 422
    assert "different project" in task.json()["detail"]


def test_task_bound_profile_versions_do_not_become_default(service_config_path, patch_mock_agent_runtime):
    app = create_app()
    client = TestClient(app)

    create_profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload())
    assert create_profile.status_code == 201
    profile = create_profile.json()
    profile_id = profile["profile_id"]
    assert profile["version"] == 1

    override_task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile_id,
            "title": "fast one-off task",
            "task_markdown": "# Package List\n\n- demo.tar.gz\n",
            "review_profile": "fast",
            "max_review_cycles": 1,
        },
    )
    assert override_task.status_code == 201
    assert override_task.json()["profile_version"] == 2
    _wait_for_task_status(client, override_task.json()["task_id"])

    default_task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile_id,
            "title": "default task after one-off override",
            "task_markdown": "# Package List\n\n- demo.tar.gz\n",
        },
    )
    assert default_task.status_code == 201
    assert default_task.json()["profile_version"] == 1
    _wait_for_task_status(client, default_task.json()["task_id"])

    profile_after = client.get(f"/api/dataflow-vuln-scanner/profiles/{profile_id}")
    assert profile_after.status_code == 200
    assert profile_after.json()["version"] == 1

    effective = client.get("/api/dataflow-vuln-scanner/projects/default/config/effective")
    assert effective.status_code == 200
    assert effective.json()["effective_config"]["profile_version"]["version"] == 1


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
        },
    )
    assert task.status_code == 201
    task_id = task.json()["task_id"]

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}")
    assert detail.status_code == 200
    payload = detail.json()
    assert "漏洞挖掘任务" in payload["task_markdown"]
    cli_plan = payload["task_metadata"]["dataflow_cli"]
    assert cli_plan["launcher"] == "run_vuln_scan.py"
    assert cli_plan["data_flow_file"] == str((case_root / "data_flow.md").resolve())
    assert cli_plan["source_dir"] == str(source_dir.resolve())
    assert Path(cli_plan["run_dir"]).parent.name == "runs"
    assert cli_plan["run_name"] == "business-scan"
    assert Path(cli_plan["run_dir"]).name == "business-scan"

    execution_id = payload["attempts"][0]["execution_id"]
    _wait_for_task_status(client, task_id)

    history_resolve = client.get(
        "/api/dataflow-vuln-scanner/history-runs/by-task",
        params={"project_id": "default", "task_id": task_id, "execution_id": execution_id},
    )
    assert history_resolve.status_code == 200
    history_detail = client.get(f"/api/dataflow-vuln-scanner/history-runs/{history_resolve.json()['history_run_id']}")
    assert history_detail.status_code == 200
    history_payload = history_detail.json()
    assert history_payload["config"]["thinking"] == ""
    assert "run_vuln_scan.py" in history_payload["command_display"]
    assert "--model mock/model" in history_payload["command_display"]
    assert "--run-name business-scan" in history_payload["command_display"]
    assert history_payload["raw"]["dataflow_cli"]["command_display"] == history_payload["command_display"]

    run_files = client.get(f"/api/dataflow-vuln-scanner/history-runs/{history_resolve.json()['history_run_id']}/files")
    assert run_files.status_code == 200
    file_paths = [item["path"] for item in run_files.json()]
    assert "input/task.md" in file_paths
    assert "config.json" in file_paths
    assert "run.log" in file_paths


def test_business_dataflow_task_uses_selected_runs_root(service_config_path, patch_mock_agent_runtime):
    config = get_config()
    project_root = config.fileserver_service.data_mount_path
    from pathlib import Path
    import json

    case_root = Path(project_root) / "files" / "default" / "case-custom"
    source_dir = case_root / "source"
    runs_root = case_root / "runs"
    source_dir.mkdir(parents=True, exist_ok=True)
    runs_root.mkdir(parents=True, exist_ok=True)
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
            "workspace_dir": {"source": "project_filesystem", "path": "/case-custom/runs"},
            "data_flow": {"source": "project_filesystem", "path": "/case-custom/data_flow.md"},
            "source_dir": {"source": "project_filesystem", "path": "/case-custom/source"},
            "model": "mock/model",
            "thinking": "medium",
            "review_profile": "fast",
            "max_review_cycles": 1,
            "result_review_concurrency": 1,
        },
    )
    assert task.status_code == 201
    task_id = task.json()["task_id"]

    detail = client.get(f"/api/dataflow-vuln-scanner/tasks/{task_id}")
    assert detail.status_code == 200
    cli_plan = detail.json()["task_metadata"]["dataflow_cli"]
    assert cli_plan["runs_root"] == str(runs_root.resolve())

    detail_payload = _wait_for_task_status(client, task_id)
    assert detail_payload["attempts"]
    execution_id = detail_payload["attempts"][0]["execution_id"]
    expected_run_root = Path(detail_payload["attempts"][0]["workspace_root"])
    assert expected_run_root.parent == runs_root.resolve()
    assert expected_run_root.name == "business-scan-custom-workspace"

    history_resolve = client.get(
        "/api/dataflow-vuln-scanner/history-runs/by-task",
        params={"project_id": "default", "task_id": task_id, "execution_id": execution_id},
    )
    assert history_resolve.status_code == 200
    history_detail = client.get(f"/api/dataflow-vuln-scanner/history-runs/{history_resolve.json()['history_run_id']}")
    assert history_detail.status_code == 200
    assert history_detail.json()["path"] == str(expected_run_root.resolve())

    runtime_config = json.loads((expected_run_root / "config.json").read_text(encoding="utf-8"))
    assert runtime_config["global"]["workspace_root"] == str((expected_run_root / "workspace").resolve())
    assert runtime_config["execution"]["output_dir"] == str((expected_run_root / "output").resolve())


def test_business_dataflow_task_rejects_output_dir_with_cli_launcher(service_config_path, patch_mock_agent_runtime):
    config = get_config()
    project_root = config.fileserver_service.data_mount_path
    from pathlib import Path

    case_root = Path(project_root) / "files" / "default" / "case-workspace-only"
    source_dir = case_root / "source"
    runs_root = case_root / "runs"
    output_dir = runs_root / "nested-output"
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
            "title": "business scan default output",
            "workspace_dir": {"source": "project_filesystem", "path": "/case-workspace-only/runs"},
            "data_flow": {"source": "project_filesystem", "path": "/case-workspace-only/data_flow.md"},
            "source_dir": {"source": "project_filesystem", "path": "/case-workspace-only/source"},
            "output_dir": {"source": "project_filesystem", "path": "/case-workspace-only/runs/nested-output"},
            "model": "mock/model",
            "thinking": "medium",
            "review_profile": "fast",
            "max_review_cycles": 1,
            "result_review_concurrency": 1,
        },
    )
    assert task.status_code == 422
    assert "output_dir is not supported" in task.text


def test_dataflow_task_creates_missing_profile_version_snapshot(service_config_path, patch_mock_agent_runtime):
    config = get_config()
    project_root = config.fileserver_service.data_mount_path
    from pathlib import Path

    case_root = Path(project_root) / "files" / "default" / "case-missing-profile-version"
    source_dir = case_root / "source"
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "demo.c").write_text("int demo(char *p) { return p[0]; }\n", encoding="utf-8")
    (case_root / "data_flow.md").write_text("# 数据流追踪：demo\n\nINPUT-1\n", encoding="utf-8")

    app = create_app()
    client = TestClient(app)
    profile = client.post("/api/dataflow-vuln-scanner/profiles", json=_profile_payload()).json()
    profile_id = profile["profile_id"]

    db = get_db_session()
    try:
        db.query(WorkflowDefinitionVersion).filter(
            WorkflowDefinitionVersion.workflow_definition_id == profile_id
        ).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()

    task = client.post(
        "/api/dataflow-vuln-scanner/tasks",
        json={
            "project_id": "default",
            "profile_id": profile_id,
            "title": "business scan with repaired profile version",
            "data_flow": {"source": "project_filesystem", "path": "/case-missing-profile-version/data_flow.md"},
            "source_dir": {"source": "project_filesystem", "path": "/case-missing-profile-version/source"},
        },
    )
    assert task.status_code == 201
    assert task.json()["profile_version"] == 1

    versions = client.get(f"/api/dataflow-vuln-scanner/profiles/{profile_id}/versions")
    assert versions.status_code == 200
    assert versions.json()[0]["version"] == 1


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
